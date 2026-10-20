;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked rules)
  #:use-module (ice-9 binary-ports)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 textual-ports)
  #:use-module (rnrs bytevectors)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked file-names)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked instances)
  #:use-module (guix-cage build locked xdg)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (system vm elf)
  #:use-module (web uri)
  #:export (base-grant

            %graphics
            %fonts
            %shm
            %dns
            %pipewire
            %runtime-directory
            %temporary-directory
            %shared-temporary-directory
            %shell
            %argument-files
            %mail-directory
            xdg-config
            xdg-state
            xdg-cache
            xdg-user-directory
            home-file
            home-program
            read-only
            read-write
            devices
            tcp-ports
            when-network-arguments))

(define (segment-string bytes segment)
  (let ((string (make-bytevector (1- (elf-segment-filesz segment)))))
    (bytevector-copy! bytes (elf-segment-offset segment)
                      string 0 (bytevector-length string))
    (utf8->string string)))

(define (elf-interpreters program)
  (let ((bytes (call-with-input-file program get-bytevector-all #:binary #t)))
    (unless (has-elf-header? bytes)
      (raise-locked-error "cannot tell what ~a runs, it is no ELF file"
                          program))
    (filter-map (lambda (segment)
                  (and (= (elf-segment-type segment) PT_INTERP)
                       (segment-string bytes segment)))
                (elf-segments (parse-elf bytes)))))

(define (store-accesses programs executes?)
  "Without EXECUTES?, only PROGRAMS and their interpreters may be
executed."
  (if executes?
      (list (file-access "/gnu/store" '(read execute)))
      (cons (file-access "/gnu/store" '(read load))
            (map (cut file-access <> '(read execute))
                 (delete-duplicates
                  (append programs (append-map elf-interpreters programs)))))))

(define (base-grant programs executes?)
  (grant #:files (append (store-accesses programs executes?)
                         (list (read-access "/etc")))))

(define (argument-file argument)
  "Return the file that ARGUMENT, a file:// URI or --NAME=VALUE names."
  (cond ((string-prefix? "file://" argument)
         (uri-decode (string-drop argument (string-length "file://"))))
        ((string-prefix? "-" argument)
         (match (string-index argument #\=)
           (#f #f)
           (index (argument-file (string-drop argument (1+ index))))))
        (else argument)))

(define %url-regexp (make-regexp "^[[:alpha:]][[:alnum:]+.-]*://"))

(define (url? argument)
  (and (regexp-exec %url-regexp argument)
       (not (string-prefix? "file://" argument))))

(define (network-arguments? arguments playlist-extensions)
  (define (playlist? argument)
    (let ((file (argument-file argument)))
      (and file
           (any (cut string-suffix-ci? <> file) playlist-extensions))))

  (any (lambda (argument)
         (or (url? argument) (playlist? argument)))
       arguments))

(define (%argument-files command-line)
  "Grant reading the regular files that the arguments name, but no symbolic
links, which others may have planted."
  (grant #:files (filter-map (lambda (argument)
                               (and=> (argument-file argument)
                                      (cut regular-file-access <> '(read))))
                             (cdr command-line))))

(define (when-network-arguments playlist-extensions . rules)
  "Return a rule that grants what RULES grant if the arguments name URLs, or
playlists with one of PLAYLIST-EXTENSIONS."
  (check-parameters 'when-network-arguments
                    (cut every string? <>) playlist-extensions)
  (lambda (command-line)
    (if (network-arguments? (cdr command-line) playlist-extensions)
        (apply grant-append (map (cut <> command-line) rules))
        %no-grant)))

(define (user-directory-setting name)
  (let ((prefix (string-append "XDG_" name "_DIR=\""))
        (file (config-path "user-dirs.dirs")))
    (and (file-exists? file)
         (and=> (find (cut string-prefix? prefix <>)
                      (string-split (call-with-input-file file get-string-all)
                                    #\newline))
                (lambda (line)
                  (string-trim-right (string-drop line (string-length prefix))
                                     #\"))))))

(define (expand-home value home)
  (cond ((string=? value "$HOME") home)
        ((string-prefix? "$HOME/" value)
         (string-append home (string-drop value (string-length "$HOME"))))
        (else value)))

(define %system-directories
  '("/gnu" "/etc" "/dev" "/proc" "/sys" "/run"))

(define (private-directories)
  "Return the directories of configurations, secrets and system files."
  (append %system-directories
          (filter-map (lambda (variable)
                        (and=> (getenv variable) normalize-file-name))
                      '("XDG_CONFIG_HOME" "XDG_CACHE_HOME" "XDG_STATE_HOME"
                        "XDG_DATA_HOME" "XDG_RUNTIME_DIR" "GNUPGHOME"))))

(define (hidden-below? directory home)
  "Whether DIRECTORY is in or below a hidden directory of HOME, such as
~/.ssh."
  (and (directory-contains? home directory)
       (any (cut string-prefix? "." <>)
            (file-name-components
             (string-drop directory (string-length home))))))

(define (overlap? directory other)
  (or (directory-contains? directory other)
      (directory-contains? other directory)))

(define (user-directory name default)
  "Return the XDG user directory NAME, or #f if it holds the home directory
or overlaps those of configurations, secrets or the system."
  (let* ((home (normalize-file-name (getenv* "HOME")))
         (value (or (user-directory-setting name)
                    (string-append "$HOME/" default)))
         (directory (and home (normalize-file-name (expand-home value home)))))
    (and directory
         (not (directory-contains? directory home))
         (not (hidden-below? directory home))
         (not (any (cut overlap? directory <>) (private-directories)))
         directory)))

(define (render-nodes)
  (map (cut string-append "/dev/dri/" <>)
       (or (scandir "/dev/dri" (cut string-prefix? "renderD" <>)) '())))

(define (%graphics command-line)
  "Grant rendering on the GPUs, but not their displays."
  (grant #:files
         (append (map (cut file-access <> '(read write ioctl)) (render-nodes))
                 (list (file-access "/dev/dri" '(list)))
                 (map read-access
                      '("/sys/dev/char" "/sys/class/drm" "/sys/bus/pci"
                        "/sys/devices")))))

(define (%fonts command-line)
  (grant #:files (map read-access
                      (list "/var/cache/fontconfig"
                            (config-path "fontconfig")
                            (cache-path "fontconfig")))))

(define (%shm command-line)
  (grant #:files (list (file-access "/dev/shm" '(read write)))))

(define (%dns command-line)
  "DNS queries can still carry data to anyone."
  (grant #:files (list (file-access "/var/run/nscd" '(connect)))
         #:ports (list (port-access 53 'udp))))

(define (%pipewire command-line)
  (socket-grant (runtime-path "pipewire-0")
                (lambda (socket)
                  `(("PIPEWIRE_RUNTIME_DIR" . ,(dirname socket))
                    ("PIPEWIRE_REMOTE" . ,(basename socket))))))

(define (private-directory directory)
  (grant #:files (list (file-access directory '(read write) #:private? #t))))

(define (%runtime-directory command-line)
  (private-directory (getenv* "XDG_RUNTIME_DIR")))

(define (%temporary-directory command-line)
  (grant-append (private-directory "/tmp")
                (grant #:variables '(("TMPDIR" . "/tmp")))))

(define (%shared-temporary-directory command-line)
  "Grant a new temporary directory that programs outside see at the same
place, for files that the program passes to them."
  (let ((directory (make-instance-directory "tmp")))
    (grant #:files (list (read-write-access directory))
           #:variables `(("TMPDIR" . ,directory)))))

(define (%shell command-line)
  "Grant /bin/sh, through which system and popen run commands."
  (grant #:files (list (file-access "/bin/sh" '(read execute)))))

(define (%mail-directory command-line)
  (grant #:files (list (read-write-access (or (getenv "MAILDIR")
                                              (home-path "Mail"))
                                          #:create? #t))
         #:variables (inherited-variables "MAILDIR")))

(define-syntax-rule (define-file-rule (name parameter) valid? access)
  (define (name parameter)
    (check-parameters 'name valid? parameter)
    (lambda (command-line)
      (grant #:files (list access)))))

(define-file-rule (xdg-config name) relative-file-name?
  (read-access (config-path name)))

(define-file-rule (xdg-state name) relative-file-name?
  (read-write-access (state-path name) #:create? #t))

(define-file-rule (xdg-cache name) relative-file-name?
  (read-write-access (cache-path name) #:create? #t))

(define-file-rule (home-file name) relative-file-name?
  (read-access (home-path name)))

(define-file-rule (home-program name) relative-file-name?
  (file-access (home-path name) '(read execute)))

(define-file-rule (read-only file) canonical-file-name?
  (read-access file))

(define-file-rule (read-write file) canonical-file-name?
  (read-write-access file))

(define (user-directory-name? name)
  (and (string? name)
       (not (string-null? name))
       (string-every (char-set-union char-set:upper-case (char-set #\_))
                     name)))

(define (xdg-user-directory name default)
  (check-parameters 'xdg-user-directory
                    (lambda (name default)
                      (and (user-directory-name? name)
                           (relative-file-name? default)))
                    name default)
  (lambda (command-line)
    (match (user-directory name default)
      (#f %no-grant)
      (directory (grant #:files (list (read-write-access directory)))))))

(define (devices . files)
  (apply check-parameters 'devices
         (lambda files (every canonical-file-name? files))
         files)
  (lambda (command-line)
    (grant #:files (map (cut file-access <> '(read write ioctl)) files))))

(define (port-number? port)
  (and (exact-integer? port) (<= 0 port 65535)))

(define (tcp-ports . ports)
  (apply check-parameters 'tcp-ports
         (lambda ports (every port-number? ports))
         ports)
  (lambda (command-line)
    (grant #:ports (map (cut port-access <> 'tcp) ports))))
