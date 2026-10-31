;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked rules)
  #:use-module ((guix build utils) #:select (mkdir-p))
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
            %pulseaudio
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
            absolute-file
            tcp-ports
            all-rules
            when-arguments))

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

(define (store-accesses programs executes-others?)
  "Without EXECUTES?, only PROGRAMS and their interpreters may be
executed."
  (if executes-others?
      (list (file-access "/gnu/store" '(read execute)))
      (cons (file-access "/gnu/store" '(read load))
            (map (cut file-access <> '(read execute))
                 (delete-duplicates
                  (append programs (append-map elf-interpreters programs)))))))

(define (base-grant programs executes-others?)
  (grant #:files (append (store-accesses programs executes-others?)
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

(define (matcher? matcher)
  (match matcher
    ('urls #t)
    (('extensions extensions ..1) (every string? extensions))
    (_ #f)))

(define (argument-matches? argument matcher)
  (match matcher
    ('urls (url? argument))
    (('extensions extensions ...)
     (let ((file (argument-file argument)))
       (and file
            (any (cut string-suffix-ci? <> file) extensions))))))

(define (arguments-match? arguments matchers)
  (any (lambda (argument)
         (any (cut argument-matches? argument <>) matchers))
       arguments))

(define (%argument-files command-line)
  "Grant reading the regular files that the arguments name, but no symbolic
links, which others may have planted."
  (grant #:files (filter-map (lambda (argument)
                               (and=> (argument-file argument)
                                      (cut regular-file-access <> '(read))))
                             (cdr command-line))))

(define (all-rules . rules)
  "Return a rule that grants what RULES grant."
  (lambda (command-line)
    (apply grant-append (map (cut <> command-line) rules))))

(define (when-arguments matchers . rules)
  "Return a rule that grants what RULES grant if an argument matches one of
MATCHERS: urls, or (extensions EXTENSION ...) for the files the arguments
name."
  (check-parameters 'when-arguments
                    (lambda (matchers)
                      (and (pair? matchers) (list? matchers)
                           (every matcher? matchers)))
                    matchers)
  (let ((rule (apply all-rules rules)))
    (lambda (command-line)
      (if (arguments-match? (cdr command-line) matchers)
          (rule command-line)
          %no-grant))))

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
  (private-directory "/dev/shm"))

(define (%dns command-line)
  "DNS queries can still carry data to anyone."
  (grant #:files (list (file-access "/var/run/nscd" '(connect)))
         #:ports (list (port-access 53 'udp))))

(define (%pipewire command-line)
  (socket-grant (runtime-path "pipewire-0")
                (lambda (socket)
                  `(("PIPEWIRE_RUNTIME_DIR" . ,(dirname socket))
                    ("PIPEWIRE_REMOTE" . ,(basename socket))))))

(define (%pulseaudio command-line)
  (socket-grant (runtime-path "pulse/native")
                (lambda (socket)
                  `(("PULSE_SERVER" . ,(string-append "unix:" socket))))))

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

(define-syntax-rule (define-file-rule name valid? path default-permissions
                      create?)
  "With CREATE?, granting write creates the directory."
  (define* (name file #:optional (permissions default-permissions))
    (check-parameters 'name
                      (lambda (file permissions)
                        (and (valid? file) (permissions? permissions)))
                      file permissions)
    (lambda (command-line)
      (let ((file (path file)))
        (when (and create? (memq 'write permissions))
          (mkdir-p file))
        (grant #:files (list (file-access file permissions)))))))

(define-file-rule xdg-config relative-file-name? config-path '(read) #f)
(define-file-rule xdg-state relative-file-name? state-path '(read write) #t)
(define-file-rule xdg-cache relative-file-name? cache-path '(read write) #t)
(define-file-rule home-file relative-file-name? home-path '(read) #f)
(define-file-rule absolute-file canonical-file-name? identity '(read) #f)

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

(define (port-number? port)
  (and (exact-integer? port) (<= 0 port 65535)))

(define (tcp-ports . ports)
  (apply check-parameters 'tcp-ports
         (lambda ports (every port-number? ports))
         ports)
  (lambda (command-line)
    (grant #:ports (map (cut port-access <> 'tcp) ports))))
