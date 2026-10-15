;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked rules)
  #:autoload (landlock) (%landlock-read-access landlock-path landlock-port)
  #:use-module (ice-9 binary-ports)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 textual-ports)
  #:use-module (rnrs bytevectors)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked files)
  #:use-module (guix-cage build locked kinds)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (system vm elf)
  #:use-module (web uri)
  #:export (base-rules
            rule-kinds))

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

(define (store-rules program executes?)
  (if executes?
      (list (landlock-path "/gnu/store" %landlock-read-access))
      (cons (read-only-rule "/gnu/store")
            (map (cut landlock-path <> '(execute))
                 (cons program (elf-interpreters program))))))

(define (base-rules program executes?)
  (append (store-rules program executes?)
          (list (read-only-rule "/etc")
                (landlock-path "/dev/null" '(read-file write-file))
                (read-only-rule "/dev/urandom")
                (landlock-path (string-append "/proc/"
                                              (number->string (getpid)))
                               '(read-file read-dir write-file)))))

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

(define (argument-files-rules arguments)
  (filter-map (lambda (argument)
                (let ((file (argument-file argument)))
                  (and file
                       (file-exists? file)
                       (read-only-rule file))))
              arguments))

(define (normalize-file-name file)
  "Return FILE without empty components, or #f if it isn't absolute and
canonical."
  (and (string-prefix? "/" file)
       (let ((components (remove string-null? (string-split file #\/))))
         (and (not (any (cut member <> '("." "..")) components))
              (string-append "/" (string-join components "/"))))))

(define (directory-contains? directory file)
  (or (string=? directory "/")
      (string-prefix? (string-append directory "/") (string-append file "/"))))

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

(define (user-directory name default)
  "Return the XDG user directory NAME, or #f if it contains the home
directory."
  (let* ((home (normalize-file-name (getenv* "HOME")))
         (value (or (user-directory-setting name)
                    (string-append "$HOME/" default)))
         (directory (and home (normalize-file-name (expand-home value home)))))
    (and directory
         (not (directory-contains? directory home))
         directory)))

(define (graphics-rules arguments)
  (list (landlock-path "/dev/dri" '(read-file write-file read-dir ioctl-dev)
                       #:optional? #t)
        (read-only-rule "/sys")))

(define (fonts-rules arguments)
  (list (read-only-rule "/var/cache/fontconfig")
        (read-only-rule (config-path "fontconfig"))
        (read-only-rule (cache-path "fontconfig"))))

(define (shm-rules arguments)
  "Shared memory of other programs stays open to guessing its name."
  (list (landlock-path "/dev/shm"
                       '(read-file write-file truncate make-reg remove-file)
                       #:optional? #t)))

(define (dns-rules arguments)
  "DNS queries can still carry data to anyone."
  (list (landlock-path "/var/run/nscd" '(resolve-unix) #:optional? #t)
        (landlock-port 53 '(connect-send-udp))))

(define (gnupg-rules arguments)
  "Decrypt through gpg-agent, without access to the secret keys."
  (let ((home (or (getenv "GNUPGHOME") (home-path ".gnupg"))))
    (cons (landlock-path (runtime-path "gnupg") '(resolve-unix) #:optional? #t)
          (map (lambda (file)
                 (read-only-rule (string-append home "/" file)))
               '("pubring.kbx" "pubring.gpg" "trustdb.gpg"
                 "gpg.conf" "common.conf")))))

(define (mail-directory-rules arguments)
  (list (read-write-rule (or (getenv "MAILDIR") (home-path "Mail"))
                         #:create? #t)))

(define (xdg-config-rules arguments name)
  (list (read-only-rule (config-path name))))

(define (xdg-state-rules arguments name)
  (list (read-write-rule (state-path name) #:create? #t)))

(define (xdg-cache-rules arguments name)
  (list (read-write-rule (cache-path name) #:create? #t)))

(define (xdg-user-directory-rules arguments name default)
  (match (user-directory name default)
    (#f '())
    (directory (list (read-write-rule directory)))))

(define (home-file-rules arguments name)
  (list (read-only-rule (home-path name))))

(define (read-only-rules arguments file)
  (list (read-only-rule file)))

(define (read-write-rules arguments file)
  (list (read-write-rule file)))

(define (devices-rules arguments . files)
  (map (cut landlock-path <> '(read-file write-file ioctl-dev) #:optional? #t)
       files))

(define (tcp-ports-rules arguments . ports)
  (map (cut landlock-port <> '(connect-tcp)) ports))

(define (rule-kinds)
  (list (rule-kind 'graphics graphics-rules)
        (rule-kind 'fonts fonts-rules)
        (rule-kind 'shm shm-rules)
        (rule-kind 'dns dns-rules)
        (rule-kind 'gnupg gnupg-rules
                   #:variables '("GNUPGHOME" "GPG_TTY"))
        (rule-kind 'argument-files argument-files-rules)
        (rule-kind 'mail-directory mail-directory-rules
                   #:variables '("MAILDIR"))
        (rule-kind 'xdg-config xdg-config-rules)
        (rule-kind 'xdg-state xdg-state-rules)
        (rule-kind 'xdg-cache xdg-cache-rules)
        (rule-kind 'xdg-user-directory xdg-user-directory-rules)
        (rule-kind 'home-file home-file-rules)
        (rule-kind 'read-only read-only-rules)
        (rule-kind 'read-write read-write-rules)
        (rule-kind 'devices devices-rules)
        (rule-kind 'tcp-ports tcp-ports-rules)
        (conditional-rule-kind 'when-network-arguments network-arguments?)))
