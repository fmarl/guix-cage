;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(use-modules (gnu packages video)
             (guix build utils)
             ((guix diagnostics) #:select (formatted-message?
                                           formatted-message-string
                                           formatted-message-arguments))
             (guix gexp)
             (guix packages)
             ((ice-9 exceptions) #:select (exception-message))
             (ice-9 ftw)
             (ice-9 match)
             (ice-9 string-fun)
             (ice-9 textual-ports)
             (landlock)
             (rnrs bytevectors)
             ((seccomp) #:select (seccomp-rule seccomp-supported?))
             (guix-cage build locked environment)
             (guix-cage build locked grants)
             ((gnu build linux-container)
              #:select (unprivileged-user-namespace-supported?))
             ((gnu system file-systems) #:select (file-system-mount-point
                                                  file-system-type
                                                  file-system-flags))
             ((guix-cage build locked dbus) #:prefix build:)
             ((guix-cage build locked gnupg) #:prefix build:)
             ((guix-cage build locked rules) #:prefix build:)
             ((guix-cage build locked) #:select (run-locked))
             ((guix-cage build locked errors)
              #:select (locked-error? call-with-error-reporting))
             ((guix-cage build locked file-names)
              #:select (directory-contains?))
             ((guix-cage build locked instances)
              #:select (make-instance-directory retain-instance-only!))
             ((guix-cage build locked landlock)
              #:select (landlock-rules enforce-landlock!))
             ((guix-cage build locked namespaces)
              #:select (%container-grant file-systems store-links))
             ((guix-cage build locked platform)
              #:select (%supported-systems check-platform!))
             ((guix-cage build locked process)
              #:select (close-on-exec-except deny-write-execute!
                        apply-resource-limits!))
             ((guix-cage build locked rules) #:select (base-grant))
             (guix-cage build locked sandbox)
             (guix-cage build locked known-syscalls)
             ((guix-cage build locked syscalls)
              #:select (enforce-syscall-filter!))
             ((guix-cage build locked-package)
              #:select (install-locked-package))
             (guix-cage locked)
             (srfi srfi-1)
             (srfi srfi-26)
             (srfi srfi-34)
             (srfi srfi-64)
             (system foreign)
             (system foreign-library))

(define mpv-locked
  (make-locked-package
   mpv
   (list (locked-command
           (name "mpv")
           (program (file-append mpv "/bin/mpv"))))))

(define-syntax-rule (define-internal module name ...)
  (begin (define name (@@ module name)) ...))

(define (access->list access)
  (if (file-access? access)
      (list (file-access-file access) (file-access-permissions access))
      (list (port-access-port access) (port-access-protocol access))))

(define (call-with-environment-variables variables thunk)
  "Call THUNK with VARIABLES, an alist where #f unsets a variable."
  (let ((saved (map (match-lambda
                      ((name . _) (cons name (getenv name))))
                    variables)))
    (dynamic-wind
      (lambda ()
        (for-each (match-lambda
                    ((name . value) (setenv name value)))
                  variables))
      thunk
      (lambda ()
        (for-each (match-lambda
                    ((name . value) (setenv name value)))
                  saved)))))

(define (call-with-replacement module name replacement thunk)
  "Call THUNK while NAME in MODULE is REPLACEMENT."
  (let* ((module (resolve-module module))
         (original (module-ref module name)))
    (dynamic-wind
      (lambda () (module-set! module name replacement))
      thunk
      (lambda () (module-set! module name original)))))

(define (call-with-temporary-directory proc)
  (let ((directory (mkdtemp (string-append (or (getenv "TMPDIR") "/tmp")
                                           "/locked-test-XXXXXX"))))
    (dynamic-wind
      (const #t)
      (lambda () (proc directory))
      (lambda () (delete-file-recursively directory)))))

(define (call-with-runtime-directory proc)
  (call-with-temporary-directory
   (lambda (directory)
     (call-with-environment-variables `(("XDG_RUNTIME_DIR" . ,directory))
       (lambda ()
         (proc directory))))))

(define (call-with-sandbox-home proc)
  "Call PROC with a temporary home and runtime directory."
  (call-with-temporary-directory
   (lambda (directory)
     (let ((home (string-append directory "/home"))
           (runtime (string-append directory "/run")))
       (mkdir-p home)
       (mkdir-p runtime)
       (call-with-environment-variables
        `(("HOME" . ,home)
          ("XDG_RUNTIME_DIR" . ,runtime)
          ("XDG_CONFIG_HOME" . ,(string-append home "/.config")))
        (lambda ()
          (proc home runtime)))))))

(define (dead-pid)
  (match (primitive-fork)
    (0 (primitive-_exit 0))
    (pid (waitpid pid) pid)))

(define (in-child thunk)
  (flush-all-ports)
  (match (pipe)
    ((in . out)
     (match (primitive-fork)
       (0
        (close-port in)
        (write (false-if-exception (thunk)) out)
        (close-port out)
        (primitive-_exit 0))
       (pid
        (close-port out)
        (let ((result (read in)))
          (close-port in)
          (waitpid pid)
          (and (not (eof-object? result)) result)))))))

(define (process-ends? pid)
  (define (ended?)
    (match (false-if-exception
            (call-with-input-file (format #f "/proc/~a/stat" pid)
              get-string-all))
      (#f #t)
      (stat (and (string-contains stat ") Z ") #t))))

  (let loop ((tries 50))
    (or (ended?)
        (and (positive? tries)
             (begin (usleep 100000)
                    (loop (1- tries)))))))

(define (unix-socket file)
  (bind (socket PF_UNIX SOCK_STREAM 0) AF_UNIX file)
  file)

(define (listening-socket file)
  (let ((listener (socket PF_UNIX SOCK_STREAM 0)))
    (bind listener AF_UNIX file)
    (listen listener 1)
    listener))

(define (can-connect? file)
  (false-if-exception
   (let ((connection (socket PF_UNIX SOCK_STREAM 0)))
     (connect connection AF_UNIX file)
     (close-port connection)
     #t)))

(define (readable? file)
  (and (false-if-exception (call-with-input-file file get-string-all)) #t))

(define (write-file file content)
  (mkdir-p (dirname file))
  (call-with-output-file file (cut display content <>)))

(define (store-program name)
  (canonicalize-path (search-path (parse-path (getenv "PATH")) name)))

(define guile (store-program "guile"))
(define tini (store-program "tini"))

(define (feature-available? available? feature)
  "Return AVAILABLE?.  Report FEATURE if it is missing, and fail unless
LOCKED_TESTS_ALLOW_SKIP is set."
  (unless available?
    (format (current-error-port) "missing kernel feature: ~a~%" feature)
    (unless (getenv "LOCKED_TESTS_ALLOW_SKIP")
      (exit 1)))
  available?)

(define-syntax-rule (test-rejects name message expression)
  (test-assert name
    (guard (exception ((formatted-message? exception)
                       (string-contains
                        (apply format #f
                               (formatted-message-string exception)
                               (formatted-message-arguments exception))
                        message)))
      expression
      #f)))

(define-syntax-rule (test-locked-error name expression)
  (test-assert name
    (guard (exception ((locked-error? exception) #t))
      expression
      #f)))

(define-internal (guix-cage build locked instances)
  delete-beneath)
(define-internal (guix-cage build locked syscalls)
  restrict! restrict-to-known!)
(define-internal (guix-cage build locked rules)
  elf-interpreters user-directory argument-file arguments-match?)
(define-internal (guix-cage build locked wayland)
  wayland-string wayland-string-ref wayland-message)

(define (granted rule . arguments)
  "Return what RULE grants for ARGUMENTS."
  (rule (cons "test" arguments)))

(define (accesses grant)
  (map access->list (append (grant-files grant) (grant-ports grant))))

(define (restrict-to! grant)
  (landlock-restrict! (landlock-rules grant)))

(define (user-directory-with line)
  (call-with-temporary-directory
   (lambda (home)
     (write-file (string-append home "/.config/user-dirs.dirs") line)
     (call-with-environment-variables
      `(("HOME" . ,home)
        ("XDG_CONFIG_HOME" . ,(string-append home "/.config")))
      (lambda ()
        (and=> (user-directory "DOWNLOAD" "Downloads")
               (lambda (directory)
                 (if (string-prefix? home directory)
                     (string-append "~" (string-drop directory
                                                     (string-length home)))
                     directory))))))))


(define (exit-with thunk)
  "Call THUNK in this child process, and exit as it asks, or with 127 if it
fails."
  (catch #t
    thunk
    (match-lambda*
      (('quit (? integer? status)) (primitive-_exit status))
      (_ (primitive-_exit 127)))))

(define (exit-status-of thunk)
  "Return the exit status of a child process that calls THUNK."
  (flush-all-ports)
  (match (primitive-fork)
    (0 (exit-with thunk))
    (pid (status:exit-val (cdr (waitpid pid))))))

(define (exit-status-under rules command)
  (exit-status-of (lambda ()
                    (landlock-restrict! rules)
                    (apply execl (car command) command))))
