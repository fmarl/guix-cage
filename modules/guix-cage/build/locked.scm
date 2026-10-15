;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked)
  #:autoload (landlock) (landlock-abi-version landlock-restrict!)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked dbus)
  #:use-module (guix-cage build locked environment)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked files)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked kinds)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked rules)
  #:use-module (guix-cage build locked syscalls)
  #:use-module (guix-cage build locked wayland)
  #:use-module (srfi srfi-1)
  #:export (run-locked))

(define (resolve-spec spec)
  (match spec
    ((module name . parameters)
     (let ((kind (module-rule-kind module name)))
       (cons kind
             (if (conditional-rule-kind? kind)
                 (match parameters
                   ((condition-parameter . specs)
                    (cons condition-parameter (map resolve-spec specs))))
                 parameters))))))

(define (resolved-rule-kinds resolved)
  (append-map (match-lambda
                (((? conditional-rule-kind?) _ . nested)
                 (resolved-rule-kinds nested))
                ((kind . _)
                 (list kind)))
              resolved))

(define (landlock-rules resolved arguments)
  (append-map (match-lambda
                (((? conditional-rule-kind? kind) condition-parameter
                  . nested)
                 (if ((conditional-rule-kind-condition kind)
                      arguments condition-parameter)
                     (landlock-rules nested arguments)
                     '()))
                ((kind . parameters)
                 (apply (rule-kind-rules kind) arguments parameters)))
              resolved))

(define (share-pipewire!)
  (share-socket! (runtime-path "pipewire-0")
                 (lambda (socket)
                   `(("PIPEWIRE_RUNTIME_DIR" . ,(dirname socket))
                     ("PIPEWIRE_REMOTE" . ,(basename socket))))))

(define (private-directory! name variable)
  (let ((directory (make-instance-directory name)))
    (grant (list (read-write-rule directory))
           `((,variable . ,directory)))))

(define %landlock-log-abi 7)

(define (enforce-rules! rules)
  (let ((status (landlock-restrict!
                 rules
                 #:scope '(signal abstract-unix-socket)
                 #:flags (if (>= (landlock-abi-version) %landlock-log-abi)
                             '(log-new-exec-on)
                             '()))))
    (unless (eq? status 'fully-enforced)
      (raise-locked-error "Landlock ABI ~a cannot enforce the whole sandbox \
(~a)"
                          (landlock-abi-version) status))))

(define (program-grants name wayland pipewire? dbus dbus-proxy
                        runtime-directory? temporary-directory?)
  (define (grant-when condition proc . arguments)
    (if condition (apply proc arguments) %no-grant))

  (list (match wayland
          (#f %no-grant)
          ('restricted (share-wayland-context! name))
          ('full (share-wayland!)))
        (grant-when pipewire? share-pipewire!)
        (grant-when dbus share-dbus! dbus-proxy dbus)
        (grant-when runtime-directory?
                    private-directory! "runtime" "XDG_RUNTIME_DIR")
        (grant-when temporary-directory?
                    private-directory! "tmp" "TMPDIR")))

(define (set-environment! preserved variables)
  (preserve-environment! preserved)
  (for-each (match-lambda
              ((variable . value) (setenv variable value)))
            ;; Through a shared shader cache, programs could poison others
            (cons '("MESA_SHADER_CACHE_DISABLE" . "true") variables)))

(define* (run-locked program specs
                     #:key (name (basename program))
                     wayland pipewire? dbus dbus-proxy
                     runtime-directory? temporary-directory?
                     (environment '())
                     (preserved-environment-variables
                      %default-preserved-environment-variables)
                     (executes? #t)
                     deny-write-execute?
                     (resource-limits %default-resource-limits)
                     (syscall-allowances '()))
  "Execute PROGRAM as NAME, confined by Landlock and seccomp."
  (call-with-error-reporting
   (lambda ()
     ;; It may fork, and the rules name the PID
     (detach-from-terminal!)
     (let* ((resolved (map resolve-spec specs))
            (arguments (cdr (command-line)))
            (rules (landlock-rules resolved arguments))
            ;; Grants read variables that set-environment! drops
            (grants (program-grants name wayland pipewire? dbus dbus-proxy
                                    runtime-directory?
                                    temporary-directory?)))
       (set-environment! (append preserved-environment-variables
                                 (append-map rule-kind-variables
                                             (resolved-rule-kinds resolved)))
                         (append environment
                                 (append-map grant-variables grants)))
       (enforce-rules! (append (base-rules program executes?) rules
                               (append-map grant-rules grants)))
       (enforce-syscall-filter! syscall-allowances)
       (apply-resource-limits! resource-limits)
       (close-on-exec-except (cons* 0 1 2 (append-map grant-fds grants)))
       (when deny-write-execute?
         (deny-write-execute!))
       (apply execl program name arguments)))))
