;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked)
  #:use-module (guix-cage build locked confinement)
  #:use-module (guix-cage build locked environment)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked platform)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked rules)
  #:use-module (guix-cage build locked sandbox)
  #:use-module (guix-cage build locked spawn)
  #:use-module (srfi srfi-26)
  #:export (run-locked))

;; Where the sandbox finds the program under its name
(define %commands "/run/locked")

(define* (run-locked program rules
                     #:key (name (basename program))
                     init
                     (environment '())
                     (preserved-environment-variables
                      %default-preserved-environment-variables)
                     (executes-others? #t)
                     (own-namespaces? #t)
                     deny-write-execute?
                     (resource-limits %default-resource-limits)
                     (allowed-syscall-groups '()))
  "Execute PROGRAM as NAME with the arguments of this process in a sandbox
that grants what RULES grant, and return its exit code.  With
OWN-NAMESPACES?, the sandbox has namespaces of its own and INIT, tini, as its
first process."
  (call-with-error-reporting
   (lambda ()
     (check-platform!)
     (when (and own-namespaces? (not init))
       (raise-locked-error "namespaces of its own need an init program"))
     (let* ((arguments (cdr (command-line)))
            ;; Outside the sandbox, rules read the environment of the host
            ;; and start helpers such as xdg-dbus-proxy
            (grant (apply grant-append
                          (base-grant (if own-namespaces?
                                          (list program init)
                                          (list program))
                                      executes-others?)
                          (map (cut <> (cons name arguments)) rules)))
            (options
             (list #:environment
                   (program-environment
                    preserved-environment-variables
                    (append environment
                            (grant-variables grant)
                            ;; Through a shared shader cache, programs could
                            ;; poison others
                            '(("MESA_SHADER_CACHE_DISABLE" . "true"))))
                   #:directory (getcwd)
                   #:allowed-syscall-groups allowed-syscall-groups
                   #:resource-limits resource-limits
                   #:deny-write-execute? deny-write-execute?
                   #:new-session? (terminal-injection-possible?))))
       (status->exit-code
        (call-in-sandbox
         (if own-namespaces?
             (let ((command (string-append %commands "/" name)))
               (apply container-sandbox grant
                      ;; tini, and with it the sandbox, dies with this process
                      `(,init "-p" "SIGKILL" "--" ,command ,@arguments)
                      #:links `((,command . ,program))
                      options))
             (apply host-sandbox grant (cons program arguments)
                    options))))))))
