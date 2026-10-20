;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked environment)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked landlock)
  #:use-module (guix-cage build locked namespaces)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked rules)
  #:use-module (guix-cage build locked sandbox)
  #:use-module (guix-cage build locked spawn)
  #:use-module (guix-cage build locked syscalls)
  #:use-module (srfi srfi-26)
  #:export (run-locked))

;; Where the sandbox finds the program under its name
(define %commands "/run/locked")

(define (enter-sandbox sandbox)
  (when (sandbox-detached? sandbox)
    (setsid))
  (false-if-exception (chdir (sandbox-directory sandbox)))
  (enforce-landlock! (sandbox-landlock-rules sandbox))
  (enforce-syscall-filter! (sandbox-syscall-allowances sandbox))
  (apply-resource-limits! (sandbox-resource-limits sandbox))
  (close-on-exec-except (sandbox-fds sandbox))
  (when (sandbox-deny-write-execute? sandbox)
    (deny-write-execute!))
  (match (sandbox-command sandbox)
    ((program . arguments)
     (apply execle program (sandbox-environment sandbox) program arguments))))

(define (call-in-sandbox sandbox)
  (call-in-namespaces (sandbox-namespaces sandbox)
                      (sandbox-file-systems sandbox)
                      (sandbox-links sandbox)
                      (lambda ()
                        (call-with-error-reporting
                         (lambda ()
                           (enter-sandbox sandbox))))
                      #:signals (sandbox-signals sandbox)))

(define* (run-locked program rules
                     #:key (name (basename program))
                     init
                     (environment '())
                     (preserved-environment-variables
                      %default-preserved-environment-variables)
                     (executes? #t)
                     deny-write-execute?
                     (resource-limits %default-resource-limits)
                     (syscall-allowances '()))
  "Execute PROGRAM as NAME with the arguments of this process in a sandbox
that grants what RULES grant, with INIT, tini, as its first process."
  (call-with-error-reporting
   (lambda ()
     (let* ((arguments (cdr (command-line)))
            ;; Outside the sandbox, rules read the environment of the host
            ;; and start helpers such as xdg-dbus-proxy
            (grant (apply grant-append
                          (base-grant (list program init) executes?)
                          (map (cut <> (cons name arguments)) rules)))
            (command (string-append %commands "/" name)))
       (exit
        (status->exit-code
         (call-in-sandbox
          (sandbox grant
                   ;; tini, and with it the sandbox, dies with this process
                   `(,init "-p" "SIGKILL" "--" ,command ,@arguments)
                   #:environment
                   (program-environment
                    preserved-environment-variables
                    (append environment
                            (grant-variables grant)
                            ;; Through a shared shader cache, programs could
                            ;; poison others
                            '(("MESA_SHADER_CACHE_DISABLE" . "true"))))
                   #:links `((,command . ,program))
                   #:directory (getcwd)
                   #:syscall-allowances syscall-allowances
                   #:resource-limits resource-limits
                   #:deny-write-execute? deny-write-execute?
                   #:detached? (terminal-injection-possible?)))))))))
