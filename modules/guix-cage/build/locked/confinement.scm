;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked confinement)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked landlock)
  #:use-module (guix-cage build locked namespaces)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked sandbox)
  #:use-module (guix-cage build locked spawn)
  #:use-module (guix-cage build locked syscalls)
  #:use-module (srfi srfi-26)
  #:export (call-in-sandbox))

(define (enter-sandbox sandbox)
  (when (sandbox-new-session? sandbox)
    (setsid))
  (false-if-exception (chdir (sandbox-directory sandbox)))
  (close-on-exec-except (sandbox-fds sandbox))
  (enforce-landlock! (sandbox-landlock-rules sandbox)
                     (sandbox-landlock-abi sandbox))
  (enforce-syscall-filter! (sandbox-allowed-syscall-groups sandbox))
  (apply-resource-limits! (sandbox-resource-limits sandbox))
  (when (sandbox-deny-write-execute? sandbox)
    (deny-write-execute!))
  (match (sandbox-command sandbox)
    ((program . arguments)
     (apply execle program (sandbox-environment sandbox) program arguments))))

(define (call-in-sandbox sandbox)
  (define (entering prepare)
    (lambda ()
      (primitive-_exit
       (call-with-error-reporting
        (lambda ()
          (prepare)
          (enter-sandbox sandbox))))))

  (match (sandbox-namespaces sandbox)
    (()
     (let ((parent (getpid)))
       (call-in-process (entering (cut die-with-parent! parent))
                        #:signals (sandbox-signals sandbox))))
    (namespaces
     (call-in-namespaces namespaces
                         (sandbox-file-systems sandbox)
                         (sandbox-links sandbox)
                         (entering (const #t))
                         #:signals (sandbox-signals sandbox)))))
