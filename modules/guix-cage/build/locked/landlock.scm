;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked landlock)
  #:autoload (landlock) (landlock-abi-version
                         landlock-path
                         landlock-port
                         landlock-restrict!)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked grants)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (landlock-rules
            enforce-landlock!))

;;; Landlock limits what the program may do with the files that the
;;; namespaces show, and the ports it may connect to.

(define %permission-rights
  '((list read-dir)
    (read read-file read-dir)
    (write write-file truncate make-reg make-dir make-sym make-sock make-fifo
           remove-file remove-dir refer)
    (execute execute)
    (ioctl ioctl-dev)
    (connect resolve-unix)
    (make-socket make-sock)))

(define (file-access->landlock access)
  (landlock-path (match (file-access-descriptor access)
                   (#f (file-access-file access))
                   (fd (string-append "/proc/self/fd/" (number->string fd))))
                 (delete-duplicates
                  (append-map (cut assq-ref %permission-rights <>)
                              (file-access-permissions access)))
                 #:optional? #t))

(define (port-access->landlock access)
  (landlock-port (port-access-port access)
                 (match (port-access-protocol access)
                   ('tcp '(connect-tcp))
                   ('udp '(connect-send-udp)))))

(define (landlock-rules grant)
  (append (map file-access->landlock (grant-files grant))
          (map port-access->landlock (grant-ports grant))))

(define %log-abi 7)

(define (enforce-landlock! rules)
  (let ((status (landlock-restrict!
                 rules
                 #:scope '(signal abstract-unix-socket)
                 #:flags (if (>= (landlock-abi-version) %log-abi)
                             '(log-new-exec-on)
                             '()))))
    (unless (eq? status 'fully-enforced)
      (raise-locked-error "Landlock ABI ~a cannot enforce the whole sandbox \
(~a)"
                          (landlock-abi-version) status))))
