;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked syscalls)
  #:autoload (seccomp) (seccomp-argument seccomp-restrict! seccomp-rule)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (srfi srfi-1)
  #:export (%syscall-groups
            enforce-syscall-filter!))

(define %clone-newuser #x10000000)

(define %af-unix 1)
(define %af-inet 2)
(define %af-inet6 10)
(define %af-netlink 16)
(define %af-max 46)
(define %netlink-route 0)

(define %personality-query-bit #x80000000)
(define %addr-no-randomize #x0040000)
(define %mmap-page-zero #x0100000)
(define %read-implies-exec #x0400000)

(define (denied syscall . arguments)
  (apply seccomp-rule syscall `(errno ,EPERM) arguments))

(define (user-namespaces-rules)
  (let ((newuser (seccomp-argument 0 'masked= %clone-newuser
                                   #:mask %clone-newuser)))
    (list (denied 'unshare newuser)
          (denied 'clone newuser))))

(define (clone3-rules)
  (list (seccomp-rule 'clone3 `(errno ,ENOSYS))))

(define (socket-families-rules)
  (define (unsupported . arguments)
    (apply seccomp-rule 'socket `(errno ,EAFNOSUPPORT) arguments))

  (append (map (lambda (family)
                 (unsupported (seccomp-argument 0 '= family #:width 32)))
               (lset-difference = (iota %af-max)
                                (list %af-unix %af-inet %af-inet6
                                      %af-netlink)))
          ;; Safe at 64 bits, since the upper half only makes it larger
          (list (unsupported (seccomp-argument 0 '>= %af-max))
                (unsupported (seccomp-argument 0 '= %af-netlink #:width 32)
                             (seccomp-argument 2 '!= %netlink-route)))))

(define (keyring-rules)
  (map denied '(keyctl add_key request_key)))

(define (userfaultfd-rules)
  (list (denied 'userfaultfd)))

(define (perf-rules)
  (list (denied 'perf_event_open)))

(define (personality-rules)
  (map (lambda (personality)
         (denied 'personality
                 (seccomp-argument 0 'masked= personality
                                   #:mask (logior %personality-query-bit
                                                  personality))))
       (list %addr-no-randomize %mmap-page-zero %read-implies-exec)))

(define %syscall-groups
  `((user-namespaces . ,user-namespaces-rules)
    (socket-families . ,socket-families-rules)
    (keyring . ,keyring-rules)
    (userfaultfd . ,userfaultfd-rules)
    (perf . ,perf-rules)
    (personality . ,personality-rules)))

(define %quiet-syscall-groups
  `((user-namespaces . ,clone3-rules)))

(define (group-rules groups allowances)
  (append-map (match-lambda
                ((name . rules)
                 (if (memq name allowances) '() (rules))))
              groups))

(define (restrict! rules flags)
  (let ((status (seccomp-restrict! rules #:flags flags)))
    (unless (eq? status 'fully-enforced)
      (raise-locked-error "seccomp cannot enforce the whole filter (~a)"
                          status))))

(define (enforce-syscall-filter! allowances)
  (restrict! (group-rules %syscall-groups allowances) '(log))
  ;; glibc tries clone3 for every thread, so its fallback stays unlogged
  (restrict! (group-rules %quiet-syscall-groups allowances) '()))
