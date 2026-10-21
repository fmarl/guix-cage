;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked syscalls)
  #:autoload (seccomp) (seccomp-argument
                        seccomp-error?
                        seccomp-restrict!
                        seccomp-rule)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%syscall-groups
            enforce-syscall-filter!))

(define %clone-newuser #x10000000)

(define %af-unix 1)
(define %af-inet 2)
(define %af-inet6 10)
(define %af-netlink 16)
(define %af-max 46)
(define %netlink-route 0)

;; The flags such as SOCK_CLOEXEC are above
(define %sock-type-mask #xf)

;; Landlock only confines TCP and UDP, so ICMP, SCTP or MPTCP would get past
;; it on the network of the host
(define %inet-protocols
  `((,SOCK_STREAM 0 ,IPPROTO_TCP)
    (,SOCK_DGRAM 0 ,IPPROTO_UDP)))

(define %personality-query-bit #x80000000)
(define %addr-no-randomize #x0040000)
(define %mmap-page-zero #x0100000)
(define %read-implies-exec #x0400000)

(define (denied syscall . arguments)
  (apply seccomp-rule syscall `(errno ,EPERM) arguments))

(define (other-values values size)
  "Return the values and masks that match the numbers below SIZE, a power of
two, other than VALUES."
  (define (blocks start end)
    ;; The largest aligned blocks from START to END
    (if (>= start end)
        '()
        (let loop ((block 1))
          (if (and (zero? (modulo start (* 2 block)))
                   (<= (+ start (* 2 block)) end))
              (loop (* 2 block))
              (cons (cons start (logand (- block) (1- size)))
                    (blocks (+ start block) end))))))

  (let loop ((start 0)
             (values (sort values <)))
    (match values
      (() (blocks start size))
      ((value . rest) (append (blocks start value) (loop (1+ value) rest))))))

(define (masked-argument index)
  (match-lambda
    ((value . mask)
     (seccomp-argument index 'masked= value #:mask mask #:width 32))))

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
                             (seccomp-argument 2 '!= %netlink-route))
                (seccomp-rule 'socketpair `(errno ,EAFNOSUPPORT)
                              (seccomp-argument 0 '!= %af-unix)))))

(define (socket-protocols-rules)
  (define (unsupported family . arguments)
    (apply seccomp-rule 'socket `(errno ,EPROTONOSUPPORT)
           (seccomp-argument 0 '= family #:width 32)
           arguments))

  (append-map
   (lambda (family)
     (append (map (compose (cut unsupported family <>) (masked-argument 1))
                  (other-values (map first %inet-protocols)
                                (1+ %sock-type-mask)))
             (append-map
              (match-lambda
                ((type . protocols)
                 (map (compose (cut unsupported family
                                    ((masked-argument 1)
                                     (cons type %sock-type-mask))
                                    <>)
                               (masked-argument 2))
                      (other-values protocols (expt 2 32)))))
              %inet-protocols)))
   (list %af-inet %af-inet6)))

(define (keyring-rules)
  (map denied '(keyctl add_key request_key)))

(define (userfaultfd-rules)
  (list (denied 'userfaultfd)))

(define (perf-rules)
  (list (denied 'perf_event_open)))

(define (io-uring-rules)
  ;; Its operations get past seccomp.  With ENOSYS, programs fall back.
  (map (cut seccomp-rule <> `(errno ,ENOSYS))
       '(io_uring_setup io_uring_enter io_uring_register)))

(define (bpf-rules)
  (list (denied 'bpf)))

(define (fanotify-rules)
  (list (denied 'fanotify_init)))

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
    (socket-protocols . ,socket-protocols-rules)
    (keyring . ,keyring-rules)
    (userfaultfd . ,userfaultfd-rules)
    (perf . ,perf-rules)
    (io-uring . ,io-uring-rules)
    (bpf . ,bpf-rules)
    (fanotify . ,fanotify-rules)
    (personality . ,personality-rules)))

(define %quiet-syscall-groups
  `((user-namespaces . ,clone3-rules)))

(define (group-rules groups allowances)
  (append-map (match-lambda
                ((name . rules)
                 (if (memq name allowances) '() (rules))))
              groups))

(define (restrict! rules flags)
  (let ((status (guard (e ((seccomp-error? e)
                           (raise-locked-error "seccomp: ~a ~s"
                                               (exception-message e)
                                               (exception-irritants e))))
                  (seccomp-restrict! rules #:flags flags))))
    (unless (eq? status 'fully-enforced)
      (raise-locked-error "seccomp cannot enforce the whole filter (~a)"
                          status))))

(define (enforce-syscall-filter! allowances)
  (restrict! (group-rules %syscall-groups allowances) '(log))
  ;; glibc tries clone3 for every thread, so its fallback stays unlogged
  (restrict! (group-rules %quiet-syscall-groups allowances) '()))
