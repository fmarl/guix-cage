;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked process)
  #:use-module (ice-9 match)
  #:use-module (ice-9 textual-ports)
  #:use-module (guix-cage build locked errors)
  #:use-module (srfi srfi-1)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (inherit-across-exec!
            close-on-exec-except
            deny-write-execute!
            die-with-parent!
            %default-resource-limits
            apply-resource-limits!
            terminal-injection-possible?))

(define (inherit-across-exec! port)
  ;; Revealed descriptors stay open across exec
  (port->fdes port))

(define %close-range-cloexec 4)

(define close-range
  (delay (foreign-library-function #f "close_range"
                                   #:return-type int
                                   #:arg-types (list unsigned-int unsigned-int
                                                     int)
                                   #:return-errno? #t)))

(define (close-on-exec-except keep)
  (call-with-values
      (lambda ()
        ((force close-range) 0 #xffffffff %close-range-cloexec))
    (lambda (result errno)
      (when (< result 0)
        (raise-locked-error "cannot close descriptors on exec: ~a"
                            (strerror errno)))))
  (for-each (lambda (fd)
              (false-if-exception (fcntl fd F_SETFD 0)))
            keep))

(define %pr-set-mdwe 65)
(define %pr-mdwe-refuse-exec-gain 1)

(define prctl
  (delay (foreign-library-function #f "prctl"
                                   #:return-type int
                                   #:arg-types (list int unsigned-long
                                                     unsigned-long
                                                     unsigned-long
                                                     unsigned-long)
                                   #:return-errno? #t)))

(define %pr-set-pdeathsig 1)

(define (prctl! option argument action)
  (call-with-values
      (lambda ()
        ((force prctl) option argument 0 0 0))
    (lambda (result errno)
      (when (< result 0)
        (raise-locked-error "cannot ~a: ~a" action (strerror errno))))))

(define (deny-write-execute!)
  (prctl! %pr-set-mdwe %pr-mdwe-refuse-exec-gain
          "deny writable executable memory"))

(define (die-with-parent! parent)
  (prctl! %pr-set-pdeathsig SIGKILL "die with the parent")
  (unless (= (getppid) parent)
    (raise-locked-error "the parent process has ended")))

(define %default-resource-limits
  '((core . 0) (rtprio . 0) (nice . 0)))

(define (apply-resource-limits! limits)
  (for-each (match-lambda
              ((resource . limit)
               (setrlimit resource limit limit)))
            limits))

(define (legacy-tiocsti?)
  (let ((file "/proc/sys/dev/tty/legacy_tiocsti"))
    (or (not (file-exists? file))
        (not (string=? "0" (string-trim-both
                            (call-with-input-file file get-string-all)))))))

(define (terminal-injection-possible?)
  "Whether a program on the terminal could inject input with TIOCSTI."
  (and (legacy-tiocsti?)
       (any isatty? (list (current-input-port) (current-output-port)
                          (current-error-port)))))
