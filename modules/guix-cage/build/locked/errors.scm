;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked errors)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:export (locked-error?
            raise-locked-error
            check-parameters
            call-with-error-reporting))

(define-exception-type &locked-error &error
  make-locked-error
  locked-error?)

(define (raise-locked-error message . arguments)
  (raise-exception
   (make-exception (make-locked-error)
                   (make-exception-with-message
                    (apply format #f message arguments)))))

(define (check-parameters rule valid? . parameters)
  (unless (apply valid? parameters)
    (raise-locked-error "invalid parameters of ~a: ~s" rule parameters)))

(define (system-error? exception)
  (eq? 'system-error (exception-kind exception)))

(define (system-error-message exception)
  (match (exception-args exception)
    ((subr message arguments . _)
     (format #f "~a: ~a" subr (apply format #f message arguments)))))

(define (call-with-error-reporting thunk)
  (define (report message)
    (format (current-error-port) "locked: ~a~%" message)
    ;; In the sandbox, the process ends without flushing
    (force-output (current-error-port))
    (exit 1))

  (with-exception-handler
      (lambda (exception)
        (cond ((locked-error? exception)
               (report (exception-message exception)))
              ((system-error? exception)
               (report (system-error-message exception)))
              (else
               (raise-exception exception))))
    thunk
    #:unwind? #t))
