;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked process)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (ice-9 textual-ports)
  #:use-module (ice-9 threads)
  #:use-module (guix-cage build locked errors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (inherit-across-exec!
            spawn-detached
            detach-from-terminal!
            close-on-exec-except
            deny-write-execute!
            %default-resource-limits
            apply-resource-limits!))

(define (inherit-across-exec! port)
  ;; Revealed descriptors stay open across exec
  (port->fdes port))

(define (open-fdes-except keep)
  (remove (cut memv <> keep)
          (filter-map string->number (scandir "/proc/self/fd"))))

(define (close-fdes-except keep)
  (for-each (lambda (fd)
              (false-if-exception (close-fdes fd)))
            (open-fdes-except keep)))

(define (close-on-exec-except keep)
  (for-each (lambda (fd)
              (false-if-exception (fcntl fd F_SETFD FD_CLOEXEC)))
            (open-fdes-except keep)))

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

(define (deny-write-execute!)
  (call-with-values
      (lambda ()
        ((force prctl) %pr-set-mdwe %pr-mdwe-refuse-exec-gain 0 0 0))
    (lambda (result errno)
      (when (< result 0)
        (raise-locked-error "cannot deny writable executable memory: ~a"
                            (strerror errno))))))

(define %default-resource-limits
  '((core . 0) (rtprio . 0) (nice . 0)))

(define (apply-resource-limits! limits)
  (for-each (match-lambda
              ((resource . limit)
               (setrlimit resource limit limit)))
            limits))

(define (spawn-detached fd program . arguments)
  "Run PROGRAM detached, with only the standard descriptors and FD."
  (match (primitive-fork)
    (0
     (catch #t
       (lambda ()
         (match (primitive-fork)
           (0
            (close-fdes-except (list 0 1 2 fd))
            (apply execl program program arguments))
           (_ #t)))
       (const #f))
     (primitive-_exit 0))
    (pid
     (waitpid pid))))

(define (legacy-tiocsti?)
  (let ((file "/proc/sys/dev/tty/legacy_tiocsti"))
    (or (not (file-exists? file))
        (not (string=? "0" (string-trim-both
                            (call-with-input-file file get-string-all)))))))

(define (forward-signals-and-exit pid)
  (for-each (lambda (signal)
              (sigaction signal
                (lambda (signal)
                  (false-if-exception (kill pid signal)))))
            (list SIGINT SIGTERM SIGHUP SIGQUIT))
  ;; The handlers only run while this thread waits in Scheme
  (let ((status (join-thread (call-with-new-thread
                              (lambda ()
                                (cdr (waitpid pid)))))))
    (exit (or (status:exit-val status)
              (+ 128 (status:term-sig status))))))

(define (detach-from-terminal!)
  "Leave the terminal if the program could inject input with TIOCSTI."
  (when (and (legacy-tiocsti?)
             (any isatty? (list (current-input-port) (current-output-port)
                                (current-error-port))))
    (match (primitive-fork)
      (0 (setsid))
      (pid (forward-signals-and-exit pid)))))
