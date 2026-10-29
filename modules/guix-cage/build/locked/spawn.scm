;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked spawn)
  #:use-module ((gnu build linux-container) #:select (call-with-container))
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked process)
  #:export (call-in-child
            call-in-process
            spawn-detached
            status->exit-code))

(define (call-in-child thunk)
  "Call THUNK in a child process and return whether it returned."
  (flush-all-ports)
  (match (primitive-fork)
    (0
     (primitive-_exit (catch #t
                        (lambda () (thunk) 0)
                        (const 1))))
    (pid
     (zero? (status:exit-val (cdr (waitpid pid)))))))

(define (spawn-detached fd program . arguments)
  "Run PROGRAM detached, with only the standard descriptors and FD."
  (match (primitive-fork)
    (0
     (catch #t
       (lambda ()
         (match (primitive-fork)
           (0
            (close-on-exec-except (list 0 1 2 fd))
            (apply execl program program arguments))
           (_ #t)))
       (const #f))
     (primitive-_exit 0))
    (pid
     (waitpid pid))))

(define (status->exit-code status)
  "Return the exit code of a shell for STATUS, from waitpid."
  (or (status:exit-val status)
      (+ 128 (or (status:term-sig status) (status:stop-sig status)))))

(define* (call-in-process thunk #:key (signals '()))
  (call-with-container '() thunk
    #:namespaces '()
    #:relayed-signals signals))
