;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(use-modules (ice-9 match)
             (srfi srfi-1)
             (srfi srfi-26)
             (system base compile))

(define output
  (string-append (or (getenv "TMPDIR") "/tmp") "/check-warnings.go"))

(define (compiler-warnings file)
  (filter (cut string-contains <> ": warning: ")
          (string-split
           (call-with-output-string
             (lambda (port)
               (parameterize ((current-warning-port port))
                 (compile-file file
                               #:output-file output
                               #:opts '(#:warnings (unbound-variable
                                                    arity-mismatch
                                                    format))))))
           #\newline)))

(define (warning-free? file)
  "Compile FILE in a child process, since compiling leaves its module empty
in the process."
  (match (primitive-fork)
    (0
     (catch #t
       (lambda ()
         (let ((warnings (compiler-warnings file)))
           (for-each (cut format #t "~a~%" <>) warnings)
           (force-output)
           (primitive-_exit (if (null? warnings) 0 1))))
       (lambda args
         (format (current-error-port) "~a: ~s~%" file args)
         (force-output (current-error-port))
         (primitive-_exit 1))))
    (pid
     (match (waitpid pid)
       ((_ . status) (eqv? 0 (status:exit-val status)))))))

(exit (every identity (map warning-free? (cdr (command-line)))))
