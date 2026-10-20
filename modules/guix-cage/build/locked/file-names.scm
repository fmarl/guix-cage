;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked file-names)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (file-name-components
            relative-file-name?
            canonical-file-name?
            normalize-file-name
            absolute-file-name
            directory-contains?))

(define (file-name-components file)
  (remove string-null? (string-split file #\/)))

(define (canonical-components? components)
  (not (any (cut member <> '("." "..")) components)))

(define (relative-file-name? name)
  "Whether NAME is relative and non-empty, without . or .. components."
  (and (string? name)
       (not (string-prefix? "/" name))
       (let ((components (file-name-components name)))
         (and (pair? components)
              (canonical-components? components)))))

(define (canonical-file-name? file)
  "Whether FILE is absolute, without . or .. components."
  (and (string? file)
       (string-prefix? "/" file)
       (canonical-components? (file-name-components file))))

(define (normalize-file-name file)
  "Return FILE without empty components, or #f if it isn't absolute and
canonical."
  (and (canonical-file-name? file)
       (string-append "/" (string-join (file-name-components file) "/"))))

(define (absolute-file-name file)
  "Return FILE as absolute, resolving . and .. without looking at the
file system."
  (string-append
   "/"
   (string-join
    (reverse
     (fold (lambda (component result)
             (match component
               ("." result)
               (".." (if (null? result) result (cdr result)))
               (_ (cons component result))))
           '()
           (file-name-components (if (string-prefix? "/" file)
                                     file
                                     (string-append (getcwd) "/" file)))))
    "/")))

(define (directory-contains? directory file)
  (or (string=? directory "/")
      (string-prefix? (string-append directory "/") (string-append file "/"))))
