;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(use-modules (ice-9 match)
             (srfi srfi-1)
             (system foreign)
             (system foreign-library))

(define %architectures
  '(#xc000003e #xc00000b7))

(define %unimplemented
  '("_sysctl" "afs_syscall" "create_module" "get_kernel_syms" "getpmsg"
    "nfsservctl" "putpmsg" "query_module" "security" "tuxcall" "uselib"
    "vserver"))

(define (syscall-names library)
  (let ((resolve (foreign-library-function
                  (load-foreign-library library)
                  "seccomp_syscall_resolve_num_arch"
                  #:return-type '*
                  #:arg-types (list uint32 int))))
    (append-map (lambda (architecture)
                  (filter-map (lambda (number)
                                (let ((name (resolve architecture number)))
                                  (and (not (null-pointer? name))
                                       (pointer->string name))))
                              (iota 1024)))
                %architectures)))

(define (filled-lines words indent width)
  (match words
    ((word . others)
     (reverse
      (fold (lambda (word lines)
              (match lines
                ((line . previous)
                 (if (> (+ (string-length line) 1 (string-length word))
                        width)
                     (cons (string-append (make-string indent #\space) word)
                           lines)
                     (cons (string-append line " " word) previous)))))
            (list (string-append (make-string (- indent 2) #\space)
                                 "'(" word))
            others)))))

(match (command-line)
  ((_ library)
   (let ((names (sort (lset-difference string=?
                                       (delete-duplicates
                                        (syscall-names library))
                                       %unimplemented)
                      string<?)))
     (format #t ";;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked known-syscalls)
  #:export (%known-syscalls))

(define %known-syscalls
~a))~%"
             (string-join (filled-lines names 4 76) "\n")))))
