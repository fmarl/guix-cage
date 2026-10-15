;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked-package)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 textual-ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (install-locked-package))

(define %entry-point-directories
  '("/applications" "/dbus-1/services" "/systemd/user"))

(define (install-locked-package original output commands)
  "Install COMMANDS, an alist of names and programs, in OUTPUT in place of
the programs of ORIGINAL."
  (define share (string-append original "/share"))
  (define original-bin (string-append original "/bin/"))
  (define bin (string-append output "/bin/"))

  (define referenced-program
    (make-regexp (string-append (regexp-quote original-bin)
                                "([^[:space:];\"']+)")))

  (define (entry-point? file)
    "Whether FILE only starts COMMANDS."
    (let ((referenced (map (cut match:substring <> 1)
                           (list-matches referenced-program
                                         (call-with-input-file file
                                           get-string-all)))))
      (and (pair? referenced)
           (every (cut assoc <> commands) referenced))))

  (define (contains-entry-points? directory)
    (any (cut string-prefix? (string-append directory "/") <>)
         %entry-point-directories))

  (define (link-data directory)
    (let ((target (string-append output "/share" directory)))
      (mkdir-p target)
      (for-each (lambda (entry)
                  (let ((relative (string-append directory "/" entry)))
                    (cond ((member relative %entry-point-directories) #t)
                          ((contains-entry-points? relative)
                           (link-data relative))
                          (else
                           (symlink (string-append share relative)
                                    (string-append target "/" entry))))))
                (scandir (string-append share directory)
                         (negate (cut member <> '("." "..")))))))

  (define (install-entry-points directory)
    (let ((source (string-append share directory)))
      (when (file-exists? source)
        (for-each (lambda (file)
                    (let ((target (string-append
                                   output "/share" directory
                                   (string-drop file (string-length source)))))
                      (mkdir-p (dirname target))
                      (copy-file file target)
                      (substitute* target
                        (((regexp-quote original-bin)) bin))))
                  (filter entry-point? (find-files source))))))

  (mkdir-p bin)
  (for-each (lambda (command)
              (symlink (cdr command) (string-append bin (car command))))
            commands)
  (when (file-exists? share)
    (link-data "")
    (for-each install-entry-points %entry-point-directories)))
