;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked-package)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (ice-9 string-fun)
  #:use-module (ice-9 textual-ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (install-locked-package))

;; Their files are only worth keeping if they start the commands
(define %entry-point-directories
  '("/applications" "/dbus-1/services" "/systemd/user"))

;; References end at characters that file names rarely have.  A reference cut
;; short counts as one to a program, so its file is left out.
(define %file-name-end
  (char-set-complement
   (char-set-union (char-set-intersection char-set:letter+digit
                                          char-set:ascii)
                   (string->char-set "-+._/~"))))

(define (file-below? directory file)
  (or (string=? directory file)
      (string-prefix? (string-append directory "/") file)))

(define (file-bytes file)
  "Return the bytes of FILE as Latin-1 characters."
  (call-with-input-file file get-string-all #:encoding "ISO-8859-1"))

(define (install-locked-package original output commands)
  "Install COMMANDS, an alist of names and programs, in OUTPUT in place of
the programs of ORIGINAL.  Keep the data of ORIGINAL, except files that would
start its programs other than through COMMANDS."
  (define share (string-append original "/share"))
  (define original-bin (string-append original "/bin/"))
  (define bin (string-append output "/bin/"))

  (define (references file)
    "Return the file names in ORIGINAL that FILE refers to."
    (define bytes
      (if (eq? 'regular (and=> (stat file #f) stat:type))
          (file-bytes file)
          ""))

    (let loop ((start 0))
      (match (string-contains bytes original start)
        (#f '())
        (index
         (let ((end (or (string-index bytes %file-name-end
                                      (+ index (string-length original)))
                        (string-length bytes))))
           (cons (substring bytes index end) (loop end)))))))

  (define (data? reference)
    (file-below? share reference))

  (define (command? reference)
    (and (string-prefix? original-bin reference)
         (assoc (string-drop reference (string-length original-bin))
                commands)))

  (define (installation file)
    "Return whether to 'link FILE, 'rewrite its references to the commands,
or leave it out."
    (let ((references (references file)))
      (cond ((not (every (lambda (reference)
                           (or (data? reference) (command? reference)))
                         references))
             #f)
            ((any command? references) 'rewrite)
            ((any (lambda (directory)
                    (file-below? (string-append share directory) file))
                  %entry-point-directories)
             #f)
            (else 'link))))

  (define installations
    (if (file-exists? share)
        (map (lambda (file)
               (cons file (installation file)))
             (find-files share))
        '()))

  (define unlinked
    (filter-map (match-lambda
                  ((file . 'link) #f)
                  ((file . _) file))
                installations))

  (define (rewrite source target)
    (call-with-output-file target
      (cut put-string <>
           (string-replace-substring (file-bytes source) original-bin bin))
      #:encoding "ISO-8859-1")
    (chmod target (stat:perms (stat source))))

  (define (install source target)
    "Link SOURCE as TARGET, or else only what it may keep of SOURCE."
    (cond ((not (any (cut file-below? source <>) unlinked))
           (symlink source target))
          ((eq? 'directory (stat:type (lstat source)))
           (mkdir-p target)
           (for-each (lambda (entry)
                       (install (string-append source "/" entry)
                                (string-append target "/" entry)))
                     (scandir source (negate (cut member <> '("." ".."))))))
          ((eq? 'rewrite (assoc-ref installations source))
           (rewrite source target))))

  (mkdir-p bin)
  (for-each (match-lambda
              ((name . program)
               (symlink program (string-append bin name))))
            commands)
  (when (file-exists? share)
    (install share (string-append output "/share"))))
