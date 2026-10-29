;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked instances)
  #:autoload (landlock) (landlock-path landlock-restrict!)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked spawn)
  #:use-module (guix-cage build locked xdg)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (make-instance-directory
            retain-instance-only!))

;;; Directories of the host that belong to a running sandbox.

(define %held-locks '())

(define (lock-file instance)
  (string-append instance ".lock"))

(define (open-lock file flags)
  (open file (logior flags O_NOFOLLOW O_CLOEXEC) #o600))

(define (call-with-lock file thunk)
  (let ((port (open-lock file (logior O_RDWR O_CREAT))))
    (dynamic-wind
      (lambda () (flock port LOCK_EX))
      thunk
      (lambda () (close-port port)))))

(define (held? file)
  (catch 'system-error
    (lambda ()
      (let ((port (open-lock file (logior O_RDONLY O_NONBLOCK))))
        (dynamic-wind
          (const #t)
          (lambda () (flock port (logior LOCK_EX LOCK_NB)) #f)
          (lambda () (close-port port)))))
    (lambda args
      (= EWOULDBLOCK (system-error-errno args)))))

(define (instances parent)
  (delete-duplicates
   (filter-map (lambda (entry)
                 (match (if (string-suffix? ".lock" entry)
                            (string-drop-right entry (string-length ".lock"))
                            entry)
                   ((or "" "." "..") #f)
                   (instance (string-append parent "/" instance))))
               (or (scandir parent) '()))))

(define %removal '(read-dir remove-file remove-dir))

(define (delete-beneath directory files)
  "Delete FILES in a child process that can only remove beneath DIRECTORY,
even through symbolic links that appear meanwhile."
  (call-in-child
   (lambda ()
     (landlock-restrict! (list (landlock-path directory %removal))
                         #:fs %removal #:net '() #:flags '()
                         #:require 'fully-enforced)
     (with-error-to-port (%make-void-port "w")
       (lambda ()
         (for-each (lambda (file)
                     (false-if-exception (delete-file-recursively file)))
                   files))))))

(define (make-instance-directory name)
  (let ((parent (runtime-path (string-append "locked/" name))))
    (mkdir-p parent)
    (call-with-lock (string-append parent "/.lock")
      (lambda ()
        ;; Programs of exited instances may still run and change their
        ;; entries
        (match (remove (compose held? lock-file) (instances parent))
          (() #t)
          (stale (delete-beneath parent
                                 (append stale (map lock-file stale)))))
        (let* ((directory (mkdtemp (string-append parent "/XXXXXX")))
               (lock (open-lock (lock-file directory)
                                (logior O_RDWR O_CREAT O_EXCL))))
          (flock lock LOCK_EX)
          (set! %held-locks (alist-cons directory lock %held-locks))
          directory)))))

(define (retain-instance-only! directory)
  (for-each (match-lambda
              ((held . lock)
               (unless (string=? held directory)
                 (close-port lock))))
            %held-locks)
  (set! %held-locks (filter (compose (cut string=? directory <>) car)
                            %held-locks)))
