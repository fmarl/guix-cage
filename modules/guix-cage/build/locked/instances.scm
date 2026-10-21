;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked instances)
  #:autoload (landlock) (landlock-path landlock-restrict!)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked spawn)
  #:use-module (guix-cage build locked xdg)
  #:use-module (srfi srfi-26)
  #:export (make-instance-directory))

;;; Directories of the host that belong to a running sandbox.

(define (process-alive? pid)
  (catch 'system-error
    (lambda ()
      (kill pid 0)
      #t)
    (lambda args
      (not (= ESRCH (system-error-errno args))))))

(define (stale-entry? entry)
  (let ((pid (string->number entry)))
    (and pid
         (or (= pid (getpid))
             (not (process-alive? pid))))))

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
    ;; Programs of exited instances may still run and change their entries
    (match (scandir parent stale-entry?)
      (() #t)
      (stale (delete-beneath parent
                             (map (cut string-append parent "/" <>) stale))))
    (let ((directory (string-append parent "/" (number->string (getpid)))))
      (mkdir directory #o700)
      directory)))
