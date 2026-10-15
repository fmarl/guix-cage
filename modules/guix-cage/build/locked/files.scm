;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked files)
  #:autoload (landlock) (landlock-path)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked grants)
  #:use-module (srfi srfi-26)
  #:export (getenv*
            file-type
            home-path
            config-path
            cache-path
            state-path
            runtime-path
            make-instance-directory
            read-only-rule
            read-write-rule
            share-socket!))

(define %read '(read-file read-dir))

(define %write
  '(write-file truncate make-reg make-dir make-sym make-sock make-fifo
    remove-file remove-dir refer))

(define (getenv* name)
  (or (getenv name)
      (raise-locked-error "~a is not set" name)))

(define (file-type file)
  (and=> (false-if-exception (stat file)) stat:type))

(define (process-alive? pid)
  (catch 'system-error
    (lambda ()
      (kill pid 0)
      #t)
    (lambda args
      (not (= ESRCH (system-error-errno args))))))

(define (home-path name)
  (string-append (getenv* "HOME") "/" name))

(define (xdg-path variable default name)
  (string-append (or (getenv variable) (home-path default)) "/" name))

(define (config-path name)
  (xdg-path "XDG_CONFIG_HOME" ".config" name))

(define (cache-path name)
  (xdg-path "XDG_CACHE_HOME" ".cache" name))

(define (state-path name)
  (xdg-path "XDG_STATE_HOME" ".local/state" name))

(define (runtime-path name)
  (string-append (getenv* "XDG_RUNTIME_DIR") "/" name))

(define (locked-runtime-path name)
  (runtime-path (string-append "locked/" name)))

(define (stale-entry? entry)
  (let ((pid (string->number entry)))
    (and pid
         (or (= pid (getpid))
             (not (process-alive? pid))))))

(define (delete-quietly file)
  (with-error-to-port (%make-void-port "w")
    (lambda ()
      (false-if-exception (delete-file-recursively file)))))

(define (remove-stale-entries directory)
  (for-each (lambda (entry)
              (delete-quietly (string-append directory "/" entry)))
            (scandir directory stale-entry?)))

(define (make-instance-directory name)
  (let ((parent (locked-runtime-path name)))
    (mkdir-p parent)
    (remove-stale-entries parent)
    (let ((directory (string-append parent "/" (number->string (getpid)))))
      (mkdir directory #o700)
      directory)))

(define (read-only-rule file)
  (landlock-path file %read #:optional? #t))

(define* (read-write-rule file #:key create?)
  (when create?
    (mkdir-p file))
  (landlock-path file (append %read %write) #:optional? #t))

(define (share-socket! socket variables)
  (if (file-exists? socket)
      (grant (list (landlock-path socket '(resolve-unix)))
             (variables socket))
      %no-grant))
