;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked grants)
  #:use-module ((guix build utils) #:select (mkdir-p))
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked file-names)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:export (file-access
            file-access?
            file-access-file
            file-access-permissions
            file-access-descriptor
            file-access-private?

            port-access
            port-access?
            port-access-port
            port-access-protocol

            grant
            grant?
            grant-files
            grant-ports
            grant-variables
            grant-fds
            grant-append
            %no-grant
            inherited-variables

            read-access
            read-write-access
            regular-file-access
            socket-grant))

;;; A rule is a procedure that takes the command line, a list of the name of
;;; the program and its arguments, and returns a <grant>: the files and ports
;;; the program may access, the variables it gets and the descriptors it
;;; keeps.

;; What the program may do with a file, and beneath it for a directory
(define %permissions
  '(list                                        ;list directories
    read                                        ;read and list
    write                                       ;change, create and remove
    execute
    ioctl                                       ;use devices
    connect                                     ;connect to Unix sockets
    make-socket))                               ;create Unix sockets

(define-record-type <file-access>
  (make-file-access file permissions descriptor private?)
  file-access?
  (file        file-access-file)
  (permissions file-access-permissions)
  (descriptor  file-access-descriptor)          ;#f or an O_PATH descriptor
  (private?    file-access-private?))           ;new and empty

(define* (file-access file permissions #:key descriptor private?)
  "Grant PERMISSIONS on FILE.  DESCRIPTOR, an O_PATH descriptor of FILE,
keeps Landlock to that file if it could be swapped.  A PRIVATE? directory is
new and empty."
  (unless (canonical-file-name? file)
    (raise-locked-error "file name is not absolute and canonical: ~a" file))
  (match (lset-difference eq? permissions %permissions)
    (() (make-file-access file permissions descriptor private?))
    (unknown (raise-locked-error "unknown permissions: ~s" unknown))))

(define-record-type <port-access>
  (make-port-access port protocol)
  port-access?
  (port     port-access-port)
  (protocol port-access-protocol))

(define (port-access port protocol)
  (unless (memq protocol '(tcp udp))
    (raise-locked-error "unknown protocol: ~s" protocol))
  (make-port-access port protocol))

(define-record-type <grant>
  (make-grant files ports variables fds)
  grant?
  (files     grant-files)                       ;list of <file-access>
  (ports     grant-ports)                       ;list of <port-access>
  (variables grant-variables)                   ;alist
  (fds       grant-fds))                        ;kept open across exec

(define* (grant #:key (files '()) (ports '()) (variables '()) (fds '()))
  (make-grant files ports variables fds))

(define %no-grant (grant))

(define (grant-append . grants)
  (make-grant (append-map grant-files grants)
              (append-map grant-ports grants)
              (append-map grant-variables grants)
              (append-map grant-fds grants)))

(define (inherited-variables . names)
  "Return the variables among NAMES that are set, with their values."
  (filter-map (lambda (name)
                (and=> (getenv name) (cut cons name <>)))
              names))

(define (read-access file)
  (file-access file '(read)))

(define* (read-write-access file #:key create?)
  (when create?
    (mkdir-p file))
  (file-access file '(read write)))

(define (regular-file-access file permissions)
  "Return an access with PERMISSIONS to FILE, pinned by a descriptor, if it
is a regular file and not a symbolic link, or #f."
  (let ((fd (false-if-exception
             (open-fdes file (logior O_PATH O_NOFOLLOW O_CLOEXEC)))))
    (cond ((not fd) #f)
          ((eq? 'regular (stat:type (stat fd)))
           (file-access (absolute-file-name file) permissions
                        #:descriptor fd))
          (else
           (close-fdes fd)
           #f))))

(define (socket-grant socket variables)
  "Grant connecting to SOCKET, if it exists, and the VARIABLES it returns."
  (if (file-exists? socket)
      (grant #:files (list (file-access socket '(connect)))
             #:variables (variables socket))
      %no-grant))
