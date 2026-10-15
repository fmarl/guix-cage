;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked virtualization)
  #:autoload (landlock) (landlock-path)
  #:use-module (ice-9 match)
  #:use-module (ice-9 receive)
  #:use-module (guix-cage build locked files)
  #:use-module (guix-cage build locked kinds)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (rule-kinds))

(define %server-options
  '("server" "server=on" "server=yes" "server=true"))

(define %read-only-options
  '("readonly" "readonly=on" "readonly=yes" "read-only=on" "read-only=yes"))

(define (parse-argument argument)
  (let ((options (string-split argument #\,)))
    (values options
            (any (cut member <> %server-options) options)
            (any (cut member <> %read-only-options) options))))

(define (option-file option)
  (let* ((value (match (string-index option #\=)
                  (#f option)
                  (index (substring option (1+ index)))))
         (file (if (string-prefix? "unix:" value)
                   (string-drop value (string-length "unix:"))
                   value)))
    (and (string-prefix? "/" file)
         (not (string-prefix? "/gnu/store/" file))
         (not (string-any char-whitespace? file))
         file)))

(define (file-rule file server? read-only?)
  "Return the rule for FILE.  Remove a stale socket that QEMU listens on."
  (match (file-type file)
    ('regular
     (landlock-path file (if read-only?
                             '(read-file)
                             '(read-file write-file truncate))))
    ((or 'char-special 'block-special)
     (landlock-path file (if read-only?
                             '(read-file ioctl-dev)
                             '(read-file write-file ioctl-dev))))
    ('fifo (landlock-path file '(read-file write-file)))
    ('directory (read-only-rule file))
    ('socket
     (if server?
         (begin
           (delete-file file)
           (landlock-path (dirname file) '(make-sock) #:optional? #t))
         (landlock-path file '(resolve-unix))))
    (#f
     (and server?
          (landlock-path (dirname file) '(make-sock) #:optional? #t)))
    (_ #f)))

(define (usb-rules arguments)
  (if (any (cut string-contains <> "usb=on") arguments)
      (list (landlock-path "/dev/bus/usb"
                           '(read-file write-file read-dir ioctl-dev)
                           #:optional? #t))
      '()))

(define (qemu-rules arguments)
  (append (append-map (lambda (argument)
                        (receive (options server? read-only?)
                            (parse-argument argument)
                          (filter-map (cut file-rule <> server? read-only?)
                                      (filter-map option-file options))))
                      arguments)
          (usb-rules arguments)))

(define (waypipe-client-rules arguments)
  (match (and (member "client" arguments)
              (or (member "--socket" arguments) (member "-s" arguments)))
    ((_ socket . _)
     (list (landlock-path (dirname socket) '(make-sock) #:optional? #t)))
    (_ '())))

(define (rule-kinds)
  (list (rule-kind 'qemu qemu-rules)
        (rule-kind 'waypipe-client waypipe-client-rules)))
