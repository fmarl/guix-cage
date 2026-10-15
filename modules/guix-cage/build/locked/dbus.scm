;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked dbus)
  #:autoload (landlock) (landlock-path)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked files)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked grants)
  #:export (share-dbus!))

(define (share-dbus! proxy policy)
  (let* ((address (or (getenv "DBUS_SESSION_BUS_ADDRESS")
                      (string-append "unix:path=" (runtime-path "bus"))))
         (directory (make-instance-directory "dbus"))
         (bus (string-append directory "/bus")))
    (match (pipe)
      ((read-end . write-end)
       (let ((fd (port->fdes write-end)))
         (apply spawn-detached fd proxy
                (string-append "--fd=" (number->string fd))
                address bus "--filter" policy)
         (close-port write-end)
         ;; xdg-dbus-proxy writes a byte once it listens
         (when (eof-object? (read-char read-end))
           (raise-locked-error "cannot start xdg-dbus-proxy"))
         (grant (list (landlock-path directory '(resolve-unix)))
                `(("DBUS_SESSION_BUS_ADDRESS"
                   . ,(string-append "unix:path=" bus)))
                (list (inherit-across-exec! read-end))))))))
