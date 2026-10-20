;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked dbus)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked instances)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked spawn)
  #:use-module (guix-cage build locked xdg)
  #:use-module (guix-cage build locked grants)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (dbus))

;; Through them, programs could run others outside the sandbox or read
;; secrets
(define %escaping-names
  '("org.freedesktop.systemd1" "org.freedesktop.Flatpak"
    "org.freedesktop.portal.Flatpak" "ca.desrt.dconf"
    "org.freedesktop.secrets"))

(define %option-regexp
  (make-regexp "^--(see|talk|own|call|broadcast)=([^=]+)(=.+)?$"))

(define (option-name option)
  (and (string? option)
       (and=> (regexp-exec %option-regexp option)
              (cut match:substring <> 2))))

(define (name-covers? name other)
  "Whether NAME, or the names it matches if it ends in .*, covers OTHER or
names below it."
  (define (below? name parent)
    (or (string=? name parent)
        (string-prefix? (string-append parent ".") name)))

  (cond ((string=? name "*") #t)
        ((string-suffix? ".*" name)
         (let ((prefix (string-drop-right name 2)))
           (or (below? other prefix) (below? prefix other))))
        (else (below? name other))))

(define (valid-option? option)
  (match (option-name option)
    (#f #f)
    (name (not (any (cut name-covers? name <>) %escaping-names)))))

(define (start-proxy! proxy address bus policy)
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
       read-end))))

(define (dbus proxy . policy)
  "Return a rule granting a session bus that PROXY, xdg-dbus-proxy, filters
by POLICY, its options such as --talk=org.freedesktop.Notifications."
  (apply check-parameters 'dbus
         (lambda policy (every valid-option? policy))
         policy)
  (lambda (command-line)
    (let* ((address (or (getenv "DBUS_SESSION_BUS_ADDRESS")
                        (string-append "unix:path=" (runtime-path "bus"))))
           (directory (make-instance-directory "dbus"))
           (bus (string-append directory "/bus"))
           (running (start-proxy! proxy address bus policy)))
      (grant #:files (list (file-access directory '(connect)))
             #:variables `(("DBUS_SESSION_BUS_ADDRESS"
                            . ,(string-append "unix:path=" bus)))
             #:fds (list (inherit-across-exec! running))))))
