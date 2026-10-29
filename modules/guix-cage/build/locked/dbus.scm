;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked dbus)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (guix-cage build locked confinement)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked instances)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked rules)
  #:use-module (guix-cage build locked sandbox)
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
    "org.freedesktop.secrets" "org.freedesktop.impl.portal"))

(define %trusting-names
  '("org.freedesktop.portal.Desktop"))

(define %option-regexp
  (make-regexp "^--(see|talk|own|call|broadcast)=([^=]+)(=(.+))?$"))

(define (parse-option option)
  (and (string? option)
       (and=> (regexp-exec %option-regexp option)
              (lambda (match)
                (list (string->symbol (match:substring match 1))
                      (match:substring match 2)
                      (match:substring match 4))))))

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

(define (covers-any? name names)
  (any (cut name-covers? name <>) names))

(define (wildcard? name)
  (or (string=? name "*") (string-suffix? ".*" name)))

(define (valid-option? option)
  (match (parse-option option)
    (#f #f)
    ((kind name rule)
     (not (or (and (memq kind '(talk call)) (wildcard? name))
              (covers-any? name %escaping-names)
              (and (covers-any? name %trusting-names)
                   (or (memq kind '(talk own))
                       (and (eq? kind 'call)
                            (or (not rule) (string-prefix? "*" rule))))))))))

(define %unix-path-regexp
  (make-regexp "^unix:([^;]*,)?path=([^,;]+)"))

(define (bus-socket address)
  (match (regexp-exec %unix-path-regexp address)
    (#f (raise-locked-error "cannot proxy the D-Bus address ~a" address))
    (found (match:substring found 2))))

(define (proxy-sandbox proxy address bus fd policy)
  (container-sandbox
   (grant-append (base-grant (list proxy) #f)
                 (grant #:files (list (file-access (bus-socket address)
                                                   '(connect))
                                      (file-access (dirname bus)
                                                   '(make-socket)))
                        #:fds (list fd)))
   `(,proxy ,(string-append "--fd=" (number->string fd))
            ,address ,bus "--filter" ,@policy)
   #:new-session? #t))

(define (start-proxy! proxy address bus policy)
  (match (pipe)
    ((read-end . write-end)
     (let ((sandbox (proxy-sandbox proxy address bus (port->fdes write-end)
                                   policy)))
       (call-detached
        (lambda ()
          (close-port read-end)
          (retain-instance-only! (dirname bus))
          (write (status->exit-code (call-in-sandbox sandbox)) write-end)
          (force-output write-end)))
       (close-port write-end)
       ;; xdg-dbus-proxy writes a byte once it listens
       (match (read-char read-end)
         (#\x read-end)
         ((? eof-object?)
          (raise-locked-error "cannot start xdg-dbus-proxy"))
         (digit
          (unread-char digit read-end)
          (raise-locked-error "xdg-dbus-proxy exited with code ~a"
                              (read read-end))))))))

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
