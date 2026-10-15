;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked environment)
  #:use-module (srfi srfi-1)
  #:export (%default-preserved-environment-variables
            preserved-variable?
            preserve-environment!))

(define %default-preserved-environment-variables
  '("HOME" "USER" "LOGNAME" "SHELL" "PATH" "LANG" "LANGUAGE" "LC_*"
    "TZ" "TZDIR" "TERM" "COLORTERM" "NO_COLOR" "TERMINFO" "TERMINFO_DIRS"
    "TMPDIR" "XDG_*" "WAYLAND_DISPLAY" "GUIX_*"
    "SSL_CERT_DIR" "SSL_CERT_FILE" "CURL_CA_BUNDLE"
    "GTK_*" "GDK_*" "GIO_*" "GI_*" "GSETTINGS_*" "GST_*" "QT_*"
    "XCURSOR_*" "XKB_*" "FONTCONFIG_*" "MESA_*" "LIBGL_*" "__EGL_*" "__GLX_*"
    "VK_*" "LIBVA_*" "VDPAU_*" "PIPEWIRE_*" "SPA_*"))

(define (preserved-variable? name preserved)
  (any (lambda (pattern)
         (if (string-suffix? "*" pattern)
             (string-prefix? (string-drop-right pattern 1) name)
             (string=? pattern name)))
       preserved))

(define (preserve-environment! preserved)
  (environ (filter (lambda (entry)
                     (preserved-variable? (car (string-split entry #\=))
                                          preserved))
                   (environ))))
