;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked xdg)
  #:use-module (guix-cage build locked errors)
  #:export (getenv*
            home-path
            config-path
            cache-path
            state-path
            runtime-path))

(define (getenv* name)
  (or (getenv name)
      (raise-locked-error "~a is not set" name)))

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
