;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked grants)
  #:use-module (srfi srfi-9)
  #:export (grant
            grant-rules
            grant-variables
            grant-fds
            %no-grant))

(define-record-type <grant>
  (make-grant rules variables fds)
  grant?
  (rules     grant-rules)
  (variables grant-variables)                   ;alist
  (fds       grant-fds))                        ;kept open across exec

(define* (grant rules variables #:optional (fds '()))
  (make-grant rules variables fds))

(define %no-grant (grant '() '()))
