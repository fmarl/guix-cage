;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked platform)
  #:use-module (guix-cage build locked errors)
  #:export (%supported-systems
            %landlock-abi
            %host-network-landlock-abi
            check-platform!))

(define %supported-systems
  '("x86_64-linux" "aarch64-linux"))

(define %landlock-abi 6)
(define %host-network-landlock-abi 10)

(define* (check-platform! #:optional (machine (utsname:machine (uname))))
  (let ((system (string-append machine "-linux")))
    (unless (member system %supported-systems)
      (raise-locked-error "~a is not supported, only ~a" system
                          (string-join %supported-systems ", ")))))
