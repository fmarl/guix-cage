;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked gnupg)
  #:use-module (guix-cage build locked file-names)
  #:use-module (guix-cage build locked instances)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked xdg)
  #:use-module (srfi srfi-26)
  #:export (%gnupg))

(define %public-files
  '("pubring.kbx" "pubring.gpg" "trustdb.gpg" "gpg.conf" "common.conf"))

(define (gnupg-home)
  (or (getenv "GNUPGHOME") (home-path ".gnupg")))

(define (agent-socket home)
  ;; GnuPG names the socket directory of other homes after their hash, and
  ;; only uses the home itself without /run/user
  (if (equal? (normalize-file-name home)
              (normalize-file-name (home-path ".gnupg")))
      (runtime-path "gnupg/S.gpg-agent.extra")
      (string-append home "/S.gpg-agent.extra")))

(define (write-socket-redirection file socket)
  (call-with-output-file file
    (cut format <> "%Assuan%~%socket=~a~%" socket)))

(define (%gnupg command-line)
  "Grant a private GnuPG home with the public keyring and the restricted
socket of gpg-agent, which can't export secret keys."
  (let* ((home (gnupg-home))
         (directory (make-instance-directory "gnupg"))
         (public (filter file-exists?
                         (map (cut string-append home "/" <>) %public-files)))
         (socket (agent-socket home)))
    (for-each (lambda (file)
                (symlink file (string-append directory "/" (basename file))))
              public)
    ;; gpg can't create a socket directory below /run/user for this home,
    ;; so it looks for the socket in the home itself
    (when (file-exists? socket)
      (write-socket-redirection (string-append directory "/S.gpg-agent")
                                socket))
    (grant #:files (cons* (read-write-access directory)
                          (file-access socket '(connect))
                          (map read-access public))
           #:variables `(("GNUPGHOME" . ,directory)
                         ,@(inherited-variables "GPG_TTY")))))
