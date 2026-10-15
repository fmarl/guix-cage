;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage packages guile-xyz)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages linux)
  #:use-module (guix build-system guile)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:prefix license:))

(define-public guile-landlock
  (let ((commit "9c11f1be2ab61df95f3ab932c66039067fa5e5d1")
        (revision "1"))
    (package
      (name "guile-landlock")
      (version (git-version "0.1.0" revision commit))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/fmarl/guile-landlock")
               (commit commit)))
         (file-name (git-file-name name version))
         (sha256
          (base32 "1w9fjv6xbgq4jxx8zwav737w8lmfli70vy6l5afvyc9pf7rsppds"))))
      (build-system guile-build-system)
      (arguments
       (list
        #:source-directory "src"))
      (native-inputs (list guile-3.0))
      (home-page "https://github.com/fmarl/guile-landlock")
      (synopsis "Guile bindings for the Landlock sandboxing API")
      (description
       "Guile-Landlock restricts filesystem, network and IPC access of Guile
programs and the programs they execute using Linux's Landlock.")
      (license license:gpl3+))))

(define-public guile-seccomp
  (let ((commit "82bc5b711cc41a2375e963b97f457e83db2d468d")
        (revision "0"))
    (package
      (name "guile-seccomp")
      (version (git-version "0.1.0" revision commit))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/fmarl/guile-seccomp")
               (commit commit)))
         (file-name (git-file-name name version))
         (sha256
          (base32 "1hf5da1jmaa4y3pixw5j1l7985xizl9f747waiw0cmw6h4pgpcjp"))))
      (build-system guile-build-system)
      (arguments
       (list
        #:source-directory "src"
        #:phases
        #~(modify-phases %standard-phases
            (add-after 'unpack 'patch-libseccomp
              (lambda* (#:key inputs #:allow-other-keys)
                (substitute* "src/seccomp.scm"
                  (("\\(define %libseccomp \"libseccomp\"\\)")
                   (format #f "(define %libseccomp ~s)"
                           (search-input-file inputs "lib/libseccomp.so")))))))))
      (native-inputs (list guile-3.0))
      (inputs (list libseccomp))
      (home-page "https://github.com/fmarl/guile-seccomp")
      (synopsis "Guile bindings for seccomp filters through libseccomp")
      (description
       "Guile-Seccomp restricts the system calls of Guile programs and the
programs they execute using Linux's seccomp filters.")
      (license license:gpl3+))))
