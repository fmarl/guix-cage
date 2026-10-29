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
  (package
    (name "guile-landlock")
    (version "0.1.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/fmarl/guile-landlock")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "1489ik8c5y9w1gb412kd1ncn32fagb1f1rgzgmnz4fv6jlmj63qd"))))
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
    (license license:gpl3+)))

(define-public guile-seccomp
  (package
    (name "guile-seccomp")
    (version "0.1.1")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/fmarl/guile-seccomp")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "1v540bc7x0d022n5y77bqx6xb2xqlpv167mjlcbiaw45rh7mmzrc"))))
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
    (license license:gpl3+)))
