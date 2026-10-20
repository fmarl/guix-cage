;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage locked)
  #:use-module ((gnu packages containers) #:select (tini))
  #:use-module (gnu packages glib)
  #:use-module (guix build-system trivial)
  #:use-module (guix diagnostics)
  #:use-module (guix gexp)
  #:use-module (guix i18n)
  #:use-module (guix modules)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:use-module (ice-9 receive)
  #:use-module (guix-cage build locked environment)
  #:use-module ((guix-cage build locked errors) #:select (locked-error?))
  #:use-module ((guix-cage build locked process)
                #:select (%default-resource-limits))
  #:use-module ((guix-cage build locked syscalls)
                #:select (%syscall-groups))
  #:use-module (guix-cage packages guile-xyz)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:re-export (%default-preserved-environment-variables
               %default-resource-limits)
  #:export (define-locked-rules
            when-network-arguments
            dbus

            locked-command
            locked-command?
            locked-command-name
            locked-command-program
            locked-command-rules
            locked-command-environment
            locked-command-preserved-environment-variables
            locked-command-executes?
            locked-command-deny-write-execute?
            locked-command-resource-limits
            locked-command-syscall-allowances
            locked-command-program-file

            make-locked-package))

;;; Rules are G-expressions of the rules of the build side, see (guix-cage
;;; build locked grants).  Their constructors check the parameters there.

(define (build-module? name)
  (match name
    (('guix-cage 'build _ ...) #t)
    (_ (guix-module-name? name))))

(define (build-procedure module name)
  (or (and=> (false-if-exception (resolve-interface module))
             (lambda (interface)
               (and=> (module-variable interface name) variable-ref)))
      (raise-exception
       (formatted-message (G_ "~a defines no rule ~a") module name))))

(define (check-build-rule rule parameters)
  "Apply RULE, a constructor of the build side, to PARAMETERS to check
them."
  (with-exception-handler
      (lambda (exception)
        (raise-exception
         (if (locked-error? exception)
             (formatted-message (G_ "~a") (exception-message exception))
             exception)))
    (lambda ()
      (apply rule parameters))
    #:unwind? #t))

(define (parameter-gexp parameter)
  "Return the code of PARAMETER: rules stay code, other values are data."
  (if (gexp? parameter)
      parameter
      #~'#$parameter))

(define* (build-rule module name #:optional parameters)
  "Return the rule NAME of the build module MODULE, or, given PARAMETERS,
the rule that the constructor NAME returns for them."
  (let ((procedure (build-procedure module name)))
    (when parameters
      (check-build-rule procedure parameters))
    (with-imported-modules (source-module-closure (list module)
                                                  #:select? build-module?)
      (if parameters
          #~((@ #$module #$name) #$@(map parameter-gexp parameters))
          #~(@ #$module #$name)))))

(define-syntax define-locked-rule
  (syntax-rules ()
    ((_ module (name parameter ...))
     (begin
       (define (name parameter ...)
         (build-rule 'module 'name (list parameter ...)))
       (export name)))
    ((_ module (name parameter ... . rest))
     (begin
       (define (name parameter ... . rest)
         (build-rule 'module 'name (cons* parameter ... rest)))
       (export name)))
    ((_ module name)
     (begin
       (define name
         (build-rule 'module 'name))
       (export name)))))

(define-syntax-rule (define-locked-rules module form ...)
  "Define and export a rule for each rule of the build MODULE, such as %dns,
and each constructor of rules, such as (xdg-config name)."
  (begin
    (define-locked-rule module form) ...))

(define-locked-rules (guix-cage build locked rules)
  %graphics
  %fonts
  %shm
  %dns
  %pipewire
  %runtime-directory
  %temporary-directory
  %argument-files
  %mail-directory
  (xdg-config name)
  (xdg-state name)
  (xdg-cache name)
  (xdg-user-directory name default)
  (home-file name)
  (read-only file)
  (read-write file)
  (devices . files)
  (tcp-ports . ports))

(define-locked-rules (guix-cage build locked gnupg)
  %gnupg)

(define-locked-rules (guix-cage build locked wayland)
  %wayland
  %full-wayland)

(define (validate-rules rules)
  (for-each (lambda (rule)
              (unless (gexp? rule)
                (raise-exception
                 (formatted-message (G_ "rule is not a G-expression: ~s")
                                    rule))))
            rules)
  rules)

(define (when-network-arguments . arguments)
  "Return a rule granting what the rules among ARGUMENTS grant if the command
line names URLs, or playlists with the #:playlists extensions."
  (receive (extensions rules)
      (match arguments
        ((#:playlists extensions . rules) (values extensions rules))
        (rules (values '() rules)))
    (build-rule '(guix-cage build locked rules) 'when-network-arguments
                (cons extensions (validate-rules rules)))))

(define (dbus . policy)
  "Return a rule granting a session bus that xdg-dbus-proxy filters by
POLICY, its options such as --talk=org.freedesktop.Notifications."
  (build-rule '(guix-cage build locked dbus) 'dbus
              (cons (file-append xdg-dbus-proxy "/bin/xdg-dbus-proxy")
                    policy)))

(define %resources
  '(as core cpu data fsize memlock msgqueue nice nofile nproc rss rtprio
    rttime sigpending stack))

(define (resource-limit? limit)
  (match limit
    ((resource . value)
     (and (memq resource %resources)
          (or (not value)
              (and (exact-integer? value) (>= value 0)))))
    (_ #f)))

(define (validate-resource-limits limits)
  (let ((invalid (remove resource-limit? limits)))
    (unless (null? invalid)
      (raise-exception
       (formatted-message (G_ "invalid resource limits: ~s") invalid)))
    limits))

(define (validate-syscall-allowances allowances)
  (let ((unknown (remove (cut assq <> %syscall-groups) allowances)))
    (unless (null? unknown)
      (raise-exception
       (formatted-message (G_ "unknown system call groups: ~s") unknown)))
    allowances))

(define-record-type* <locked-command>
  locked-command make-locked-command
  locked-command?
  (name                 locked-command-name)    ;string
  (program              locked-command-program) ;file-like
  (rules                locked-command-rules    ;list of G-expressions
                        (default '())
                        (sanitize validate-rules))
  (environment          locked-command-environment ;alist
                        (default '()))
  (preserved-environment-variables
   locked-command-preserved-environment-variables
   (default %default-preserved-environment-variables))
  ;; Without it, the program can't start others, but compromised code still
  ;; can through the dynamic loader or a memfd
  (executes?            locked-command-executes?
                        (default #t))
  (deny-write-execute?  locked-command-deny-write-execute?
                        (default #f))
  (resource-limits      locked-command-resource-limits ;alist
                        (default %default-resource-limits)
                        (sanitize validate-resource-limits))
  (syscall-allowances   locked-command-syscall-allowances ;list of groups
                        (default '())
                        (sanitize validate-syscall-allowances)))

(define (locked-command-program-file command)
  (match-record command <locked-command>
    (name program rules environment preserved-environment-variables
          executes? deny-write-execute? resource-limits syscall-allowances)
    (program-file
     name
     (with-extensions (list guile-landlock guile-seccomp)
       (with-imported-modules (source-module-closure
                               '((guix-cage build locked))
                               #:select? build-module?)
         #~(begin
             (use-modules (guix-cage build locked))
             (run-locked #$program (list #$@rules)
                         #:name #$name
                         #:init #$(file-append tini "/bin/tini")
                         #:environment '#$environment
                         #:preserved-environment-variables
                         '#$preserved-environment-variables
                         #:executes? #$executes?
                         #:deny-write-execute? #$deny-write-execute?
                         #:resource-limits '#$resource-limits
                         #:syscall-allowances '#$syscall-allowances)))))))

(define* (make-locked-package original commands
                              #:key (name (string-append (package-name original)
                                                         "-locked"))
                              (description (package-description original)))
  "Return a package providing COMMANDS in place of the programs of
ORIGINAL."
  (package
    (name name)
    (version (package-version original))
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:builder
      (with-imported-modules (source-module-closure
                              '((guix-cage build locked-package))
                              #:select? build-module?)
        #~(begin
            (use-modules (guix-cage build locked-package))
            (install-locked-package
             #$original #$output
             (map cons
                  '#$(map locked-command-name commands)
                  (list #$@(map locked-command-program-file commands))))))))
    (inputs (list original))
    (supported-systems (filter (cut string-suffix? "-linux" <>)
                               (package-supported-systems original)))
    (home-page (package-home-page original))
    (synopsis (package-synopsis original))
    (description
     (string-append description
                    "\n\nThis variant runs the program confined by Landlock \
and seccomp."))
    (license (package-license original))))
