;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage locked)
  #:use-module (gnu packages glib)
  #:use-module (guix build-system trivial)
  #:use-module (guix diagnostics)
  #:use-module (guix gexp)
  #:use-module (guix i18n)
  #:use-module (guix modules)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (ice-9 match)
  #:use-module (ice-9 receive)
  #:use-module (guix-cage build locked environment)
  #:use-module ((guix-cage build locked kinds)
                #:select (module-rule-kind-names))
  #:use-module ((guix-cage build locked process)
                #:select (%default-resource-limits))
  #:use-module ((guix-cage build locked syscalls)
                #:select (%syscall-groups))
  #:use-module (guix-cage packages guile-xyz)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:re-export (%default-preserved-environment-variables
               %default-resource-limits)
  #:export (locked-rule?
            locked-rule-module
            locked-rule-kind
            locked-rule-parameters
            locked-rule->spec
            define-locked-rules
            when-network-arguments

            locked-command
            locked-command?
            locked-command-name
            locked-command-program
            locked-command-rules
            locked-command-wayland
            locked-command-pipewire?
            locked-command-dbus
            locked-command-runtime-directory?
            locked-command-temporary-directory?
            locked-command-environment
            locked-command-preserved-environment-variables
            locked-command-executes?
            locked-command-deny-write-execute?
            locked-command-resource-limits
            locked-command-syscall-allowances
            locked-command-program-file

            make-locked-package))

(define-record-type <locked-rule>
  (make-locked-rule module kind parameters)
  locked-rule?
  (module     locked-rule-module)
  (kind       locked-rule-kind)
  (parameters locked-rule-parameters))

(define (locked-rule->spec rule)
  (cons* (locked-rule-module rule)
         (locked-rule-kind rule)
         (map (lambda (parameter)
                (if (locked-rule? parameter)
                    (locked-rule->spec parameter)
                    parameter))
              (locked-rule-parameters rule))))

(define (locked-rule-modules rule)
  (cons (locked-rule-module rule)
        (append-map locked-rule-modules
                    (filter locked-rule? (locked-rule-parameters rule)))))

(define (validate-kinds module kinds)
  (let ((known (module-rule-kind-names module)))
    (for-each (lambda (kind)
                (unless (memq kind known)
                  (raise-exception
                   (formatted-message (G_ "~a defines no kind of rules ~a")
                                      module kind))))
              kinds)))

(define-syntax define-locked-rules
  (lambda (s)
    "Define and export a constructor of <locked-rule> for each form, such as
%dns or (xdg-config name)."
    (define (kind name)
      (datum->syntax name
                     (string->symbol
                      (string-trim (symbol->string (syntax->datum name))
                                   #\%))))

    (define (form-name form)
      (syntax-case form ()
        ((name . _) #'name)
        (name #'name)))

    ;; (guix packages) replaces define-public with one without rest arguments
    (define (definition module form)
      (syntax-case form ()
        ((name parameter ...)
         #`(define (name parameter ...)
             (make-locked-rule '#,module '#,(kind #'name)
                               (list parameter ...))))
        ((name parameter ... . rest)
         #`(define (name parameter ... . rest)
             (make-locked-rule '#,module '#,(kind #'name)
                               (cons* parameter ... rest))))
        (name
         #`(define name
             (make-locked-rule '#,module '#,(kind #'name) '())))))

    (syntax-case s ()
      ((_ module form ...)
       #`(begin
           (validate-kinds 'module
                           '#,(map kind (map form-name #'(form ...))))
           #,@(map (cut definition #'module <>) #'(form ...))
           (export #,@(map form-name #'(form ...))))))))

(define-locked-rules (guix-cage build locked rules)
  %graphics
  %fonts
  %shm
  %dns
  %gnupg
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

(define (validate-rules rules)
  (for-each (lambda (rule)
              (unless (locked-rule? rule)
                (raise-exception
                 (formatted-message (G_ "not a <locked-rule>: ~s") rule)))
              (validate-kinds (locked-rule-module rule)
                              (list (locked-rule-kind rule))))
            rules)
  rules)

(define (when-network-arguments . arguments)
  "Return a rule applying the rules among ARGUMENTS if the command line names
URLs or playlists with the #:playlists extensions."
  (receive (extensions rules)
      (match arguments
        ((#:playlists extensions . rules) (values extensions rules))
        (rules (values '() rules)))
    (make-locked-rule '(guix-cage build locked rules)
                      'when-network-arguments
                      (cons extensions (validate-rules rules)))))

(define (validate-wayland value)
  (match value
    ((or #f 'restricted 'full) value)
    (_ (raise-exception
        (formatted-message
         (G_ "Wayland access is not #f, 'restricted or 'full: ~s")
         value)))))

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
  (rules                locked-command-rules    ;list of <locked-rule>
                        (default '())
                        (sanitize validate-rules))
  (wayland              locked-command-wayland  ;#f | 'restricted | 'full
                        (default #f)
                        (sanitize validate-wayland))
  (pipewire?            locked-command-pipewire?
                        (default #f))
  (dbus                 locked-command-dbus     ;#f or xdg-dbus-proxy options
                        (default #f))
  (runtime-directory?   locked-command-runtime-directory?
                        (default #f))
  (temporary-directory? locked-command-temporary-directory?
                        (default #f))
  (environment          locked-command-environment ;alist
                        (default '()))
  (preserved-environment-variables
   locked-command-preserved-environment-variables
   (default %default-preserved-environment-variables))
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

(define (locked-command-options command)
  (match-record command <locked-command>
    (name wayland pipewire? dbus runtime-directory? temporary-directory?
          environment preserved-environment-variables executes?
          deny-write-execute? resource-limits syscall-allowances)
    (list #:name name
          #:wayland wayland
          #:pipewire? pipewire?
          #:dbus dbus
          #:runtime-directory? runtime-directory?
          #:temporary-directory? temporary-directory?
          #:environment environment
          #:preserved-environment-variables preserved-environment-variables
          #:executes? executes?
          #:deny-write-execute? deny-write-execute?
          #:resource-limits resource-limits
          #:syscall-allowances syscall-allowances)))

(define (build-module? name)
  (match name
    (('guix-cage 'build _ ...) #t)
    (('guix 'build 'utils) #t)
    (_ #f)))

(define (locked-command-program-file command)
  (program-file
   (locked-command-name command)
   (with-extensions (list guile-landlock guile-seccomp)
     (with-imported-modules (source-module-closure
                             (delete-duplicates
                              (cons '(guix-cage build locked)
                                    (append-map locked-rule-modules
                                                (locked-command-rules
                                                 command))))
                             #:select? build-module?)
       #~(begin
           (use-modules (guix-cage build locked))
           (apply run-locked #$(locked-command-program command)
                  '#$(map locked-rule->spec (locked-command-rules command))
                  #:dbus-proxy #$(and (locked-command-dbus command)
                                      (file-append xdg-dbus-proxy
                                                   "/bin/xdg-dbus-proxy"))
                  '#$(locked-command-options command)))))))

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
