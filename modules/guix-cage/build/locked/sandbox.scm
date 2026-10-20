;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked sandbox)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked landlock)
  #:use-module (guix-cage build locked namespaces)
  #:use-module (guix-cage build locked process)
  #:use-module (srfi srfi-9)
  #:export (sandbox
            sandbox?
            sandbox-namespaces
            sandbox-file-systems
            sandbox-links
            sandbox-signals
            sandbox-landlock-rules
            sandbox-syscall-allowances
            sandbox-detached?
            sandbox-directory
            sandbox-environment
            sandbox-fds
            sandbox-resource-limits
            sandbox-deny-write-execute?
            sandbox-command))

;;; How each layer of a sandbox enforces a grant, computed without touching
;;; the system.  Landlock and seccomp confine all they can, also where the
;;; namespaces already do, so that only the namespaces depend on the grant.

(define-record-type <sandbox>
  (make-sandbox namespaces file-systems links signals
                landlock-rules syscall-allowances
                detached? directory environment fds resource-limits
                deny-write-execute? command)
  sandbox?
  ;; Namespaces
  (namespaces          sandbox-namespaces)
  (file-systems        sandbox-file-systems)
  (links               sandbox-links)           ;alist of links and targets
  (signals             sandbox-signals)         ;passed on to the sandbox
  ;; Landlock and seccomp
  (landlock-rules      sandbox-landlock-rules)
  (syscall-allowances  sandbox-syscall-allowances)
  ;; The process
  (detached?           sandbox-detached?)       ;from the terminal
  (directory           sandbox-directory)
  (environment         sandbox-environment)     ;NAME=VALUE strings
  (fds                 sandbox-fds)             ;kept open
  (resource-limits     sandbox-resource-limits)
  (deny-write-execute? sandbox-deny-write-execute?)
  (command             sandbox-command))        ;program and arguments

(define* (sandbox grant command
                  #:key (environment '()) (links '()) (directory "/")
                  (syscall-allowances '())
                  (resource-limits %default-resource-limits)
                  deny-write-execute? detached?)
  "Return the sandbox that enforces GRANT for COMMAND, a list of a program and
its arguments.  LINKS are the symbolic links it needs besides those into the
store."
  (let ((grant (grant-append %container-grant grant)))
    (make-sandbox
     `(user mnt pid ipc uts cgroup
            ;; Ports are on the network of the host
            ,@(if (null? (grant-ports grant)) '(net) '()))
     (file-systems grant)
     (append links (store-links environment))
     ;; Those of the terminal reach an attached sandbox directly
     (if detached?
         (list SIGINT SIGQUIT SIGTERM SIGHUP)
         (list SIGTERM))
     (landlock-rules grant)
     syscall-allowances
     detached?
     directory
     environment
     (cons* 0 1 2 (grant-fds grant))
     resource-limits
     deny-write-execute?
     command)))
