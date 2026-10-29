;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked sandbox)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked grants)
  #:use-module (guix-cage build locked landlock)
  #:use-module (guix-cage build locked namespaces)
  #:use-module (guix-cage build locked platform)
  #:use-module (guix-cage build locked process)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:export (container-sandbox
            host-sandbox
            sandbox?
            sandbox-namespaces
            sandbox-file-systems
            sandbox-links
            sandbox-signals
            sandbox-landlock-rules
            sandbox-landlock-abi
            sandbox-allowed-syscall-groups
            sandbox-new-session?
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
                landlock-rules landlock-abi allowed-syscall-groups
                new-session? directory environment fds resource-limits
                deny-write-execute? command)
  sandbox?
  (namespaces             sandbox-namespaces)
  (file-systems           sandbox-file-systems)
  (links                  sandbox-links)        ;alist of links and targets
  (signals                sandbox-signals)      ;passed on to the sandbox
  (landlock-rules         sandbox-landlock-rules)
  (landlock-abi           sandbox-landlock-abi)
  (allowed-syscall-groups sandbox-allowed-syscall-groups)
  (new-session?           sandbox-new-session?)
  (directory              sandbox-directory)
  (environment            sandbox-environment)  ;NAME=VALUE strings
  (fds                    sandbox-fds)          ;kept open
  (resource-limits        sandbox-resource-limits)
  (deny-write-execute?    sandbox-deny-write-execute?)
  (command                sandbox-command))     ;program and arguments

(define %device-grant
  (grant #:files (list (file-access "/dev/null" '(read write))
                       (read-access "/dev/urandom"))))

(define* (make-sandbox* grant command namespaces file-systems links
                        #:key environment directory allowed-syscall-groups
                        resource-limits deny-write-execute? new-session?)
  (make-sandbox
   namespaces
   file-systems
   links
   (if new-session?
       (list SIGINT SIGQUIT SIGTERM SIGHUP)
       (list SIGTERM))
   (landlock-rules grant)
   (if (memq 'net namespaces) %landlock-abi %host-network-landlock-abi)
   (if (memq 'ipc namespaces)
       (lset-adjoin eq? allowed-syscall-groups 'ipc)
       allowed-syscall-groups)
   new-session?
   directory
   environment
   (cons* 0 1 2 (grant-fds grant))
   resource-limits
   deny-write-execute?
   command))

(define* (container-sandbox grant command
                            #:key (environment '()) (links '())
                            (directory "/") (allowed-syscall-groups '())
                            (resource-limits %default-resource-limits)
                            deny-write-execute? new-session?)
  "Return the sandbox that enforces GRANT for COMMAND, a list of a program and
its arguments, in namespaces of its own.  LINKS are the symbolic links it
needs besides those into the store."
  (let ((grant (grant-append %device-grant %container-grant grant)))
    (make-sandbox* grant command
                   `(user mnt pid ipc uts cgroup
                          ;; Ports are on the network of the host
                          ,@(if (null? (grant-ports grant)) '(net) '()))
                   (file-systems grant)
                   (append links (store-links environment))
                   #:environment environment
                   #:directory directory
                   #:allowed-syscall-groups allowed-syscall-groups
                   #:resource-limits resource-limits
                   #:deny-write-execute? deny-write-execute?
                   #:new-session? new-session?)))

(define* (host-sandbox grant command
                       #:key (environment '()) (directory "/")
                       (allowed-syscall-groups '())
                       (resource-limits %default-resource-limits)
                       deny-write-execute? new-session?)
  (match (filter file-access-private? (grant-files grant))
    (() #t)
    ((access . _)
     (raise-locked-error "~a can only be private in namespaces of its own"
                         (file-access-file access))))
  (make-sandbox* (grant-append %device-grant grant) command '() '() '()
                 #:environment environment
                 #:directory directory
                 #:allowed-syscall-groups allowed-syscall-groups
                 #:resource-limits resource-limits
                 #:deny-write-execute? deny-write-execute?
                 #:new-session? new-session?))
