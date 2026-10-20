;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked namespaces)
  #:use-module (gnu build linux-container)
  #:use-module (gnu system file-systems)
  #:use-module ((guix build syscalls) #:select (set-network-interface-up))
  #:use-module ((guix build utils) #:select (mkdir-p))
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked file-names)
  #:use-module (guix-cage build locked grants)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%container-grant
            file-systems
            store-links
            call-in-namespaces))

;;; The namespaces only show the granted files, and give the program its own
;;; processes, IPC and host name, and network unless it needs ports.

;; The container makes these itself, so grants only give rights on them
(define %container-files
  '("/proc" "/dev/null" "/dev/zero" "/dev/full" "/dev/random" "/dev/urandom"
    "/dev/tty" "/dev/pts" "/dev/shm"))

(define %container-grant
  ;; /proc only has the processes of the sandbox.  Writing /proc/PID/mem
  ;; would get past deny-write-execute?.
  (grant #:files (list (read-access "/proc")
                       (file-access "/dev/null" '(read write))
                       (read-access "/dev/urandom"))))

(define (merge-accesses accesses)
  "Return ACCESSES with one access per file, holding all its permissions."
  (map (lambda (file)
         (let ((same (filter (compose (cut string=? file <>) file-access-file)
                             accesses)))
           (file-access file
                        (delete-duplicates
                         (append-map file-access-permissions same))
                        #:private? (any file-access-private? same))))
       (delete-duplicates (map file-access-file accesses))))

(define (bind-mount-flags permissions)
  `(bind-mount no-suid
    ,@(if (any (cut memq <> permissions) '(write make-socket))
          '()
          '(read-only))
    ,@(if (memq 'execute permissions) '() '(no-exec))
    ,@(if (memq 'ioctl permissions) '() '(no-dev))))

(define (access-file-system access)
  (let ((file (file-access-file access))
        (permissions (file-access-permissions access)))
    (cond ((file-access-private? access)
           (file-system
             (device "tmpfs")
             (mount-point file)
             (type "tmpfs")
             (flags '(no-suid no-dev))
             (options "mode=0700")
             (check? #f)
             (create-mount-point? #t)))
          ((or (lset<= eq? permissions '(list))
               (any (cut directory-contains? <> file) %container-files)
               (not (file-exists? file)))
           #f)
          (else
           ;; Descriptors of this mount namespace can't serve as sources in
           ;; the new one.  Landlock still pins files to them.
           (file-system
             (device file)
             (mount-point file)
             (type "none")
             (flags (bind-mount-flags permissions))
             (check? #f)
             (create-mount-point? #t))))))

(define (file-systems grant)
  "Return the file systems that show what GRANT grants, outer ones first."
  (sort (filter-map access-file-system (merge-accesses (grant-files grant)))
        (lambda (a b)
          (< (string-length (file-system-mount-point a))
             (string-length (file-system-mount-point b))))))

(define (store-link file)
  "Return the symbolic link that leads from FILE into the store, with its
target, or #f."
  (let loop ((directory "")
             (components (file-name-components file)))
    (match components
      (() #f)
      ((component . rest)
       (let ((link (string-append directory "/" component)))
         (if (eq? 'symlink (and=> (false-if-exception (lstat link))
                                  stat:type))
             (let ((target (false-if-exception (canonicalize-path link))))
               (and target
                    (string-prefix? "/gnu/store/" target)
                    (cons link target)))
             (loop link rest)))))))

(define (store-links environment)
  "Return the symbolic links into the store, such as profiles, that the
file names in ENVIRONMENT, a list of NAME=VALUE strings, go through."
  (delete-duplicates
   (filter-map store-link
               (append-map (lambda (entry)
                             (filter (cut string-prefix? "/" <>)
                                     (string-split
                                      (substring entry
                                                 (1+ (string-index entry #\=)))
                                      #\:)))
                           environment))))

(define (make-links! links)
  (for-each (match-lambda
              ((link . target)
               (unless (false-if-exception (lstat link))
                 (mkdir-p (dirname link))
                 (symlink target link))))
            links))

(define* (call-in-namespaces namespaces file-systems links thunk
                             #:key (signals '()))
  "Call THUNK as the first process in new NAMESPACES with FILE-SYSTEMS and
LINKS, an alist of symbolic links and targets.  Pass SIGNALS on to it, and
return its status."
  (unless (unprivileged-user-namespace-supported?)
    (raise-locked-error "the kernel doesn't let users create namespaces"))
  (call-with-container file-systems
    thunk
    #:namespaces namespaces
    ;; Only the root user keeps its capabilities when it executes programs
    #:guest-uid (getuid)
    #:guest-gid (getgid)
    #:child-is-pid1? #t
    #:relayed-signals signals
    ;; It would write /etc/hosts, which is the host's
    #:loopback-network? #f
    #:populate-file-system
    (lambda ()
      (make-links! links)
      (when (memq 'net namespaces)
        (set-network-interface-up "lo")))))
