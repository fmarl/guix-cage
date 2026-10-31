;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(include "common.scm")

(test-begin "kernel")

(define %prot-read 1)
(define %prot-write 2)
(define %prot-exec 4)
(define %map-private 2)
(define %map-anonymous #x20)

(define mmap
  (foreign-library-function #f "mmap" #:return-type '*
                            #:arg-types (list '* size_t int int int long)))

(define mprotect
  (foreign-library-function #f "mprotect" #:return-type int
                            #:arg-types (list '* size_t int)
                            #:return-errno? #t))

(define (make-written-executable)
  (let ((page (mmap %null-pointer 4096 (logior %prot-read %prot-write)
                    (logior %map-private %map-anonymous) -1 0)))
    (call-with-values
        (lambda ()
          (mprotect page 4096 (logior %prot-read %prot-exec)))
      (lambda (result errno)
        (if (< result 0) errno 0)))))

(test-equal "deny-write-execute! keeps written memory from being executed"
  (list 0 EACCES)
  (map (lambda (deny?)
         (in-child
          (lambda ()
            (when deny?
              (deny-write-execute!))
            (make-written-executable))))
       '(#f #t)))

(for-each
 (lambda (proc?)
   (test-equal (if proc?
                   "close-on-exec-except"
                   "close-on-exec-except without /proc")
     '(#t #f)
     (in-child
      (lambda ()
        (let ((closed (port->fdes (open-input-file "/dev/null")))
              (kept (port->fdes (open-input-file "/dev/null"))))
          (unless proc?
            (landlock-restrict! '()))
          (close-on-exec-except (list 0 1 2 kept))
          (map (lambda (fd)
                 (= FD_CLOEXEC (logand FD_CLOEXEC (fcntl fd F_GETFD))))
               (list closed kept)))))))
 '(#t #f))

(test-equal "apply-resource-limits!"
  '((0 0) (0 0))
  (in-child
   (lambda ()
     (apply-resource-limits! %default-resource-limits)
     (map (lambda (resource)
            (call-with-values (lambda () (getrlimit resource)) list))
          '(core rtprio)))))

(define (lock-held? file)
  (let ((port (open file (logior O_RDONLY O_CLOEXEC))))
    (dynamic-wind
      (const #t)
      (lambda ()
        (catch 'system-error
          (lambda () (flock port (logior LOCK_EX LOCK_NB)) #f)
          (const #t)))
      (lambda () (close-port port)))))

(test-assert "make-instance-directory removes those that no process holds"
  (call-with-runtime-directory
   (lambda (directory)
     (let* ((parent (string-append directory "/locked/tmp"))
            (stale (string-append parent "/stale"))
            (unlocked (string-append parent "/unlocked"))
            (alive (string-append parent "/alive")))
       (for-each mkdir-p (list stale unlocked alive))
       (write-file (string-append unlocked ".lock") "")
       (write-file (string-append alive ".lock") "")
       (let* ((lock (open-file (string-append alive ".lock") "r"))
              (instance (begin (flock lock LOCK_EX)
                               (make-instance-directory "tmp"))))
         (close-port lock)
         (and (string=? parent (dirname instance))
              (lock-held? (string-append instance ".lock"))
              (file-exists? alive)
              (not (file-exists? stale))
              (not (file-exists? unlocked))
              (not (file-exists? (string-append unlocked ".lock")))))))))

(test-equal "retain-instance-only! releases the locks of the other instances"
  '(#t #f)
  (call-with-runtime-directory
   (lambda (runtime)
     (match (in-child
             (lambda ()
               (let ((kept (make-instance-directory "tmp"))
                     (other (make-instance-directory "tmp")))
                 (match (pipe)
                   ((in . out)
                    (match (primitive-fork)
                      (0
                       (close-port in)
                       (retain-instance-only! kept)
                       (write 'ready out)
                       (close-port out)
                       (sleep 30)
                       (primitive-_exit 0))
                      (pid
                       (close-port out)
                       (read in)
                       (list kept other pid))))))))
       ((kept other pid)
        (let ((held (map (compose lock-held? (cut string-append <> ".lock"))
                         (list kept other))))
          (kill pid SIGKILL)
          held))))))

(test-assert "make-instance-directory gives every instance its own directory"
  (call-with-runtime-directory
   (lambda (directory)
     (let ((first (make-instance-directory "tmp")))
       (not (string=? first (make-instance-directory "tmp")))))))

(test-assert "make-instance-directory doesn't follow symbolic links"
  (call-with-runtime-directory
   (lambda (runtime)
     (call-with-temporary-directory
      (lambda (outside)
        (let ((stale (format #f "~a/locked/tmp/stale" runtime))
              (kept (string-append outside "/kept/file")))
          (write-file kept "")
          (mkdir-p (string-append stale "/sub"))
          (symlink (dirname kept) (string-append stale "/sub/link"))
          (symlink outside (string-append stale "/link"))
          (make-instance-directory "tmp")
          (and (not (file-exists? stale))
               (file-exists? kept))))))))

(test-equal "delete-beneath only deletes beneath the directory"
  '(#f #t)
  (call-with-temporary-directory
   (lambda (directory)
     (let ((inside (string-append directory "/inside/file"))
           (outside (string-append directory "/outside/file")))
       (write-file inside "")
       (write-file outside "")
       (delete-beneath (dirname inside) (list inside outside))
       (map file-exists? (list inside outside))))))

(unless (feature-available? (>= (landlock-abi-version) 9)
                            "Landlock ABI 9, for Unix sockets")
  (test-skip "socket-grant only grants the socket"))

(test-equal "socket-grant only grants the socket"
  '(#t #f)
  (call-with-temporary-directory
   (lambda (directory)
     (let ((granted (listening-socket (string-append directory "/granted")))
           (other (listening-socket (string-append directory "/other"))))
       (in-child
        (lambda ()
          (landlock-restrict!
           (landlock-rules (socket-grant (string-append directory "/granted")
                                          (const '())))
           #:fs '(resolve-unix) #:net '() #:flags '()
           #:require 'fully-enforced)
          (map can-connect?
               (list (string-append directory "/granted")
                     (string-append directory "/other")))))))))

(test-equal "without executes-others?, the program only runs itself"
  '(0 126)
  (let ((sh (store-program "sh"))
        (true (store-program "true")))
    (map (lambda (executes-others?)
           (exit-status-under (landlock-rules
                               (base-grant (list sh) executes-others?))
                              (list sh "-c" (string-append true "; exit $?"))))
         '(#t #f))))

(define syscall
  (let ((proc (foreign-library-function #f "syscall"
                                        #:return-type long
                                        #:arg-types (list long long long
                                                          long long)
                                        #:return-errno? #t)))
    (lambda (name . args)
      "Return the errno of system call NAME with ARGS, or 0.  Strings are
passed as pointers to their C strings."
      (let ((pointers (map (lambda (arg)
                             (if (string? arg) (string->pointer arg) arg))
                           args)))
        (call-with-values
            (lambda ()
              (apply proc ((@@ (seccomp) syscall-number) name)
                     (append (map (lambda (arg)
                                    (if (pointer? arg)
                                        (pointer-address arg)
                                        arg))
                                  pointers)
                             (make-list (- 4 (length args)) 0))))
          (lambda (result errno)
            ;; Keep the strings from the garbage collector until here
            (set! %syscall-arguments pointers)
            (if (< result 0) errno 0)))))))

(define %syscall-arguments '())

(define %clone-newuser #x10000000)
(define %af-netlink 16)
(define %af-packet 17)
(define %at-fdcwd -100)
(define %netlink-kobject-uevent 15)
(define %ipproto-icmp 1)
(define %ipproto-icmpv6 58)
(define %ipproto-sctp 132)
(define %ipproto-mptcp 262)
(define %uffd-user-mode-only 1)
(define %keyctl-get-keyring-id 0)
(define %key-spec-session-keyring -3)
(define %fan-report-fid #x200)
(define %unused-ipc-key #x6c6f636b)
(define %ipc-create #o1000)
(define %ipc-rmid 0)
(define %addr-no-randomize #x0040000)
(define %personality-query #xffffffff)

(define %socket-pair (make-bytevector 8))

;; System calls with the errnos that the filter answers them with.  File
;; names are null pointers, which the kernel answers with EFAULT.
(define %denied-calls
  `(((unshare ,%clone-newuser) ,EPERM)
    ((clone3 0 0) ,ENOSYS)
    ((socket ,%af-packet ,SOCK_RAW 0) ,EAFNOSUPPORT)
    ((socket ,(logior (ash 1 32) %af-packet) ,SOCK_RAW 0) ,EAFNOSUPPORT)
    ((socket ,%af-netlink ,SOCK_RAW ,%netlink-kobject-uevent) ,EAFNOSUPPORT)
    ((socketpair ,AF_INET ,SOCK_STREAM 0 0) ,EAFNOSUPPORT)
    ((socket ,AF_INET ,SOCK_DGRAM ,%ipproto-icmp) ,EPROTONOSUPPORT)
    ((socket ,AF_INET6 ,(logior SOCK_DGRAM SOCK_CLOEXEC) ,%ipproto-icmpv6)
     ,EPROTONOSUPPORT)
    ((socket ,AF_INET ,SOCK_STREAM ,%ipproto-mptcp) ,EPROTONOSUPPORT)
    ((socket ,AF_INET ,SOCK_STREAM ,%ipproto-sctp) ,EPROTONOSUPPORT)
    ((socket ,AF_INET ,SOCK_RAW ,%ipproto-icmp) ,EPROTONOSUPPORT)
    ((keyctl ,%keyctl-get-keyring-id ,%key-spec-session-keyring) ,EPERM)
    ((userfaultfd ,%uffd-user-mode-only) ,EPERM)
    ((perf_event_open 0 0 -1 -1) ,EPERM)
    ((io_uring_setup 0 0) ,ENOSYS)
    ((bpf 0 0 1) ,EPERM)
    ((fanotify_init ,%fan-report-fid 0) ,EPERM)
    ((personality ,%addr-no-randomize) ,EPERM)
    ((shmget ,%unused-ipc-key 0 0) ,EPERM)
    ((semget ,%unused-ipc-key 0 0) ,EPERM)
    ((msgget ,%unused-ipc-key 0) ,EPERM)
    ((mq_open 0 0) ,EPERM)))

;; System calls that the filter leaves to the kernel
(define %allowed-calls
  `((unshare 0)
    (socket ,AF_UNIX ,SOCK_STREAM 0)
    (socketpair ,AF_UNIX ,SOCK_STREAM 0
                ,(pointer-address (bytevector->pointer %socket-pair)))
    (socket ,AF_INET ,SOCK_STREAM 0)
    (socket ,AF_INET ,SOCK_STREAM ,IPPROTO_TCP)
    (socket ,AF_INET6 ,(logior SOCK_STREAM SOCK_NONBLOCK SOCK_CLOEXEC)
            ,IPPROTO_TCP)
    (socket ,AF_INET ,SOCK_DGRAM 0)
    (socket ,AF_INET6 ,SOCK_DGRAM ,IPPROTO_UDP)
    (socket ,%af-netlink ,SOCK_RAW 0)
    (personality ,%personality-query)))

(define (errno-in-new-child call)
  "Return the errno of CALL in a new child process, which is single-threaded
until then, as unshare needs."
  (match (primitive-fork)
    (0 (primitive-_exit (apply syscall call)))
    (pid (status:exit-val (cdr (waitpid pid))))))

(define (errnos-under-filter allowed-groups calls)
  (in-child
   (lambda ()
     (when allowed-groups
       (enforce-syscall-filter! allowed-groups))
     (map errno-in-new-child calls))))

(unless (feature-available? (seccomp-supported?) "seccomp")
  (test-skip "seccomp"))

(test-group "seccomp"
  (for-each
   (match-lambda*
     (((call errno) unfiltered filtered)
      ;; The kernel lacks the call or protocol, so the filter changes nothing
      (when (and (= errno unfiltered)
                 (memv errno (list ENOSYS EPROTONOSUPPORT)))
        (test-skip 1))
      (test-equal (format #f "enforce-syscall-filter! denies ~s" call)
        (list #t errno)
        (list (not (= unfiltered errno)) filtered))))
   %denied-calls
   (errnos-under-filter #f (map first %denied-calls))
   (errnos-under-filter '() (map first %denied-calls)))

  (test-equal "enforce-syscall-filter! keeps the other system calls"
    (errnos-under-filter #f %allowed-calls)
    (errnos-under-filter '() %allowed-calls))

  (test-equal "enforce-syscall-filter! leaves out the allowed groups"
    (list 0 EPERM 0)
    (errnos-under-filter '(user-namespaces socket-protocols)
                         `((unshare ,%clone-newuser)
                           (keyctl ,%keyctl-get-keyring-id
                                   ,%key-spec-session-keyring)
                           (socket ,AF_INET ,SOCK_DGRAM ,%ipproto-icmp))))

  (test-equal "restrict-to-known! denies the system calls it doesn't know"
    (list 0 ENOSYS)
    (in-child
     (lambda ()
       (restrict-to-known! (delete 'getppid %known-syscalls))
       (map errno-in-new-child '((getpid) (getppid)))))))

(define (errno-mapping-own-id)
  "Return the errno of mapping the user ID in a new user namespace of a new
child process, or 0."
  (let ((uid (getuid)))
    (match (primitive-fork)
      (0 (primitive-_exit
          (match (syscall 'unshare %clone-newuser)
            (0 (catch 'system-error
                 (lambda ()
                   (let ((port (open "/proc/self/uid_map" O_WRONLY)))
                     (format port "~a ~a 1" uid uid)
                     (close-port port)
                     0))
                 (lambda args
                   (system-error-errno args))))
            (errno errno))))
      (pid (status:exit-val (cdr (waitpid pid)))))))

(unless (feature-available? (unprivileged-user-namespace-supported?)
                            "user namespaces")
  (test-skip "container-sandbox lets programs map IDs in user namespaces"))

(test-equal "container-sandbox lets programs map IDs in user namespaces"
  (list 0 EACCES)
  (map (lambda (groups)
         (let ((sandbox (container-sandbox %no-grant '("/bin/true")
                                           #:allowed-syscall-groups groups)))
           (in-child
            (lambda ()
              (enforce-landlock! (sandbox-landlock-rules sandbox)
                                 (sandbox-landlock-abi sandbox))
              (errno-mapping-own-id)))))
       '((user-namespaces) ())))

(define (guile-script expression)
  (object->string `(exit (if ,expression 42 43))))

(define (guile-status expression)
  "Return 42 if Guile finds EXPRESSION true, and 43 otherwise."
  (exit-status-of (lambda ()
                    (execl guile "guile" "-c" (guile-script expression)))))

(define* (locked-guile-status expression #:optional (rules '())
                              #:key (executes-others? #t)
                              (own-namespaces? #t))
  "Return 42 if Guile finds EXPRESSION true under run-locked with RULES, and
43 otherwise."
  (exit-status-of (lambda ()
                    (set-program-arguments
                     (list "guile" "-c" (guile-script expression)))
                    (exit (run-locked guile rules #:init tini
                                      #:executes-others? executes-others?
                                      #:own-namespaces? own-namespaces?)))))

(define* (test-locked name expression #:optional (rules '())
                      #:key (own-namespaces? #t))
  "Test that EXPRESSION is only true outside of run-locked with RULES."
  (test-equal name
    '(42 43)
    (list (guile-status expression)
          (locked-guile-status expression rules
                               #:own-namespaces? own-namespaces?))))

(unless (and (feature-available? (seccomp-supported?) "seccomp")
             (feature-available? (>= (landlock-abi-version) 10)
                                 "Landlock ABI 10, for Unix sockets and UDP")
             (feature-available? (unprivileged-user-namespace-supported?)
                                 "user namespaces"))
  (test-skip "run-locked"))

(test-group "run-locked"
  (call-with-sandbox-home
   (lambda (home runtime)
     (let ((secret (string-append home "/secret")))
       (write-file secret "secret")
       (test-locked "run-locked keeps the home directory from being read"
         `(false-if-exception (call-with-input-file ,secret read-char)))
       (test-locked "run-locked hides the files it doesn't grant"
         `(file-exists? ,secret)))

     (let* ((bus (string-append runtime "/bus"))
            (listener (listening-socket bus)))
       (test-locked "run-locked hides the sockets of the runtime directory"
         `(false-if-exception
           (connect (socket PF_UNIX SOCK_STREAM 0) AF_UNIX ,bus)))
       (close-port listener))))

  (let* ((name (string-append (string #\nul) "locked-test-"
                              (number->string (getpid))))
         (listener (socket PF_UNIX SOCK_STREAM 0)))
    (bind listener AF_UNIX name)
    ;; Connections are never accepted
    (listen listener 16)
    (for-each (lambda (network rules)
                (test-locked (string-append "run-locked hides abstract sockets, "
                                            network)
                  `(false-if-exception
                    (connect (socket PF_UNIX SOCK_STREAM 0) AF_UNIX
                             (string-append (string #\nul)
                                            ,(string-drop name 1))))
                  rules))
              '("in its network namespace" "on the host network")
              (list '() (list (build:tcp-ports 443))))
    (close-port listener))

  (call-with-environment-variables '(("SSH_AUTH_SOCK" . "/agent")
                                     ("DISPLAY" . ":0")
                                     ("LD_PRELOAD" . ""))
    (lambda ()
      (test-locked "run-locked drops variables"
        '(or (getenv "SSH_AUTH_SOCK") (getenv "DISPLAY")
             (getenv "LD_PRELOAD")))))

  (let ((fd (dup->fdes (open-input-file "/dev/null") 100)))
    (test-locked "run-locked closes inherited descriptors"
      `(false-if-exception (stat ,fd)))
    (close-fdes fd))

  (test-locked "run-locked filters system calls"
    `(let ((personality ((@ (system foreign-library) foreign-library-function)
                         #f "personality"
                         #:return-type (@ (system foreign) int)
                         #:arg-types (list (@ (system foreign) unsigned-long)))))
       (>= (personality ,%addr-no-randomize) 0)))

  (test-equal "run-locked only shows /bin/sh with %shell"
    '(43 42)
    (map (lambda (rules)
           (locked-guile-status
            '(false-if-exception (zero? (system* "/bin/sh" "-c" "exit 0")))
            rules))
         (list '() (list build:%shell))))

  (test-equal "run-locked without executes-others? only runs the program"
    '(42 43)
    (map (lambda (expression)
           (locked-guile-status expression '() #:executes-others? #f))
         (list #t `(false-if-exception (zero? (system* ,(store-program "true")))))))

  (test-locked "run-locked keeps the program from signalling others"
    `(false-if-exception (begin (kill ,(getpid) 0) #t)))

  (test-locked "run-locked only shows the processes of the sandbox"
    `(file-exists? ,(string-append "/proc/" (number->string (getpid)))))

  (for-each
   (lambda (own-namespaces?)
     (test-equal (if own-namespaces?
                     "run-locked passes signals on"
                     "run-locked without namespaces passes signals on")
       (+ 128 SIGTERM)
       (match (pipe)
         ((in . out)
          (flush-all-ports)
          (match (primitive-fork)
            (0
             (close-port in)
             (dup2 (port->fdes out) 1)
             (exit-with
              (lambda ()
                (set-program-arguments
                 '("guile" "-c"
                   "(begin (write '(ready)) (force-output) (sleep 30))"))
                (exit (run-locked guile '() #:init tini
                                  #:own-namespaces? own-namespaces?)))))
            (pid
             (close-port out)
             ;; The program is running once it is ready
             (read in)
             (kill pid SIGTERM)
             (status:exit-val (cdr (waitpid pid)))))))))
   '(#t #f))

  (test-equal "run-locked without namespaces grants the devices"
    42
    (locked-guile-status '(begin (call-with-output-file "/dev/null"
                                   (lambda (port) (display "test" port)))
                                 #t)
                         '() #:own-namespaces? #f))

  (test-equal "run-locked without namespaces shares the PID namespace"
    '(43 42)
    (map (lambda (own-namespaces?)
           (locked-guile-status '(> (getpid) 2) '()
                                #:own-namespaces? own-namespaces?))
         '(#t #f)))

  (test-locked "run-locked without namespaces denies /proc"
    '(false-if-exception (call-with-input-file "/proc/self/status" read-char))
    '() #:own-namespaces? #f)

  (test-locked "run-locked without namespaces denies signalling others"
    `(false-if-exception (begin (kill ,(getpid) 0) #t))
    '() #:own-namespaces? #f)

  (call-with-sandbox-home
   (lambda (home runtime)
     (let ((secret (string-append home "/secret")))
       (write-file secret "secret")
       (test-locked "run-locked without namespaces denies the home directory"
         `(false-if-exception (call-with-input-file ,secret read-char))
         '() #:own-namespaces? #f))

     (let* ((bus (string-append runtime "/bus"))
            (listener (listening-socket bus)))
       (test-locked "run-locked without namespaces denies XDG_RUNTIME_DIR"
         `(false-if-exception
           (connect (socket PF_UNIX SOCK_STREAM 0) AF_UNIX ,bus))
         '() #:own-namespaces? #f)
       (close-port listener))))

  (let* ((name (string-append (string #\nul) "locked-test-host-"
                              (number->string (getpid))))
         (listener (socket PF_UNIX SOCK_STREAM 0)))
    (bind listener AF_UNIX name)
    (listen listener 16)
    (test-locked "run-locked without namespaces hides abstract sockets"
      `(false-if-exception
        (connect (socket PF_UNIX SOCK_STREAM 0) AF_UNIX
                 (string-append (string #\nul) ,(string-drop name 1))))
      '() #:own-namespaces? #f)
    (close-port listener))

  (let* ((listener (socket PF_INET SOCK_STREAM 0))
         (port (begin (bind listener AF_INET INADDR_LOOPBACK 0)
                      (listen listener 16)
                      (sockaddr:port (getsockname listener))))
         (connects `(false-if-exception
                     (begin (connect (socket PF_INET SOCK_STREAM 0)
                                     AF_INET INADDR_LOOPBACK ,port)
                            #t))))
    (test-locked "run-locked without namespaces denies TCP ports"
      connects '() #:own-namespaces? #f)
    (test-equal "run-locked without namespaces grants TCP ports"
      42
      (locked-guile-status connects (list (build:tcp-ports port))
                           #:own-namespaces? #f))
    (close-port listener))

  (let* ((receiver (socket PF_INET SOCK_DGRAM 0))
         (port (begin (bind receiver AF_INET INADDR_LOOPBACK 0)
                      (sockaddr:port (getsockname receiver)))))
    (test-locked "run-locked without namespaces denies UDP ports"
      `(false-if-exception
        (sendto (socket PF_INET SOCK_DGRAM 0) #vu8(1)
                AF_INET INADDR_LOOPBACK ,port))
      '() #:own-namespaces? #f)
    (close-port receiver))

  (let* ((key (1+ %unused-ipc-key))
         (shmget (foreign-library-function #f "shmget"
                                           #:return-type int
                                           #:arg-types (list int size_t int)))
         (shmctl (foreign-library-function #f "shmctl"
                                           #:return-type int
                                           #:arg-types (list int int '*)))
         (segment (shmget key 4096 (logior %ipc-create #o600))))
    (test-locked "run-locked without namespaces denies System V IPC"
      `(>= (((@ (system foreign-library) foreign-library-function)
             #f "shmget"
             #:return-type (@ (system foreign) int)
             #:arg-types (list (@ (system foreign) int)
                               (@ (system foreign) size_t)
                               (@ (system foreign) int)))
            ,key 0 0)
           0)
      '() #:own-namespaces? #f)
    (shmctl segment %ipc-rmid %null-pointer))

  (call-with-sandbox-home
   (lambda (home runtime)
     (let ((bus (string-append runtime "/bus")))
       (call-with-environment-variables
        `(("DBUS_SESSION_BUS_ADDRESS" . ,(string-append "unix:path=" bus)))
        (lambda ()
          (let* ((listener (listening-socket bus))
                 (granted ((build:dbus (store-program "xdg-dbus-proxy")
                                       "--talk=org.freedesktop.Notifications")
                           '("test")))
                 (proxied (match (assoc-ref (grant-variables granted)
                                            "DBUS_SESSION_BUS_ADDRESS")
                            ((? (cut string-prefix? "unix:path=" <>) address)
                             (string-drop address
                                          (string-length "unix:path=")))))
                 (proxy (find (lambda (pid)
                                (false-if-exception
                                 (string-contains
                                  (call-with-input-file
                                      (format #f "/proc/~a/cmdline" pid)
                                    get-string-all)
                                  proxied)))
                              (filter-map string->number (scandir "/proc")))))
            (test-assert "dbus runs xdg-dbus-proxy in namespaces of its own"
              (and proxy
                   (file-exists? proxied)
                   (not (string=? (readlink "/proc/self/ns/pid")
                                  (readlink (format #f "/proc/~a/ns/pid"
                                                    proxy))))))
            (for-each close-fdes (grant-fds granted))
            (test-assert "xdg-dbus-proxy ends with the sandbox"
              (process-ends? proxy))
            (test-assert "dbus reports the exit code of a failed proxy"
              (guard (e ((locked-error? e)
                         (string-contains (exception-message e)
                                          "exited with code 1")))
                ((build:dbus (store-program "false")
                             "--talk=org.freedesktop.Notifications")
                 '("test"))
                #f))
            (close-port listener)))))))

  (test-assert "run-locked without namespaces ends with this process"
    (match (pipe)
      ((in . out)
       (flush-all-ports)
       (match (primitive-fork)
         (0
          (close-port in)
          (dup2 (port->fdes out) 1)
          (exit-with
           (lambda ()
             (set-program-arguments
              '("guile" "-c"
                "(begin (write (getpid)) (newline) (force-output)
                        (sleep 30))"))
             (exit (run-locked guile '() #:own-namespaces? #f)))))
         (launcher
          (close-port out)
          (let ((program (read in)))
            (close-port in)
            (kill launcher SIGKILL)
            (waitpid launcher)
            (process-ends? program))))))))


(define failures (test-runner-fail-count (test-runner-current)))
(test-end "kernel")
(exit (zero? failures))
