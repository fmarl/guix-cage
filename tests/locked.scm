;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(use-modules (gnu packages video)
             (guix build utils)
             (guix gexp)
             (guix packages)
             (ice-9 ftw)
             (ice-9 match)
             (ice-9 string-fun)
             (ice-9 textual-ports)
             (landlock)
             (rnrs bytevectors)
             ((seccomp) #:select (seccomp-supported?))
             (guix-cage build locked environment)
             (guix-cage locked)
             (srfi srfi-1)
             (srfi srfi-26)
             (srfi srfi-34)
             (srfi srfi-64)
             (system foreign)
             (system foreign-library))

(define-locked-rules (guix-cage build locked virtualization)
  %qemu)

(define mpv-locked
  (make-locked-package
   mpv
   (list (locked-command
           (name "mpv")
           (program (file-append mpv "/bin/mpv"))))))

(define-syntax-rule (define-internal module name ...)
  (begin (define name (@@ module name)) ...))

(define (rule->list rule)
  (if (landlock-path? rule)
      (list ((@@ (landlock) landlock-path-path) rule)
            ((@@ (landlock) landlock-path-access) rule))
      (list ((@@ (landlock) landlock-port-port) rule)
            ((@@ (landlock) landlock-port-access) rule))))

(define (call-with-environment-variables variables thunk)
  (let ((saved (map (match-lambda
                      ((name . _) (cons name (getenv name))))
                    variables)))
    (dynamic-wind
      (lambda ()
        (for-each (match-lambda
                    ((name . value) (setenv name value)))
                  variables))
      thunk
      (lambda ()
        (for-each (match-lambda
                    ((name . #f) (unsetenv name))
                    ((name . value) (setenv name value)))
                  saved)))))

(define (call-with-temporary-directory proc)
  (let ((directory (mkdtemp (string-append (or (getenv "TMPDIR") "/tmp")
                                           "/locked-test-XXXXXX"))))
    (dynamic-wind
      (const #t)
      (lambda () (proc directory))
      (lambda () (delete-file-recursively directory)))))

(define (call-with-runtime-directory proc)
  (call-with-temporary-directory
   (lambda (directory)
     (call-with-environment-variables `(("XDG_RUNTIME_DIR" . ,directory))
       (lambda ()
         (proc directory))))))

(define (dead-pid)
  (match (primitive-fork)
    (0 (primitive-_exit 0))
    (pid (waitpid pid) pid)))

(define (in-child thunk)
  (flush-all-ports)
  (match (pipe)
    ((in . out)
     (match (primitive-fork)
       (0
        (close-port in)
        (write (false-if-exception (thunk)) out)
        (close-port out)
        (primitive-_exit 0))
       (pid
        (close-port out)
        (let ((result (read in)))
          (close-port in)
          (waitpid pid)
          (and (not (eof-object? result)) result)))))))

(define (unix-socket file)
  (bind (socket PF_UNIX SOCK_STREAM 0) AF_UNIX file)
  file)

(define (listening-socket file)
  (let ((listener (socket PF_UNIX SOCK_STREAM 0)))
    (bind listener AF_UNIX file)
    (listen listener 1)
    listener))

(define (can-connect? file)
  (false-if-exception
   (let ((connection (socket PF_UNIX SOCK_STREAM 0)))
     (connect connection AF_UNIX file)
     (close-port connection)
     #t)))

(define (write-file file content)
  (mkdir-p (dirname file))
  (call-with-output-file file (cut display content <>)))

(define-internal (guix-cage locked)
  make-locked-rule locked-rule-modules)
(define-internal (guix-cage build locked)
  resolve-spec resolved-rule-kinds landlock-rules)
(define-internal (guix-cage build locked errors)
  locked-error?)
(define-internal (guix-cage build locked files)
  make-instance-directory share-socket!)
(define-internal (guix-cage build locked grants)
  grant-rules grant-variables)
(define-internal (guix-cage build locked kinds)
  kind-name)
(define-internal (guix-cage build locked process)
  forward-signals-and-exit close-on-exec-except deny-write-execute!
  apply-resource-limits!)
(define-internal (guix-cage build locked syscalls)
  enforce-syscall-filter!)
(define-internal (guix-cage build locked rules)
  base-rules elf-interpreters user-directory argument-file network-arguments?)
(define-internal (guix-cage build locked virtualization)
  qemu-rules waypipe-client-rules)
(define-internal (guix-cage build locked wayland)
  wayland-string wayland-string-ref wayland-message)
(define-internal (guix-cage build locked-package)
  install-locked-package)

(define (rule name . parameters)
  (cons* '(guix-cage build locked rules) name parameters))

(define (specs->landlock-rules specs arguments)
  (landlock-rules (map resolve-spec specs) arguments))

(define (user-directory-with line)
  (call-with-temporary-directory
   (lambda (home)
     (write-file (string-append home "/.config/user-dirs.dirs") line)
     (call-with-environment-variables
      `(("HOME" . ,home)
        ("XDG_CONFIG_HOME" . ,(string-append home "/.config")))
      (lambda ()
        (and=> (user-directory "DOWNLOAD" "Downloads")
               (lambda (directory)
                 (if (string-prefix? home directory)
                     (string-append "~" (string-drop directory
                                                     (string-length home)))
                     directory))))))))

(test-begin "locked")

(test-equal "locked-rule->spec"
  '((guix-cage build locked rules) when-network-arguments (".m3u")
    ((guix-cage build locked rules) dns)
    ((guix-cage build locked rules) tcp-ports 80 443))
  (locked-rule->spec
   (when-network-arguments #:playlists '(".m3u") %dns (tcp-ports 80 443))))

(test-equal "locked-rule-modules"
  '((guix-cage build locked rules) (guix-cage build locked virtualization))
  (locked-rule-modules (when-network-arguments %qemu)))

(test-equal "locked-command defaults"
  (list '() #f #f %default-preserved-environment-variables)
  (let ((command (locked-command
                   (name "true")
                   (program "/bin/true"))))
    (list (locked-command-rules command)
          (locked-command-wayland command)
          (locked-command-dbus command)
          (locked-command-preserved-environment-variables command))))

(test-error "locked-command rejects unknown Wayland access"
  #t
  (locked-command
    (name "true")
    (program "/bin/true")
    (wayland #t)))

(test-equal "locked-command takes system call groups"
  '(user-namespaces)
  (locked-command-syscall-allowances
   (locked-command
     (name "true")
     (program "/bin/true")
     (syscall-allowances '(user-namespaces)))))

(test-equal "locked-command resource limits default"
  %default-resource-limits
  (locked-command-resource-limits
   (locked-command
     (name "true")
     (program "/bin/true"))))

(test-assert "locked-command only denies writable executable memory on request"
  (not (locked-command-deny-write-execute?
        (locked-command
          (name "true")
          (program "/bin/true")))))

(test-error "locked-command rejects invalid resource limits"
  #t
  (locked-command
    (name "true")
    (program "/bin/true")
    (resource-limits '((cores . 0) (nofile . -1)))))

(test-error "locked-command rejects unknown system call groups"
  #t
  (locked-command
    (name "true")
    (program "/bin/true")
    (syscall-allowances '(typo))))

(test-error "locked-command rejects rules that aren't <locked-rule>"
  #t
  (locked-command
    (name "true")
    (program "/bin/true")
    (rules (list "/home"))))

(test-error "when-network-arguments rejects rules that aren't <locked-rule>"
  #t
  (when-network-arguments "/home"))

(test-error "locked-command rejects unknown kinds of rules"
  #t
  (locked-command
    (name "true")
    (program "/bin/true")
    (rules (list (make-locked-rule '(guix-cage build locked rules)
                                   'typo '())))))

(test-error "define-locked-rules rejects unknown kinds"
  #t
  (eval '(define-locked-rules (guix-cage build locked rules) %typo)
        (let ((module (make-fresh-user-module)))
          (module-use! module (resolve-interface '(guix-cage locked)))
          module)))

(test-assert "make-locked-package only supports Linux"
  (every (lambda (system)
           (string-suffix? "-linux" system))
         (package-supported-systems mpv-locked)))

(test-equal "make-locked-package keeps the version"
  (package-version mpv)
  (package-version mpv-locked))

(test-equal "user-directory, below the home directory"
  "~/Downloads"
  (user-directory-with "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n"))

(test-equal "user-directory, absolute"
  "/data/downloads"
  (user-directory-with "XDG_DOWNLOAD_DIR=\"/data/downloads\"\n"))

(test-equal "user-directory, default"
  "~/Downloads"
  (user-directory-with "# empty\n"))

(for-each (lambda (value)
            (test-assert (string-append "user-directory, rejects " value)
              (not (user-directory-with
                    (string-append "XDG_DOWNLOAD_DIR=\"" value "\"\n")))))
          '("$HOME/" "$HOME" "$HOMEfoo" "$HOME/../" "/" "relative"))

(test-equal "argument-file"
  '("film.mkv" "/film.mkv" "list.m3u" #f #f)
  (map argument-file
       '("film.mkv" "file:///film.mkv" "--playlist=list.m3u" "-v"
         "--volume")))

(test-assert "network-arguments?, local files"
  (not (network-arguments? '("film.mkv" "file:///film.mkv" "-v") '())))

(test-assert "network-arguments?, URL"
  (network-arguments? '("https://example.org/film.mkv") '()))

(test-assert "network-arguments?, playlist"
  (network-arguments? '("--playlist=list.M3U8") '(".m3u8")))

(test-assert "network-arguments?, playlists not given"
  (not (network-arguments? '("list.m3u8") '())))

(test-assert "network-arguments?, URL in an option"
  (not (network-arguments? '("--script-opts=x=https://example.org") '())))

(test-equal "landlock-rules, tcp-ports"
  '((143 (connect-tcp)) (993 (connect-tcp)))
  (map rule->list
       (specs->landlock-rules (list (rule 'tcp-ports 143 993)) '())))

(test-equal "landlock-rules, when-network-arguments"
  '(0 1)
  (map (lambda (arguments)
         (length (specs->landlock-rules
                  (list (rule 'when-network-arguments '()
                              (rule 'tcp-ports 443)))
                  arguments)))
       '(("film.mkv") ("https://example.org"))))

(test-assert "landlock-rules, argument-files"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((film (string-append directory "/film.mkv"))
           (playlist (string-append directory "/list.m3u")))
       (write-file film "")
       (write-file playlist "")
       (equal? (map rule->list
                    (specs->landlock-rules
                     (list (rule 'argument-files))
                     (list "--verbose" film
                           (string-append "--playlist=" playlist)
                           "/nonexistent")))
               `((,film (read-file read-dir))
                 (,playlist (read-file read-dir))))))))

(test-equal "gnupg rules don't reach the secret keys"
  '()
  (filter (lambda (rule)
            (string-contains (car (rule->list rule)) "private-keys"))
          (specs->landlock-rules (list (rule 'gnupg)) '())))

(test-equal "resolved-rule-kinds includes those that conditional kinds hold"
  '(gnupg fonts)
  (map kind-name
       (resolved-rule-kinds
        (map resolve-spec
             (list (rule 'when-network-arguments '() (rule 'gnupg))
                   (rule 'fonts))))))

(test-assert "resolve-spec rejects unknown kinds"
  (guard (exception ((locked-error? exception) #t))
    (resolve-spec (rule 'typo))
    #f))

(test-assert "resolve-spec rejects modules without kinds"
  (guard (exception ((locked-error? exception) #t))
    (resolve-spec '((guix-cage build locked files) read-only "/"))
    #f))

(test-equal "wayland-string pads to 32 bits"
  '(5 #vu8(119 112 95 120 0 0 0 0))
  (let ((bytes (wayland-string "wp_x")))
    (list (bytevector-u32-native-ref bytes 0)
          (let ((rest (make-bytevector 8)))
            (bytevector-copy! bytes 4 rest 0 8)
            rest))))

(test-equal "wayland-string-ref"
  "wp_security_context_manager_v1"
  (wayland-string-ref (wayland-string "wp_security_context_manager_v1") 0))

(test-equal "wayland-message, get_registry"
  '(1 #x000c0001 2)
  (let ((message (wayland-message 1 1 2)))
    (list (bytevector-u32-native-ref message 0)
          (bytevector-u32-native-ref message 4)
          (bytevector-u32-native-ref message 8))))

(test-assert "preserved-variable?"
  (let ((preserved? (cut preserved-variable? <>
                         %default-preserved-environment-variables)))
    (and (preserved? "LC_ALL")
         (preserved? "HOME")
         (not (preserved? "GITHUB_TOKEN"))
         (not (preserved? "DISPLAY")))))

(test-equal "preserve-environment!"
  '("C" #f)
  (let ((saved (environ)))
    (dynamic-wind
      (const #t)
      (lambda ()
        (setenv "LC_TEST" "C")
        (setenv "SECRET_TOKEN" "x")
        (preserve-environment! '("LC_*"))
        (list (getenv "LC_TEST") (getenv "SECRET_TOKEN")))
      (lambda ()
        (environ saved)))))

(test-equal "forward-signals-and-exit passes the signal on"
  (+ 128 SIGTERM)
  (match (primitive-fork)
    (0
     (match (primitive-fork)
       (0
        (sleep 30)
        (primitive-_exit 0))
       (child
        (catch 'quit
          (lambda ()
            (forward-signals-and-exit child))
          (lambda (key status)
            (primitive-_exit status))))))
    (supervisor
     (sleep 1)
     (kill supervisor SIGTERM)
     (status:exit-val (cdr (waitpid supervisor))))))

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

(test-equal "close-on-exec-except"
  '(#t #f)
  (in-child
   (lambda ()
     (let ((closed (port->fdes (open-input-file "/dev/null")))
           (kept (port->fdes (open-input-file "/dev/null"))))
       (fcntl kept F_SETFD 0)
       (close-on-exec-except (list 0 1 2 kept))
       (map (lambda (fd)
              (= FD_CLOEXEC (logand FD_CLOEXEC (fcntl fd F_GETFD))))
            (list closed kept))))))

(test-equal "apply-resource-limits!"
  '((0 0) (0 0))
  (in-child
   (lambda ()
     (apply-resource-limits! %default-resource-limits)
     (map (lambda (resource)
            (call-with-values (lambda () (getrlimit resource)) list))
          '(core rtprio)))))

(test-assert "make-instance-directory removes those of exited processes"
  (call-with-runtime-directory
   (lambda (directory)
     (let ((stale (format #f "~a/locked/tmp/~a" directory (dead-pid)))
           (alive (format #f "~a/locked/tmp/~a" directory (getppid))))
       (mkdir-p stale)
       (mkdir-p alive)
       (and (equal? (make-instance-directory "tmp")
                    (format #f "~a/locked/tmp/~a" directory (getpid)))
            (not (file-exists? stale))
            (file-exists? alive))))))

(test-assert "share-socket!"
  (call-with-temporary-directory
   (lambda (directory)
     (let* ((socket (unix-socket (string-append directory "/s")))
            (shared (share-socket! socket
                                   (lambda (socket) `(("SOCKET" . ,socket)))))
            (missing (share-socket! (string-append directory "/missing")
                                    (const '(("SOCKET" . "x"))))))
       (equal? (list (map rule->list (grant-rules shared))
                     (grant-variables shared)
                     (grant-rules missing)
                     (grant-variables missing))
               `(((,socket (resolve-unix))) (("SOCKET" . ,socket)) () ()))))))

(unless (>= (landlock-abi-version) 9)
  (test-skip "share-socket! only grants the socket"))

(define (store-program name)
  (canonicalize-path (search-path (parse-path (getenv "PATH")) name)))

(define (exit-status-under rules command)
  (flush-all-ports)
  (match (primitive-fork)
    (0
     (catch #t
       (lambda ()
         (landlock-restrict! rules)
         (apply execl (car command) command))
       (lambda _
         (primitive-_exit 127))))
    (pid
     (status:exit-val (cdr (waitpid pid))))))

(test-assert "elf-interpreters finds the dynamic loader"
  (match (elf-interpreters (store-program "true"))
    ((loader) (string-contains loader "/ld-"))
    (_ #f)))

(test-assert "elf-interpreters rejects scripts"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((script (string-append directory "/script")))
       (write-file script "#!/bin/sh\n")
       (guard (exception ((locked-error? exception) #t))
         (elf-interpreters script)
         #f)))))

(test-equal "without executes?, the program can't run others"
  '(0 126)
  (let ((sh (store-program "sh"))
        (true (store-program "true")))
    (map (lambda (executes?)
           (exit-status-under (base-rules sh executes?)
                              (list sh "-c" (string-append true "; exit $?"))))
         '(#t #f))))

(test-equal "share-socket! only grants the socket"
  '(#t #f)
  (call-with-temporary-directory
   (lambda (directory)
     (let ((granted (listening-socket (string-append directory "/granted")))
           (other (listening-socket (string-append directory "/other"))))
       (in-child
        (lambda ()
          (landlock-restrict!
           (grant-rules (share-socket! (string-append directory "/granted")
                                       (const '())))
           #:fs '(resolve-unix) #:net '() #:best-effort? #f)
          (map can-connect?
               (list (string-append directory "/granted")
                     (string-append directory "/other")))))))))

(test-equal "install-locked-package keeps the entry points of the commands"
  '(("bin" "foo")
    ("share/applications" "foo.desktop")
    ("share/dbus-1/services" "foo.service")
    "Exec=OUT/bin/foo %U")
  (call-with-temporary-directory
   (lambda (directory)
     (let ((original (string-append directory "/original"))
           (output (string-append directory "/out")))
       (define (entry file . programs)
         (write-file (string-append original "/share/" file)
                     (string-join
                      (map (cut string-append "Exec=" original "/bin/" <>
                                " %U")
                           programs)
                      "\n")))

       (define (entries subdirectory)
         (cons subdirectory
               (scandir (string-append output "/" subdirectory)
                        (negate (cut member <> '("." ".."))))))

       (entry "applications/foo.desktop" "foo")
       (entry "applications/bar.desktop" "bar")
       (entry "applications/both.desktop" "foo" "bar")
       (entry "dbus-1/services/foo.service" "foo")
       (entry "dbus-1/interfaces/foo.xml")
       (write-file (string-append original "/share/doc/README") "")
       (install-locked-package original output '(("foo" . "/wrapper/foo")))
       (list (entries "bin")
             (entries "share/applications")
             (entries "share/dbus-1/services")
             (string-replace-substring
              (call-with-input-file
                  (string-append output "/share/applications/foo.desktop")
                get-string-all)
              output "OUT"))))))

(define syscall
  (let ((proc (foreign-library-function #f "syscall"
                                        #:return-type long
                                        #:arg-types (list long long long
                                                          long long)
                                        #:return-errno? #t)))
    (lambda (name . args)
      (call-with-values
          (lambda ()
            (apply proc ((@@ (seccomp) syscall-number) name)
                   (append args (make-list (- 4 (length args)) 0))))
        (lambda (result errno)
          (if (< result 0) errno 0))))))

(define %clone-newuser #x10000000)
(define %af-netlink 16)
(define %af-packet 17)
(define %netlink-kobject-uevent 15)
(define %uffd-user-mode-only 1)
(define %keyctl-get-keyring-id 0)
(define %key-spec-session-keyring -3)
(define %addr-no-randomize #x0040000)
(define %personality-query #xffffffff)

(define %denied-calls
  `((unshare ,%clone-newuser)
    (clone3 0 0)
    (socket ,%af-packet ,SOCK_RAW 0)
    (socket ,(logior (ash 1 32) %af-packet) ,SOCK_RAW 0)
    (socket ,%af-netlink ,SOCK_RAW ,%netlink-kobject-uevent)
    (keyctl ,%keyctl-get-keyring-id ,%key-spec-session-keyring)
    (userfaultfd ,%uffd-user-mode-only)
    (perf_event_open 0 0 -1 -1)
    (personality ,%addr-no-randomize)))

(define %allowed-calls
  `((unshare 0)
    (socket ,AF_UNIX ,SOCK_STREAM 0)
    (socket ,AF_INET ,SOCK_STREAM 0)
    (socket ,%af-netlink ,SOCK_RAW 0)
    (personality ,%personality-query)))

(define %denied-errnos
  (list EPERM ENOSYS EAFNOSUPPORT EAFNOSUPPORT EAFNOSUPPORT EPERM EPERM EPERM
        EPERM))

(define (errnos-under-filter allowances calls)
  (in-child
   (lambda ()
     (enforce-syscall-filter! allowances)
     (map (cut apply syscall <>) calls))))

(unless (seccomp-supported?)
  (test-skip "enforce-syscall-filter! denies the groups")
  (test-skip "enforce-syscall-filter! keeps the other system calls")
  (test-skip "enforce-syscall-filter! leaves out the allowances"))

(test-assert "the denied calls give other results without the filter"
  (every (negate =)
         %denied-errnos
         (in-child (lambda ()
                     (map (cut apply syscall <>) %denied-calls)))))

(test-equal "enforce-syscall-filter! denies the groups"
  %denied-errnos
  (errnos-under-filter '() %denied-calls))

(test-equal "enforce-syscall-filter! keeps the other system calls"
  (map (const 0) %allowed-calls)
  (errnos-under-filter '() %allowed-calls))

(test-equal "enforce-syscall-filter! leaves out the allowances"
  (list 0 EPERM)
  (errnos-under-filter '(user-namespaces)
                       `((unshare ,%clone-newuser)
                         (keyctl ,%keyctl-get-keyring-id
                                 ,%key-spec-session-keyring))))

(test-equal "qemu-rules, missing file"
  '()
  (qemu-rules '("-append" "rdinit=/init")))

(test-equal "qemu-rules, server socket"
  '(("/tmp" (make-sock)))
  (map rule->list
       (qemu-rules '("-chardev" "socket,id=m,path=/tmp/qmp.sock,server=on"))))

(test-equal "qemu-rules, read-only file"
  '((read-file))
  (call-with-temporary-directory
   (lambda (directory)
     (let ((image (string-append directory "/disk.img")))
       (write-file image "")
       (map (compose cadr rule->list)
            (qemu-rules
             (list (string-append "file=" image ",readonly=on"))))))))

(test-assert "qemu-rules, client socket"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((path (unix-socket (string-append directory "/s"))))
       (equal? (map rule->list
                    (qemu-rules (list (string-append "socket,id=c,path=" path))))
               `((,path (resolve-unix))))))))

(test-assert "qemu-rules, unix: prefix"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((path (unix-socket (string-append directory "/s"))))
       (equal? (map rule->list
                    (qemu-rules (list "-qmp" (string-append "unix:" path))))
               `((,path (resolve-unix))))))))

(test-assert "qemu-rules, stale server socket"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((path (unix-socket (string-append directory "/s"))))
       (and (equal? (map rule->list
                         (qemu-rules
                          (list (string-append "socket,id=m,path=" path
                                               ",server=on"))))
                    `((,directory (make-sock))))
            (not (file-exists? path)))))))

(test-equal "waypipe-client-rules"
  '((("/run/vm" (make-sock))) (("/run/vm" (make-sock))) () ())
  (map (compose (cut map rule->list <>) waypipe-client-rules)
       '(("--socket" "/run/vm/w.sock" "--no-gpu" "client")
         ("-s" "/run/vm/w.sock" "client")
         ("--socket" "/run/vm/w.sock" "server" "--" "foot")
         ("client"))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "locked")
(exit (zero? failures))
