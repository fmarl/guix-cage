;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(use-modules (gnu packages video)
             (guix build utils)
             ((guix diagnostics) #:select (formatted-message?
                                           formatted-message-string
                                           formatted-message-arguments))
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
             (guix-cage build locked grants)
             ((gnu build linux-container)
              #:select (unprivileged-user-namespace-supported?))
             ((gnu system file-systems) #:select (file-system-mount-point
                                                  file-system-type
                                                  file-system-flags))
             ((guix-cage build locked gnupg) #:prefix build:)
             ((guix-cage build locked rules) #:prefix build:)
             (guix-cage locked)
             (srfi srfi-1)
             (srfi srfi-26)
             (srfi srfi-34)
             (srfi srfi-64)
             (system foreign)
             (system foreign-library))

(define mpv-locked
  (make-locked-package
   mpv
   (list (locked-command
           (name "mpv")
           (program (file-append mpv "/bin/mpv"))))))

(define-syntax-rule (define-internal module name ...)
  (begin (define name (@@ module name)) ...))

(define (access->list access)
  (if (file-access? access)
      (list (file-access-file access) (file-access-permissions access))
      (list (port-access-port access) (port-access-protocol access))))

(define (call-with-environment-variables variables thunk)
  "Call THUNK with VARIABLES, an alist where #f unsets a variable."
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
                    ((name . value) (setenv name value)))
                  saved)))))

(define (call-with-replacement module name replacement thunk)
  "Call THUNK while NAME in MODULE is REPLACEMENT."
  (let* ((module (resolve-module module))
         (original (module-ref module name)))
    (dynamic-wind
      (lambda () (module-set! module name replacement))
      thunk
      (lambda () (module-set! module name original)))))

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

(define (call-with-sandbox-home proc)
  "Call PROC with a temporary home and runtime directory."
  (call-with-temporary-directory
   (lambda (directory)
     (let ((home (string-append directory "/home"))
           (runtime (string-append directory "/run")))
       (mkdir-p home)
       (mkdir-p runtime)
       (call-with-environment-variables
        `(("HOME" . ,home)
          ("XDG_RUNTIME_DIR" . ,runtime)
          ("XDG_CONFIG_HOME" . ,(string-append home "/.config")))
        (lambda ()
          (proc home runtime)))))))

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

(define (readable? file)
  (and (false-if-exception (call-with-input-file file get-string-all)) #t))

(define (write-file file content)
  (mkdir-p (dirname file))
  (call-with-output-file file (cut display content <>)))

(define (store-program name)
  (canonicalize-path (search-path (parse-path (getenv "PATH")) name)))

(define guile (store-program "guile"))
(define tini (store-program "tini"))

(define (feature-available? available? feature)
  "Return AVAILABLE?.  Report FEATURE if it is missing, and fail unless
LOCKED_TESTS_ALLOW_SKIP is set."
  (unless available?
    (format (current-error-port) "missing kernel feature: ~a~%" feature)
    (unless (getenv "LOCKED_TESTS_ALLOW_SKIP")
      (exit 1)))
  available?)

(define-syntax-rule (test-rejects name message expression)
  (test-assert name
    (guard (exception ((formatted-message? exception)
                       (string-contains
                        (apply format #f
                               (formatted-message-string exception)
                               (formatted-message-arguments exception))
                        message)))
      expression
      #f)))

(define-syntax-rule (test-locked-error name expression)
  (test-assert name
    (guard (exception ((locked-error? exception) #t))
      expression
      #f)))

(define-internal (guix-cage build locked)
  run-locked)
(define-internal (guix-cage build locked errors)
  locked-error?)
(define-internal (guix-cage build locked file-names)
  directory-contains?)
(define-internal (guix-cage build locked instances)
  make-instance-directory delete-beneath)
(define-internal (guix-cage build locked landlock)
  landlock-rules enforce-landlock!)
(define-internal (guix-cage build locked namespaces)
  %container-grant file-systems store-links)
(define-internal (guix-cage build locked sandbox)
  sandbox sandbox-namespaces sandbox-links sandbox-signals sandbox-fds)
(define-internal (guix-cage build locked process)
  close-on-exec-except deny-write-execute! apply-resource-limits!)
(define-internal (guix-cage build locked syscalls)
  enforce-syscall-filter! restrict!)
(define-internal (guix-cage build locked rules)
  base-grant elf-interpreters user-directory argument-file arguments-match?)
(define-internal (guix-cage build locked wayland)
  wayland-string wayland-string-ref wayland-message)
(define-internal (guix-cage build locked-package)
  install-locked-package)

(define (granted rule . arguments)
  "Return what RULE grants for ARGUMENTS."
  (rule (cons "test" arguments)))

(define (accesses grant)
  (map access->list (append (grant-files grant) (grant-ports grant))))

(define (restrict-to! grant)
  (landlock-restrict! (landlock-rules grant)))

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

(define (rule-sexp rule)
  "Return the code of RULE, with that of the G-expressions in it."
  (let expand ((code (gexp->approximate-sexp rule)))
    (cond ((gexp? code) (rule-sexp code))
          ((pair? code) (cons (expand (car code)) (expand (cdr code))))
          (else code))))

(test-equal "rules apply the build rules"
  '((@ (guix-cage build locked rules) xdg-config) '"foo")
  (rule-sexp (xdg-config "foo")))

(test-equal "rules take optional permissions"
  '((@ (guix-cage build locked rules) home-file) '"bin/foo" '(read execute))
  (rule-sexp (home-file "bin/foo" '(read execute))))

(test-equal "rules nest in when-arguments"
  '((@ (guix-cage build locked rules) when-arguments)
    '(urls (extensions ".m3u"))
    (@ (guix-cage build locked rules) %dns)
    ((@ (guix-cage build locked rules) tcp-ports) '80 '443))
  (rule-sexp
   (when-arguments '(urls (extensions ".m3u")) %dns (tcp-ports 80 443))))

(test-assert "rules import their build modules"
  (every (cut member <> (gexp-modules (all-rules %gnupg %wayland)))
         '((guix-cage build locked rules)
           (guix-cage build locked gnupg)
           (guix-cage build locked wayland))))

(test-equal "rules import the build modules of other channels"
  '(#t #t #f)
  (map (@@ (guix-cage locked) build-module?)
       '((guix-microvm build locked-rules) (guix build utils) (guix-cage locked))))

(test-equal "default resource limits forbid core dumps and priorities"
  '((core . 0) (rtprio . 0) (nice . 0))
  %default-resource-limits)

(for-each
 (lambda (variable)
   (test-assert (string-append "default environment drops " variable)
     (not (preserved-variable? variable
                               %default-preserved-environment-variables))))
 '("SSH_AUTH_SOCK" "DBUS_SESSION_BUS_ADDRESS" "DISPLAY" "XAUTHORITY"
   "WAYLAND_SOCKET" "LD_PRELOAD" "LD_LIBRARY_PATH" "GNUPGHOME"
   "GPG_AGENT_INFO" "GITHUB_TOKEN"))

(test-equal "locked-command defaults are closed"
  '(() #f ())
  (let ((command (locked-command (name "true") (program "/bin/true"))))
    (list (locked-command-rules command)
          (locked-command-deny-write-execute? command)
          (locked-command-syscall-allowances command))))

(define (command-with-limits limits)
  (locked-command
    (name "true")
    (program "/bin/true")
    (resource-limits limits)))

(test-rejects "locked-command rejects unknown resources"
  "invalid resource limits" (command-with-limits '((cores . 0))))

(test-rejects "locked-command rejects negative resource limits"
  "invalid resource limits" (command-with-limits '((nofile . -1))))

(test-rejects "locked-command rejects non-integer resource limits"
  "invalid resource limits" (command-with-limits '((nofile . "1"))))

(test-equal "locked-command takes valid resource limits"
  '((nofile . 1024) (as . #f))
  (locked-command-resource-limits
   (command-with-limits '((nofile . 1024) (as . #f)))))

(test-equal "locked-command takes system call groups"
  '(user-namespaces keyring)
  (locked-command-syscall-allowances
   (locked-command
     (name "true")
     (program "/bin/true")
     (syscall-allowances '(user-namespaces keyring)))))

(test-rejects "locked-command rejects unknown system call groups"
  "unknown system call groups"
  (locked-command
    (name "true")
    (program "/bin/true")
    (syscall-allowances '(typo))))

(test-rejects "locked-command rejects rules that aren't G-expressions"
  "rule is not a G-expression"
  (locked-command
    (name "true")
    (program "/bin/true")
    (rules (list "/home"))))

(test-rejects "when-arguments rejects rules that aren't G-expressions"
  "rule is not a G-expression"
  (when-arguments '(urls) "/home"))

(test-rejects "all-rules rejects rules that aren't G-expressions"
  "rule is not a G-expression"
  (all-rules %dns "/home"))

(test-rejects "define-locked-rules rejects unknown rules"
  "defines no rule"
  (eval '(define-locked-rules (guix-cage build locked rules) %typo)
        (let ((module (make-fresh-user-module)))
          (module-use! module (resolve-interface '(guix-cage locked)))
          module)))

(for-each
 (match-lambda
   ((name . make-rule)
    (test-rejects (string-append "rules reject " name)
      "invalid parameters" (make-rule))))
 `(("an empty name" . ,(lambda () (xdg-config "")))
   ("the parent directory" . ,(lambda () (xdg-cache "..")))
   ("names leading out" . ,(lambda () (home-file "../x")))
   ("names with dot components" . ,(lambda () (xdg-config "a/./b")))
   ("absolute names" . ,(lambda () (xdg-state "/etc")))
   ("user directories leading out"
    . ,(lambda () (xdg-user-directory "DOWNLOAD" "../x")))
   ("unknown user directories"
    . ,(lambda () (xdg-user-directory "DOWNLOAD\"" "Downloads")))
   ("relative files" . ,(lambda () (absolute-file "etc")))
   ("files leading out" . ,(lambda () (absolute-file "/tmp/../etc")))
   ("unknown permissions" . ,(lambda () (xdg-config "foo" '(fly))))
   ("no permissions" . ,(lambda () (home-file ".foorc" '())))
   ("permissions that aren't lists"
    . ,(lambda () (absolute-file "/dev/kvm" 'read)))
   ("ports beyond 65535" . ,(lambda () (tcp-ports 443 65536)))
   ("ports that aren't numbers" . ,(lambda () (tcp-ports "443")))
   ("no matchers" . ,(lambda () (when-arguments '() %dns)))
   ("unknown matchers" . ,(lambda () (when-arguments '(files) %dns)))
   ("extensions that aren't strings"
    . ,(lambda () (when-arguments '((extensions m3u)) %dns)))
   ("no extensions" . ,(lambda () (when-arguments '((extensions)) %dns)))
   ("malformed D-Bus policies"
    . ,(lambda () (dbus "talk=org.freedesktop.Notifications")))
   ,@(map (lambda (option)
            (cons (string-append "D-Bus policies with " option)
                  (lambda () (dbus option))))
          '("--talk=org.freedesktop.secrets" "--talk=org.freedesktop.*"
            "--own=*" "--call=ca.desrt.dconf=*"
            "--see=org.freedesktop.systemd1.Manager"
            "--talk=org.freedesktop.Flatpak.*"))))

(test-assert "rules take valid parameters"
  (every gexp?
         (list (xdg-config "foo/bar.conf") (xdg-cache "foo")
               (xdg-state "foo" '(read))
               (home-file ".foorc") (home-file ".local/bin/foo" '(read execute))
               (xdg-user-directory "DOWNLOAD" "Downloads")
               (absolute-file "/") (absolute-file "/srv/data" '(read write))
               (absolute-file "/dev/kvm" '(read write ioctl))
               (tcp-ports 80 443) (all-rules) %gui
               (when-arguments '(urls (extensions ".m3u")) %dns)
               (dbus "--talk=org.freedesktop.Notifications"
                     "--own=org.mpris.MediaPlayer2.mpv.*"
                     "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI.*"))))

(test-assert "make-locked-package only supports Linux"
  (let ((systems (package-supported-systems mpv-locked)))
    (and (pair? systems)
         (every (cut string-suffix? "-linux" <>) systems))))

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
          '("$HOME/" "$HOME" "$HOMEfoo" "$HOME/../" "/" "relative"
            "$HOME/.config" "$HOME/.ssh" "$HOME/.local" "$HOME/.gnupg"
            "$HOME/Downloads/.hidden" "/run/user/1000" "/gnu/store" "/etc"
            "/sys"))

(test-assert "user-directory, rejects the home directory without XDG variables"
  (call-with-temporary-directory
   (lambda (home)
     (write-file (string-append home "/.config/user-dirs.dirs")
                 "XDG_DOWNLOAD_DIR=\"$HOME\"\n")
     (call-with-environment-variables
      (cons `("HOME" . ,home)
            (map (cut cons <> #f)
                 '("XDG_CONFIG_HOME" "XDG_CACHE_HOME" "XDG_STATE_HOME"
                   "XDG_DATA_HOME" "XDG_RUNTIME_DIR" "GNUPGHOME")))
      (lambda ()
        (not (user-directory "DOWNLOAD" "Downloads")))))))

(test-equal "user-directory, rejects the directories of XDG variables"
  '(#f "/data/downloads")
  (call-with-environment-variables '(("XDG_DATA_HOME" . "/data/share"))
    (lambda ()
      (map (lambda (value)
             (user-directory-with
              (string-append "XDG_DOWNLOAD_DIR=\"" value "\"\n")))
           '("/data" "/data/downloads")))))

(test-equal "argument-file"
  '("film.mkv" "/film.mkv" "list.m3u" #f #f)
  (map argument-file
       '("film.mkv" "file:///film.mkv" "--playlist=list.m3u" "-v"
         "--volume")))

(test-assert "arguments-match?, local files"
  (not (arguments-match? '("film.mkv" "file:///film.mkv" "-v") '(urls))))

(test-assert "arguments-match?, URL"
  (arguments-match? '("https://example.org/film.mkv") '(urls)))

(test-assert "arguments-match?, extension"
  (arguments-match? '("--playlist=list.M3U8") '((extensions ".m3u8"))))

(test-assert "arguments-match?, extension of a file:// URI"
  (arguments-match? '("file:///list.m3u") '(urls (extensions ".m3u"))))

(test-assert "arguments-match?, extensions not given"
  (not (arguments-match? '("list.m3u8") '(urls))))

(test-assert "arguments-match?, URL in an option"
  (not (arguments-match? '("--script-opts=x=https://example.org") '(urls))))

(test-equal "tcp-ports"
  '((143 tcp) (993 tcp))
  (accesses (granted (build:tcp-ports 143 993))))

(test-equal "all-rules"
  '(("/bin/sh" (read execute)) (143 tcp))
  (accesses (granted (build:all-rules (build:tcp-ports 143) build:%shell))))

(test-equal "when-arguments"
  '(() ((443 tcp)) ((443 tcp)))
  (map (lambda (argument)
         (accesses (granted (build:when-arguments
                             '(urls (extensions ".m3u"))
                             (build:tcp-ports 443))
                            argument)))
       '("film.mkv" "https://example.org" "list.m3u")))

(test-equal "file rules grant their permissions"
  `((,(string-append (getenv "HOME") "/.local/bin/foo") (read execute))
    ("/dev/kvm" (read write ioctl))
    ("/srv/data" (read)))
  (append-map (lambda (rule)
                (accesses (granted rule)))
              (list (build:home-file ".local/bin/foo" '(read execute))
                    (build:absolute-file "/dev/kvm" '(read write ioctl))
                    (build:absolute-file "/srv/data"))))

(test-equal "xdg-state only creates its directory to write it"
  '(#f #t)
  (call-with-temporary-directory
   (lambda (directory)
     (call-with-environment-variables `(("XDG_STATE_HOME" . ,directory))
       (lambda ()
         (map (lambda (name permissions)
                (granted (build:xdg-state name permissions))
                (file-exists? (string-append directory "/" name)))
              '("read" "write")
              '((read) (read write))))))))

(test-equal "%shell grants executing /bin/sh"
  '(("/bin/sh" (read execute)))
  (accesses (granted build:%shell)))

(test-assert "%shared-temporary-directory is a directory of the host"
  (call-with-runtime-directory
   (lambda (runtime)
     (let* ((grant (granted build:%shared-temporary-directory))
            (directory (assoc-ref (grant-variables grant) "TMPDIR")))
       (and (file-exists? directory)
            (string-prefix? runtime directory)
            (equal? `((,directory (read write))) (accesses grant)))))))

(test-locked-error "build rules reject invalid parameters"
  (build:home-file ".."))

(test-assert "argument-files only grants regular files"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((film (string-append directory "/film.mkv"))
           (playlist (string-append directory "/list.m3u"))
           (link (string-append directory "/link"))
           (directory-link (string-append directory "/directory-link")))
       (write-file film "")
       (write-file playlist "")
       (symlink film link)
       (symlink directory directory-link)
       (equal? (accesses
                    (granted build:%argument-files
                             "--verbose" film
                             (string-append "--playlist=" playlist)
                             "/nonexistent" link directory-link directory
                             "/dev/null"))
               `((,film (read))
                 (,playlist (read))))))))

(test-equal "argument-files rules grant reading the files"
  '(#t #f)
  (call-with-temporary-directory
   (lambda (directory)
     (let ((film (string-append directory "/film.mkv"))
           (other (string-append directory "/other.mkv")))
       (write-file film "film")
       (write-file other "other")
       (in-child
        (lambda ()
          (restrict-to! (granted build:%argument-files film))
          (map readable? (list film other))))))))

(define (call-with-gnupg-home proc)
  "Call PROC with a runtime directory and a non-default GnuPG home."
  (call-with-runtime-directory
   (lambda (runtime)
     (call-with-temporary-directory
      (lambda (home)
        (call-with-environment-variables `(("GNUPGHOME" . ,home))
          (lambda ()
            (proc runtime home))))))))

(test-equal "gnupg rules grant the public keyring, but not the secret keys"
  '((#t #t) (#t #f))
  (call-with-gnupg-home
   (lambda (runtime home)
     (let ((public (string-append home "/pubring.kbx"))
           (secret (string-append home "/private-keys-v1.d/x.key")))
       (write-file public "public")
       (write-file secret "secret")
       (map (lambda (locked?)
              (in-child
               (lambda ()
                 (when locked?
                   (restrict-to! (granted build:%gnupg)))
                 (map readable?
                      (list (string-append (getenv "GNUPGHOME")
                                           "/pubring.kbx")
                            secret)))))
            '(#f #t))))))

(test-equal "gnupg rules only reach the restricted socket of gpg-agent"
  '((#t #t #t) (#t #f #f))
  (call-with-gnupg-home
   (lambda (runtime home)
     (let* ((sockets (map (cut string-append home "/" <>)
                          '("S.gpg-agent.extra" "S.gpg-agent"
                            "S.gpg-agent.ssh")))
            (listeners (map listening-socket sockets))
            (result (map (lambda (locked?)
                           (in-child
                            (lambda ()
                              (when locked?
                                (restrict-to! (granted build:%gnupg)))
                              (map can-connect? sockets))))
                         '(#f #t))))
       (for-each close-port listeners)
       result))))

(test-assert "gnupg grant leads gpg to the restricted socket of gpg-agent"
  (call-with-gnupg-home
   (lambda (runtime home)
     (let ((socket (unix-socket (string-append home "/S.gpg-agent.extra"))))
       (write-file (string-append home "/pubring.kbx") "")
       (let* ((variables (call-with-environment-variables
                             '(("GPG_TTY" . "/dev/pts/1"))
                           (lambda ()
                             (grant-variables (build:%gnupg '("test"))))))
              (private (assoc-ref variables "GNUPGHOME")))
         (and (not (string=? private home))
              (equal? "/dev/pts/1" (assoc-ref variables "GPG_TTY"))
              (string=? (string-append home "/pubring.kbx")
                        (readlink (string-append private "/pubring.kbx")))
              (string=? (string-append "%Assuan%\nsocket=" socket "\n")
                        (call-with-input-file
                            (string-append private "/S.gpg-agent")
                          get-string-all))))))))

(test-assert "gnupg rules hold none of the default GnuPG directories"
  (call-with-sandbox-home
   (lambda (home runtime)
     (call-with-environment-variables '(("GNUPGHOME" . #f))
       (lambda ()
         (let ((secret (string-append home "/.gnupg/private-keys-v1.d"))
               (ssh (string-append runtime "/gnupg/S.gpg-agent.ssh"))
               (extra (string-append runtime "/gnupg/S.gpg-agent.extra")))
           (mkdir-p secret)
           (mkdir-p (dirname ssh))
           (write-file (string-append home "/.gnupg/pubring.kbx") "")
           (unix-socket ssh)
           (unix-socket extra)
           (let ((files (map first (accesses (granted build:%gnupg)))))
             (and (member extra files)
                  (not (any (lambda (file)
                              (or (directory-contains? file secret)
                                  (directory-contains? file ssh)))
                            files))))))))))


(test-equal "wayland-string pads to 32 bits"
  '(5 #vu8(119 112 95 120 0 0 0 0))
  (let ((bytes (wayland-string "wp_x")))
    (list (bytevector-u32-native-ref bytes 0)
          (let ((rest (make-bytevector 8)))
            (bytevector-copy! bytes 4 rest 0 8)
            rest))))

(define (wayland-bytes size content)
  "Return a Wayland string of SIZE with CONTENT, a bytevector."
  (let ((bytes (make-bytevector (+ 4 (bytevector-length content)) 0)))
    (bytevector-u32-native-set! bytes 0 size)
    (bytevector-copy! content 0 bytes 4 (bytevector-length content))
    bytes))

(test-equal "wayland-string-ref"
  "wp_x"
  (wayland-string-ref (wayland-bytes 5 #vu8(119 112 95 120 0 0 0 0)) 0))

(test-locked-error "wayland-string-ref rejects null strings"
  (wayland-string-ref (wayland-bytes 0 #vu8()) 0))

(test-locked-error "wayland-string-ref rejects strings beyond the message"
  (wayland-string-ref (wayland-bytes 9 #vu8(119 112 95 120 0 0 0 0)) 0))

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

(test-equal "program-environment"
  '("LC_OTHER=granted" "LC_TEST=C" "TMPDIR=/tmp")
  (call-with-environment-variables '(("LC_TEST" . "C")
                                     ("LC_OTHER" . "host")
                                     ("SECRET_TOKEN" . "x"))
    (lambda ()
      (sort (filter (lambda (entry)
                      (any (cut string-prefix? <> entry)
                           '("LC_TEST" "LC_OTHER" "SECRET" "TMPDIR")))
                    (program-environment '("LC_*")
                                   '(("LC_OTHER" . "x")
                                     ("TMPDIR" . "/tmp")
                                     ("LC_OTHER" . "granted"))))
            string<?))))

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

(test-assert "make-instance-directory doesn't follow symbolic links"
  (call-with-runtime-directory
   (lambda (runtime)
     (call-with-temporary-directory
      (lambda (outside)
        (let ((stale (format #f "~a/locked/tmp/~a" runtime (dead-pid)))
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

(test-assert "socket-grant"
  (call-with-temporary-directory
   (lambda (directory)
     (let* ((socket (unix-socket (string-append directory "/s")))
            (shared (socket-grant socket
                                   (lambda (socket) `(("SOCKET" . ,socket)))))
            (missing (socket-grant (string-append directory "/missing")
                                    (const '(("SOCKET" . "x"))))))
       (equal? (list (accesses shared)
                     (grant-variables shared)
                     (accesses missing)
                     (grant-variables missing))
               `(((,socket (connect))) (("SOCKET" . ,socket)) () ()))))))

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
           #:fs '(resolve-unix) #:net '() #:best-effort? #f)
          (map can-connect?
               (list (string-append directory "/granted")
                     (string-append directory "/other")))))))))

(define (exit-with thunk)
  "Call THUNK in this child process, and exit as it asks, or with 127 if it
fails."
  (catch #t
    thunk
    (match-lambda*
      (('quit (? integer? status)) (primitive-_exit status))
      (_ (primitive-_exit 127)))))

(define (exit-status-of thunk)
  "Return the exit status of a child process that calls THUNK."
  (flush-all-ports)
  (match (primitive-fork)
    (0 (exit-with thunk))
    (pid (status:exit-val (cdr (waitpid pid))))))

(define (exit-status-under rules command)
  (exit-status-of (lambda ()
                    (landlock-restrict! rules)
                    (apply execl (car command) command))))

(test-assert "elf-interpreters finds the dynamic loader"
  (match (elf-interpreters (store-program "true"))
    ((loader) (string-contains loader "/ld-"))
    (_ #f)))

(test-locked-error "elf-interpreters rejects scripts"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((script (string-append directory "/script")))
       (write-file script "#!/bin/sh\n")
       (elf-interpreters script)))))

(test-equal "base-grant grants the store and /etc"
  '(("/gnu/store" (read execute))
    ("/etc" (read)))
  (accesses (base-grant (list (store-program "true")) #t)))

(test-equal "the container grants /proc, /dev/null and /dev/urandom"
  '(("/proc" (read))
    ("/dev/null" (read write))
    ("/dev/urandom" (read)))
  (accesses %container-grant))

(test-equal "base-grant without executes? only grants executing the programs"
  (let ((true (store-program "true")))
    `(("/gnu/store" (read load))
      (,true (read execute))
      ,@(map (cut list <> '(read execute)) (elf-interpreters true))))
  (take (accesses (base-grant (list (store-program "true")) #f)) 3))

(test-equal "without executes?, the program only runs itself"
  '(0 126)
  (let ((sh (store-program "sh"))
        (true (store-program "true")))
    (map (lambda (executes?)
           (exit-status-under (landlock-rules (base-grant (list sh) executes?))
                              (list sh "-c" (string-append true "; exit $?"))))
         '(#t #f))))

(define (landlock-options-under status)
  "Return the options that enforce-landlock! gives landlock-restrict!, which
returns STATUS."
  (let ((options #f))
    (call-with-replacement '(landlock) 'landlock-restrict!
      (lambda (rules . rest)
        (set! options rest)
        status)
      (lambda ()
        (enforce-landlock! '())))
    options))

(for-each
 (lambda (status)
   (test-locked-error (format #f "enforce-landlock! refuses ~a" status)
     (landlock-options-under status)))
 '(partially-enforced not-enforced))

(test-equal "enforce-landlock! scopes signals and abstract sockets"
  '(signal abstract-unix-socket)
  (cadr (memq #:scope (landlock-options-under 'fully-enforced))))

(test-equal "sandbox only shares the network of the host for ports"
  '((user mnt pid ipc uts cgroup net) (user mnt pid ipc uts cgroup))
  (map (lambda (grant)
         (sandbox-namespaces (sandbox grant '("/bin/true"))))
       (list %no-grant (grant #:ports (list (port-access 443 'tcp))))))

(test-equal "sandbox passes on the signals of the terminal if detached"
  (list (list SIGTERM) (list SIGINT SIGQUIT SIGTERM SIGHUP))
  (map (lambda (detached?)
         (sandbox-signals (sandbox %no-grant '("/bin/true")
                                   #:detached? detached?)))
       '(#f #t)))

(test-equal "sandbox keeps the standard descriptors and those of the grant"
  '(0 1 2 7)
  (sandbox-fds (sandbox (grant #:fds '(7)) '("/bin/true"))))

(test-assert "sandbox adds the links into the store"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((link (string-append directory "/profile")))
       (symlink (dirname (dirname guile)) link)
       (equal? `(("/run/locked/true" . "/bin/true")
                 (,link . ,(dirname (dirname guile))))
               (sandbox-links
                (sandbox %no-grant '("/bin/true")
                         #:environment
                         (list (string-append "PATH=" link "/bin"))
                         #:links '(("/run/locked/true" . "/bin/true")))))))))

(test-assert "file-systems show the granted files"
  (call-with-temporary-directory
   (lambda (directory)
     (mkdir (string-append directory "/dev"))
     (equal?
      `(("/etc" "none" (bind-mount no-suid read-only no-exec no-dev))
        ("/tmp/x" "tmpfs" (no-suid no-dev))
        ("/gnu/store" "none" (bind-mount no-suid read-only no-dev))
        (,directory "none" (bind-mount no-suid no-exec no-dev))
        (,(string-append directory "/dev") "none"
         (bind-mount no-suid no-exec)))
      (map (lambda (file-system)
            (list (file-system-mount-point file-system)
                  (file-system-type file-system)
                  (file-system-flags file-system)))
          (file-systems
           (grant #:files
                  (list (file-access (string-append directory "/dev")
                                     '(read write ioctl))
                        (file-access directory '(read))
                        (file-access directory '(write))
                        (file-access "/gnu/store" '(read execute))
                        (file-access "/etc" '(read))
                        (file-access "/tmp/x" '(read write) #:private? #t)
                        (file-access "/dev/null" '(read write))
                        (file-access "/proc" '(read))
                        (file-access "/dev/dri" '(list))
                        (file-access "/nonexistent" '(read))))))))))

(test-assert "store-links finds the links into the store"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((link (string-append directory "/profile"))
           (target (dirname (dirname guile))))
       (symlink target link)
       (equal? (store-links
                (list (string-append "PATH=" link "/bin:/nonexistent:relative")
                      (string-append "HOME=" directory)))
               `((,link . ,target)))))))

(for-each
 (lambda (status)
   (test-locked-error (format #f "restrict! refuses ~a" status)
     (call-with-replacement '(seccomp) 'seccomp-restrict!
       (const status)
       (lambda ()
         (restrict! '() '())))))
 '(partially-enforced not-enforced))

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
       (entry "applications/none.desktop")
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

(test-equal "install-locked-package leaves out other ways to the programs"
  '("Exec=OUT/bin/foo %i %o" #f #t #t #f)
  (call-with-temporary-directory
   (lambda (directory)
     (let ((original (string-append directory "/original"))
           (output (string-append directory "/out")))
       (define (share file)
         (string-append "/share/" file))

       (write-file (string-append original (share "thumbnailers/foo.thumbnailer"))
                   (string-append "Exec=" original "/bin/foo %i %o"))
       (write-file (string-append original (share "foo/helper.el"))
                   (string-append "(start \"" original "/libexec/helper\")"))
       (write-file (string-append original (share "foo/data"))
                   (string-append (string #\nul) original "/share/foo/data"))
       (write-file (string-append original (share "doc/README")) "")
       (write-file (string-append original (share "foo/other"))
                   (string-append original "/bin/bar"))
       (install-locked-package original output '(("foo" . "/wrapper/foo")))
       (list (string-replace-substring
              (call-with-input-file
                  (string-append output (share "thumbnailers/foo.thumbnailer"))
                get-string-all)
              output "OUT")
             (file-exists? (string-append output (share "foo/helper.el")))
             (file-exists? (string-append output (share "foo/data")))
             (eq? 'symlink
                  (stat:type (lstat (string-append output (share "doc")))))
             (file-exists? (string-append output (share "foo/other"))))))))

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
    ((personality ,%addr-no-randomize) ,EPERM)))

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

(define (errnos-under-filter allowances calls)
  (in-child
   (lambda ()
     (when allowances
       (enforce-syscall-filter! allowances))
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

  (test-equal "enforce-syscall-filter! leaves out the allowances"
    (list 0 EPERM 0)
    (errnos-under-filter '(user-namespaces socket-protocols)
                         `((unshare ,%clone-newuser)
                           (keyctl ,%keyctl-get-keyring-id
                                   ,%key-spec-session-keyring)
                           (socket ,AF_INET ,SOCK_DGRAM ,%ipproto-icmp)))))
(define (guile-script expression)
  (object->string `(exit (if ,expression 42 43))))

(define (guile-status expression)
  "Return 42 if Guile finds EXPRESSION true, and 43 otherwise."
  (exit-status-of (lambda ()
                    (execl guile "guile" "-c" (guile-script expression)))))

(define* (locked-guile-status expression #:optional (rules '())
                              #:key (executes? #t))
  "Return 42 if Guile finds EXPRESSION true under run-locked with RULES, and
43 otherwise."
  (exit-status-of (lambda ()
                    (set-program-arguments
                     (list "guile" "-c" (guile-script expression)))
                    (run-locked guile rules #:init tini
                                #:executes? executes?))))

(define* (test-locked name expression #:optional (rules '()))
  "Test that EXPRESSION is only true outside of run-locked with RULES."
  (test-equal name
    '(42 43)
    (list (guile-status expression)
          (locked-guile-status expression rules))))

(unless (and (feature-available? (seccomp-supported?) "seccomp")
             (feature-available? (>= (landlock-abi-version) 6)
                                 "Landlock ABI 6, for scopes")
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

  (test-equal "run-locked without executes? runs the program, but no others"
    '(42 43)
    (map (lambda (expression)
           (locked-guile-status expression '() #:executes? #f))
         (list #t `(false-if-exception (zero? (system* ,(store-program "true")))))))

  (test-locked "run-locked keeps the program from signalling others"
    `(false-if-exception (begin (kill ,(getpid) 0) #t)))

  (test-locked "run-locked only shows the processes of the sandbox"
    `(file-exists? ,(string-append "/proc/" (number->string (getpid)))))

  (test-equal "run-locked passes signals on"
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
             (run-locked guile '() #:init tini))))
         (pid
          (close-port out)
          ;; The program is running once it is ready
          (read in)
          (kill pid SIGTERM)
          (status:exit-val (cdr (waitpid pid)))))))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "locked")
(exit (zero? failures))
