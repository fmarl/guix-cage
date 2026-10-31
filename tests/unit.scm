;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(include "common.scm")

(test-begin "unit")

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
  '(() #t #f ())
  (let ((command (locked-command (name "true") (program "/bin/true"))))
    (list (locked-command-rules command)
          (locked-command-own-namespaces? command)
          (locked-command-deny-write-execute? command)
          (locked-command-allowed-syscall-groups command))))

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
  (locked-command-allowed-syscall-groups
   (locked-command
     (name "true")
     (program "/bin/true")
     (allowed-syscall-groups '(user-namespaces keyring)))))

(test-rejects "locked-command rejects unknown system call groups"
  "unknown system call groups"
  (locked-command
    (name "true")
    (program "/bin/true")
    (allowed-syscall-groups '(typo))))

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
            "--talk=org.freedesktop.Flatpak.*"
            "--talk=org.freedesktop.impl.portal.desktop.wlr"
            "--talk=org.freedesktop.portal.Desktop"
            "--talk=org.freedesktop.portal.*"
            "--own=org.freedesktop.portal.Desktop"
            "--call=org.freedesktop.portal.Desktop=*"
            "--call=org.freedesktop.portal.Desktop"
            "--talk=org.mpris.*"
            "--call=org.mpris.*=org.mpris.MediaPlayer2.*"))))

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
                     "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI.*"
                     "--see=org.freedesktop.portal.Desktop"))))

(test-assert "make-locked-package only supports the supported systems"
  (let ((systems (package-supported-systems mpv-locked)))
    (and (pair? systems)
         (every (cut member <> %supported-systems) systems))))

(test-assert "check-platform! takes the supported systems"
  (begin
    (check-platform! "x86_64")
    (check-platform! "aarch64")
    #t))

(test-locked-error "check-platform! refuses 32-bit systems"
  (check-platform! "i686"))

(test-assert "the known system calls are sorted and unique"
  (let ((names (map symbol->string %known-syscalls)))
    (equal? names (sort (delete-duplicates names) string<?))))

(test-assert "libseccomp knows the known system calls"
  (let ((resolve (foreign-library-function
                  (force (@@ (seccomp) libseccomp))
                  "seccomp_syscall_resolve_name_arch"
                  #:return-type int
                  #:arg-types (list uint32 '*))))
    (every (lambda (name)
             (any (lambda (architecture)
                    (>= (resolve architecture
                                 (string->pointer (symbol->string name)))
                        0))
                  '(#xc000003e #xc00000b7)))
           %known-syscalls)))

(test-equal "make-locked-package keeps the version"
  (package-version mpv)
  (package-version mpv-locked))

(test-equal "make-locked-package names the layers of the sandbox"
  '(#t #f)
  (map (lambda (own-namespaces?)
         (let ((package (make-locked-package
                         mpv
                         (list (locked-command
                                 (name "mpv")
                                 (program (file-append mpv "/bin/mpv"))
                                 (own-namespaces? own-namespaces?))))))
           (and (string-contains (package-description package) "namespaces")
                #t)))
       '(#t #f)))

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

(define (error-report thunk)
  (match (pipe)
    ((in . out)
     (flush-all-ports)
     (match (primitive-fork)
       (0
        (close-port in)
        (dup2 (port->fdes out) 2)
        (exit-with (lambda () (exit (call-with-error-reporting thunk)))))
       (pid
        (close-port out)
        (let ((report (get-string-all in)))
          (close-port in)
          (list (status:exit-val (cdr (waitpid pid))) report)))))))

(test-assert "call-with-error-reporting reports unexpected errors"
  (match (error-report (lambda () (car (string->number "x"))))
    ((1 report)
     (string-prefix? "locked: car: Wrong type argument" report))
    (_ #f)))

(test-equal "call-with-error-reporting returns the value of the thunk"
  '(42 "")
  (error-report (const 42)))

(test-equal "run-locked needs an init program in namespaces of its own"
  1
  (run-locked guile '()))

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

(test-equal "the container grants reading /proc"
  '(("/proc" (read)))
  (accesses %container-grant))

(test-equal "base-grant without executes-others? only lets the programs run"
  (let ((true (store-program "true")))
    `(("/gnu/store" (read load))
      (,true (read execute))
      ,@(map (cut list <> '(read execute)) (elf-interpreters true))))
  (take (accesses (base-grant (list (store-program "true")) #f)) 3))

(define (landlock-options-under status)
  "Return the options that enforce-landlock! gives landlock-restrict!, which
returns STATUS."
  (let ((options #f))
    (call-with-replacement '(landlock) 'landlock-restrict!
      (lambda (rules . rest)
        (set! options rest)
        status)
      (lambda ()
        (enforce-landlock! '() 6)))
    options))

(for-each
 (lambda (status)
   (test-locked-error (format #f "enforce-landlock! refuses ~a" status)
     (landlock-options-under status)))
 '(partially-enforced not-enforced))

(test-equal "enforce-landlock! scopes signals and abstract sockets"
  '(signal abstract-unix-socket)
  (cadr (memq #:scope (landlock-options-under 'fully-enforced))))

(test-locked-error "enforce-landlock! refuses kernels below the ABI it needs"
  (call-with-replacement '(landlock) 'landlock-abi-version (const 9)
    (lambda ()
      (enforce-landlock! '() 10))))

(test-equal "container-sandbox shares the network of the host for ports"
  '((user mnt pid ipc uts cgroup net) (user mnt pid ipc uts cgroup))
  (map (lambda (grant)
         (sandbox-namespaces (container-sandbox grant '("/bin/true"))))
       (list %no-grant (grant #:ports (list (port-access 443 'tcp))))))

(test-equal "host-sandbox mounts and links nothing"
  '(() () ())
  (call-with-temporary-directory
   (lambda (directory)
     (let ((link (string-append directory "/profile")))
       (symlink (dirname (dirname guile)) link)
       (let ((sandbox (host-sandbox
                       (grant #:files (list (read-access directory)))
                       '("/bin/true")
                       #:environment
                       (list (string-append "PATH=" link "/bin")))))
         (list (sandbox-namespaces sandbox)
               (sandbox-file-systems sandbox)
               (sandbox-links sandbox)))))))

(test-assert "sandboxes refuse unknown options"
  (every (lambda (make)
           (catch 'keyword-argument-error
             (lambda () (make %no-grant '("/bin/true") #:new-sesion? #t) #f)
             (const #t)))
         (list container-sandbox host-sandbox)))

(test-locked-error "host-sandbox refuses private files"
  (host-sandbox (grant #:files (list (file-access "/dev/shm" '(read write)
                                                  #:private? #t)))
                '("/bin/true")))

(test-equal "sandboxes need Landlock ABI 10 on the network of the host"
  '(6 10 10)
  (map sandbox-landlock-abi
       (list (container-sandbox %no-grant '("/bin/true"))
             (container-sandbox (grant #:ports (list (port-access 443 'tcp)))
                                '("/bin/true"))
             (host-sandbox %no-grant '("/bin/true")))))

(test-equal "sandboxes only allow IPC in an IPC namespace of their own"
  '(#t #f)
  (map (lambda (sandbox)
         (and (memq 'ipc (sandbox-allowed-syscall-groups sandbox)) #t))
       (list (container-sandbox %no-grant '("/bin/true"))
             (host-sandbox %no-grant '("/bin/true")))))

(test-locked-error "user namespaces rule out deny-write-execute?"
  (container-sandbox %no-grant '("/bin/true")
                     #:allowed-syscall-groups '(user-namespaces)
                     #:deny-write-execute? #t))

(test-equal "sandboxes pass on the signals of the terminal in a new session"
  (list (list SIGTERM) (list SIGINT SIGQUIT SIGTERM SIGHUP))
  (map (lambda (new-session?)
         (sandbox-signals (container-sandbox %no-grant '("/bin/true")
                                             #:new-session? new-session?)))
       '(#f #t)))

(test-equal "sandboxes keep the standard descriptors and those of the grant"
  '(0 1 2 7)
  (sandbox-fds (container-sandbox (grant #:fds '(7)) '("/bin/true"))))

(test-assert "container-sandbox adds the links into the store"
  (call-with-temporary-directory
   (lambda (directory)
     (let ((link (string-append directory "/profile")))
       (symlink (dirname (dirname guile)) link)
       (equal? `(("/run/locked/true" . "/bin/true")
                 (,link . ,(dirname (dirname guile))))
               (sandbox-links
                (container-sandbox
                 %no-grant '("/bin/true")
                 #:environment (list (string-append "PATH=" link "/bin"))
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

(test-equal "%shm grants a private /dev/shm"
  '(("/dev/shm" "tmpfs" (no-suid no-dev)))
  (map (lambda (file-system)
         (list (file-system-mount-point file-system)
               (file-system-type file-system)
               (file-system-flags file-system)))
       (file-systems (granted build:%shm))))

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

(test-locked-error "restrict! reports seccomp errors"
  (call-with-replacement '(seccomp) 'seccomp-restrict!
    (lambda _
      (seccomp-rule 'getpid 'deny))
    (lambda ()
      (restrict! '() '()))))

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

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "unit")
(exit (zero? failures))
