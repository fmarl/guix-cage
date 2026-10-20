# guix-cage
Runs the programs of Guix packages in a sandbox, so they only get the files,
sockets and ports their rules allow.

```scheme
(use-modules (gnu packages pdf)
             (guix gexp)
             (guix-cage locked))

(define-public zathura-locked
  (make-locked-package
   zathura
   (list (locked-command
           (name "zathura")
           (program (file-append zathura "/bin/zathura-sandbox"))
           (rules (list %fonts %wayland (xdg-config "zathura")
                        %argument-files))))))
```

The rules are in `(guix-cage locked)`.  A rule is a G-expression of a
procedure that takes the command line, a list of the name of the program and
its arguments, and returns a `<grant>` of `(guix-cage build locked grants)`.

The rules for files take a name below their directory and, optionally,
permissions from `(guix-cage build locked grants)`, such as
`(home-file ".local/bin/foo" '(read execute))` or
`(absolute-file "/dev/kvm" '(read write ioctl))`.

`all-rules` combines rules; `%gui` is `%wayland`, `%fonts` and `%graphics`.
`when-arguments` only applies rules if the arguments name URLs or files with
some extensions:

```scheme
(when-arguments '(urls (extensions ".m3u" ".m3u8"))
  %dns (tcp-ports 80 443))
```

Rules for single programs belong to the channels of their packages.
`define-locked-rules` defines rules for those of a build module, such as
`(my-channel build locked-rules)`:

```scheme
(define-locked-rules (my-channel build locked-rules)
  %qemu)
```
