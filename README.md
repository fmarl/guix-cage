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
`define-locked-rules` defines rules for those of a build module, like
`(guix-cage build locked virtualization)`:

```scheme
(define-locked-rules (guix-cage build locked virtualization)
  %qemu
  %waypipe-client)
```

## Layers

Each layer of the sandbox enforces the grants:

1. User namespaces: only the granted files exist, and the program has its
   own processes, IPC, and network unless a rule grants ports.  tini is its
   first process.
2. Landlock: what the program may do with these files, and the ports it may
   connect to.
3. seccomp: no further namespaces, BPF, io_uring and other parts of the
   kernel that programs rarely need.

Without user namespaces, the program doesn't run.
