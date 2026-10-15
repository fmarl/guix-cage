# guix-cage
Runs the programs of Guix packages under Landlock and seccomp, so they only
get the files, sockets and ports their rules allow.

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
           (rules (list %fonts (xdg-config "zathura") %argument-files))
           (wayland 'restricted)))))
```

The available rules are in `(guix-cage locked)`.  New ones come from a module
that exports `rule-kinds`, like `(guix-cage build locked virtualization)`.
