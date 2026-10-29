# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

GUIX := guix time-machine -C $(CURDIR)/channels-lock.scm --
PACKAGES := -e '(@ (guix-cage packages guile-xyz) guile-landlock)' \
    -e '(@ (guix-cage packages guile-xyz) guile-seccomp)'
MODULES := $(shell find modules -name '*.scm' | sort)

export GUILE_LOAD_PATH := $(CURDIR)/modules$(if $(GUILE_LOAD_PATH),:$(GUILE_LOAD_PATH))

# Runs a script with the Guile modules of PACKAGES
repl = paths=$$($(GUIX) build -L $(CURDIR)/modules $(PACKAGES)) && \
	$(GUIX) repl $$(printf -- '-L %s/share/guile/site/3.0 ' $$paths) -- $(1)

.PHONY: check known-syscalls lint test test-unit test-kernel warnings update

check: warnings lint test

warnings:
	$(call repl,etc/check-warnings.scm $(MODULES))

test: test-unit test-kernel

test-unit:
	$(call repl,tests/unit.scm)

test-kernel:
	$(call repl,tests/kernel.scm)

lint:
	! $(GUIX) lint -L $(CURDIR)/modules --no-network $(PACKAGES) 2>&1 \
	    | grep -v '^;;;' | grep .

update:
	guix time-machine -C channels.scm -- \
	    describe -f channels > channels-lock.scm.new
	mv channels-lock.scm.new channels-lock.scm

known-syscalls:
	libseccomp=$$($(GUIX) build libseccomp) && \
	guile --no-auto-compile etc/known-syscalls.scm \
	    $$libseccomp/lib/libseccomp.so \
	    > modules/guix-cage/build/locked/known-syscalls.scm
