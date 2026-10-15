;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked kinds)
  #:use-module (ice-9 match)
  #:use-module (guix-cage build locked errors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:export (rule-kind
            rule-kind?
            rule-kind-rules
            rule-kind-variables
            conditional-rule-kind
            conditional-rule-kind?
            conditional-rule-kind-condition
            kind-name
            module-rule-kind-names
            module-rule-kind))

(define-record-type <rule-kind>
  (make-rule-kind name rules variables)
  rule-kind?
  (name      rule-kind-name)
  (rules     rule-kind-rules)
  (variables rule-kind-variables))

(define* (rule-kind name rules #:key (variables '()))
  (make-rule-kind name rules variables))

(define-record-type <conditional-rule-kind>
  (conditional-rule-kind name condition)
  conditional-rule-kind?
  (name      conditional-rule-kind-name)
  (condition conditional-rule-kind-condition))

(define (kind-name kind)
  (match kind
    ((? rule-kind?) (rule-kind-name kind))
    ((? conditional-rule-kind?) (conditional-rule-kind-name kind))))

(define (module-rule-kinds module)
  (let ((variable (and=> (false-if-exception (resolve-interface module))
                         (cut module-variable <> 'rule-kinds))))
    (unless variable
      (raise-locked-error "module ~a defines no kinds of rules" module))
    ((variable-ref variable))))

(define (module-rule-kind-names module)
  (map kind-name (module-rule-kinds module)))

(define (module-rule-kind module name)
  (or (find (lambda (kind)
              (eq? (kind-name kind) name))
            (module-rule-kinds module))
      (raise-locked-error "module ~a defines no kind of rules ~a"
                          module name)))
