;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

(define-module (guix-cage build locked wayland)
  #:use-module (ice-9 binary-ports)
  #:use-module (ice-9 match)
  #:use-module (rnrs bytevectors)
  #:use-module (guix-cage build locked errors)
  #:use-module (guix-cage build locked instances)
  #:use-module (guix-cage build locked process)
  #:use-module (guix-cage build locked xdg)
  #:use-module (guix-cage build locked grants)
  #:use-module (srfi srfi-1)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (%wayland
            %full-wayland))

(define (wayland-socket)
  (let ((wayland-display (or (getenv "WAYLAND_DISPLAY") "wayland-0")))
    (if (string-prefix? "/" wayland-display)
        wayland-display
        (runtime-path wayland-display))))

(define (%full-wayland command-line)
  "Grant the whole compositor, as layer shells such as panels need."
  (socket-grant (wayland-socket)
                 (lambda (socket)
                   `(("WAYLAND_DISPLAY" . ,socket)))))

(define (u32 value)
  (let ((bytes (make-bytevector 4)))
    (bytevector-u32-native-set! bytes 0 value)
    bytes))

(define (wayland-string string)
  "Return STRING with its length, null-terminated and padded to 32 bits."
  (let* ((bytes (string->utf8 string))
         (size (1+ (bytevector-length bytes)))
         (result (make-bytevector (+ 4 (* 4 (quotient (+ size 3) 4))) 0)))
    (bytevector-u32-native-set! result 0 size)
    (bytevector-copy! bytes 0 result 4 (bytevector-length bytes))
    result))

(define (wayland-string-ref bytes offset)
  (let ((size (bytevector-u32-native-ref bytes offset)))
    ;; The size counts the null byte, so only null strings have none
    (unless (and (positive? size)
                 (<= (+ offset 4 size) (bytevector-length bytes)))
      (raise-locked-error "the compositor sent a malformed string"))
    (let ((result (make-bytevector (1- size))))
      (bytevector-copy! bytes (+ offset 4) result 0 (1- size))
      (utf8->string result))))

(define (wayland-message object opcode . arguments)
  (let* ((body (map (lambda (argument)
                      (if (string? argument)
                          (wayland-string argument)
                          (u32 argument)))
                    arguments))
         (size (+ 8 (apply + (map bytevector-length body))))
         (message (make-bytevector size)))
    (bytevector-u32-native-set! message 0 object)
    (bytevector-u32-native-set! message 4 (logior (ash size 16) opcode))
    (fold (lambda (part offset)
            (bytevector-copy! part 0 message offset (bytevector-length part))
            (+ offset (bytevector-length part)))
          8
          body)
    message))

(define sendmsg
  (delay (foreign-library-function #f "sendmsg"
                                   #:return-type ssize_t
                                   #:arg-types (list int '* int)
                                   #:return-errno? #t)))

(define %scm-rights 1)
(define %msg-nosignal #x4000)

(define (align size alignment)
  (* alignment (quotient (+ size alignment -1) alignment)))

(define (control-message fds)
  (let* ((word (sizeof size_t))
         (header (align (sizeof (list size_t int int)) word))
         (size (+ header (* (sizeof int) (length fds))))
         (control (make-bytevector (align size word) 0)))
    (bytevector-uint-set! control 0 size (native-endianness) word)
    (bytevector-s32-native-set! control word SOL_SOCKET)
    (bytevector-s32-native-set! control (+ word (sizeof int)) %scm-rights)
    (for-each (lambda (fd index)
                (bytevector-s32-native-set! control
                                            (+ header (* index (sizeof int)))
                                            fd))
              fds
              (iota (length fds)))
    control))

(define (msghdr-buffer message control)
  "Return a struct msghdr followed by the iovec, CONTROL and MESSAGE it
points to."
  (let* ((pointer (sizeof '*))
         (word (sizeof size_t))
         ;; struct msghdr: name, namelen, iov, iovlen, control, controllen
         ;; and flags
         (iov-field (align (+ pointer (sizeof uint32)) pointer))
         (control-field (+ iov-field pointer word))
         (iovec-offset (align (+ control-field pointer word (sizeof int))
                              pointer))
         (control-offset (+ iovec-offset pointer word))
         (message-offset (+ control-offset (bytevector-length control)))
         (buffer (make-bytevector (+ message-offset
                                     (bytevector-length message))
                                  0))
         (base (pointer-address (bytevector->pointer buffer))))
    (define (store! offset value size)
      (bytevector-uint-set! buffer offset value (native-endianness) size))

    (store! iov-field (+ base iovec-offset) pointer)
    (store! (+ iov-field pointer) 1 word)
    (unless (zero? (bytevector-length control))
      (store! control-field (+ base control-offset) pointer)
      (store! (+ control-field pointer) (bytevector-length control) word))
    (store! iovec-offset (+ base message-offset) pointer)
    (store! (+ iovec-offset pointer) (bytevector-length message) word)
    (bytevector-copy! control 0 buffer control-offset
                      (bytevector-length control))
    (bytevector-copy! message 0 buffer message-offset
                      (bytevector-length message))
    buffer))

(define (send-message port message . fds)
  "Send MESSAGE with FDS, which Guile's send can't."
  (let ((buffer (msghdr-buffer message
                               (if (null? fds) #vu8() (control-message fds)))))
    (call-with-values (lambda ()
                        ((force sendmsg) (fileno port)
                         (bytevector->pointer buffer) %msg-nosignal))
      (lambda (result errno)
        (unless (= result (bytevector-length message))
          (raise-locked-error "cannot talk to the compositor: ~a"
                              (if (< result 0)
                                  (strerror errno)
                                  "short write")))))))

(define (read-event port)
  (define (read-bytes count)
    (let ((bytes (if (positive? count)
                     (get-bytevector-n port count)
                     (make-bytevector 0))))
      (when (or (eof-object? bytes) (< (bytevector-length bytes) count))
        (raise-locked-error "the compositor closed the connection"))
      bytes))

  (let* ((header (read-bytes 8))
         (word (bytevector-u32-native-ref header 4)))
    (values (bytevector-u32-native-ref header 0)
            (logand word #xffff)
            (read-bytes (- (ash word -16) 8)))))

;; The compositor expects new IDs in this order
(define %display 1)
(define %registry 2)
(define %callback 3)
(define %manager 4)
(define %context 5)
(define %final-callback 6)

(define %display-sync 0)
(define %display-get-registry 1)
(define %display-error 0)
(define %registry-bind 0)
(define %registry-global 0)
(define %manager-create-listener 1)
(define %context-destroy 0)
(define %context-set-sandbox-engine 1)
(define %context-set-app-id 2)
(define %context-commit 4)

(define (wayland-roundtrip port callback handle-event seed)
  "Fold HANDLE-EVENT over the events until the compositor answers the sync
on CALLBACK."
  (send-message port (wayland-message %display %display-sync callback))
  (let loop ((result seed))
    (call-with-values (lambda () (read-event port))
      (lambda (object opcode body)
        (cond ((= object callback)
               result)
              ((and (= object %display) (= opcode %display-error))
               (raise-locked-error "Wayland protocol error: ~a"
                                   (wayland-string-ref body 8)))
              ((= object %display)
               (loop result))
              (else
               (loop (handle-event object opcode body result))))))))

(define (find-security-context-manager port)
  (send-message port
                (wayland-message %display %display-get-registry %registry))
  (or (wayland-roundtrip port %callback
                         (lambda (object opcode body manager)
                           (if (and (= object %registry)
                                    (= opcode %registry-global)
                                    (string=? (wayland-string-ref body 4)
                                              "wp_security_context_manager_v1"))
                               (bytevector-u32-native-ref body 0)
                               manager))
                         #f)
      (raise-locked-error
       "the compositor doesn't support wp_security_context_v1")))

(define (listening-socket path)
  (let ((listener (socket PF_UNIX SOCK_STREAM 0)))
    (bind listener AF_UNIX path)
    (listen listener 128)
    listener))

(define (connect-to-compositor compositor)
  (let ((connection (socket PF_UNIX SOCK_STREAM 0)))
    (connect connection AF_UNIX compositor)
    (setvbuf connection 'none)
    connection))

(define (create-security-context! connection listener close-end name)
  (let ((manager (find-security-context-manager connection)))
    (send-message connection
                  (wayland-message %registry %registry-bind manager
                                   "wp_security_context_manager_v1" 1
                                   %manager))
    (send-message connection
                  (wayland-message %manager %manager-create-listener %context)
                  (fileno listener) (fileno close-end))
    (send-message connection
                  (wayland-message %context %context-set-sandbox-engine
                                   "org.guix.cage"))
    (send-message connection
                  (wayland-message %context %context-set-app-id name))
    (send-message connection (wayland-message %context %context-commit))
    (send-message connection (wayland-message %context %context-destroy))
    (wayland-roundtrip connection %final-callback
                       (lambda (object opcode body result) result)
                       #t)))

(define (%wayland command-line)
  "Grant a socket on which the compositor hides privileged protocols, such
as screen capture, from the program."
  (let ((compositor (wayland-socket))
        (name (first command-line)))
    (if (file-exists? compositor)
        (let* ((directory (make-instance-directory "wayland-context"))
               (listen-path (string-append directory "/wayland-0"))
               (listener (listening-socket listen-path))
               (connection (connect-to-compositor compositor)))
          (match (pipe)
            ((read-end . write-end)
             (create-security-context! connection listener read-end name)
             (for-each close-port (list connection listener read-end))
             (grant #:files (list (file-access directory '(connect)))
                    #:variables `(("WAYLAND_DISPLAY" . ,listen-path))
                    #:fds (list (inherit-across-exec! write-end))))))
        %no-grant)))
