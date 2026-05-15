; example_nasm.asm - testowy plik NASM dla sprawdzenia podświetlania składni
; assembli: NASM (Intel syntax), x86-64 examples

; dyrektywy globalne / sekcje
BITS 64
%define PAGE_SIZE 4096
%define MSG "Hello, NASM world!"

section .data
    ; różne sposoby definiowania danych
    hello_msg    db  "Hello, world!", 0x0A ; newline
    hello_len    equ $ - hello_msg
    numbers      dd  1, 2, 3, 0xFF, 255
    wordvals     dw  0x1234, 0x4321
    qwords       dq  0x1122334455667788

    ; string with single quote allowed
    quoted       db  'Single-quoted string with '' inside', 0

    ; INC BIN example (binary include) - file must exist to assemble
    ; incbin "image.bin"

section .rodata
    msg_ptr      dq  hello_msg

section .bss
    res_buf      resb 64
    res_qword    resq 4

; equ / times / org examples
section .text
    global _start
    extern printf    ; if linking with libc
    extern puts

_start:
    ; label at line start
    main_label:
        ; move immediate into register
        mov     rax, 1              ; syscall: write
        mov     rdi, 1              ; fd: stdout
        lea     rsi, [rel hello_msg]
        mov     rdx, hello_len
        syscall

        ; call external C function example (if linked)
        ; lea rdi, [rel hello_msg]
        ; call printf

        ; arithmetic and bitwise ops
        mov     rax, 0x10
        add     rax, 0x02
        shl     rax, 1
        and     rax, 0xFF

        ; using registers of different sizes
        mov     eax, 0x1234
        mov     ax, 0x55
        mov     al, 0x7F

        ; stack operations
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32

        ; local numeric labels demo: 1: ... jmp 1b
        jmp     short forward1
    1:
        nop
        jmp     short 2f
    2:
        nop
    forward1:
        ; call a local label and return
        call    do_work
        jmp     done

; function example (do_work)
do_work:
    push    rbp
    mov     rbp, rsp
    ; use of local variables on stack
    mov     qword [rbp-8], 0xDEADBEEFCAFEBABE
    ; use string in rsi with lea and rel addressing
    lea     rsi, [rel hello_msg]
    xor     rax, rax
    call    puts
    pop     rbp
    ret

; macro examples
%macro LOG 1
    ; prints message via write syscall (simple, no libc)
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel %1]
    mov     rdx, %1_len
    syscall
%endmacro

; Using macro (macro parameter must be identifier defined earlier)
; LOG hello_msg  ; (uncomment to use if %1_len defined appropriately)

; conditional assembly
%ifdef DEBUG
    ; debug-only instructions
    mov rax, 0
%else
    ; release code
%endif

; switch-like / jump table example
jump_table:
    dq label0, label1, label2

label0:
    ; do something
    nop
    jmp common_exit

label1:
    nop
    jmp common_exit

label2:
    nop
    jmp common_exit

common_exit:
    ; restore stack and exit
    mov     rsp, rbp
    pop     rbp

done:
    ; syscall exit (Linux x86-64)
    mov     rax, 60     ; sys_exit
    xor     rdi, rdi
    syscall

; more directives: align, times, org
SECTION .note aligned  ; example of section naming
align 16
times 4 db 0x00

; local labels revisited: 1f (forward) and 1b (back)
jmp     1f
db      'X'
1:
    nop

; macros with parameters and repetition
%macro REPEAT_NOP 1
    %rep %1
        nop
    %endrep
%endmacro

REPEAT_NOP 3

; arithmetic immediate forms and memory addressing examples
mov     rax, [rel res_qword]
mov     rbx, [rax + rsi*2 + 8]

; example of segment override (rare in 64-bit, but shown)
mov     eax, [fs:0x28]

; labels with dots and dollar signs in names
proc.init:
    mov rax, 0
    ret

$private_label:
    nop

; include other files (if present)
; %include "other.asm"

; comment styles: semicolon to end-of-line
; multi-line comments are not standard in NASM, so use ; for each line

; end of file marker (optional)
