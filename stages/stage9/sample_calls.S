.intel_syntax noprefix
.text
.global sceAgcInit
.type sceAgcInit,@function
sceAgcInit:
    ret
.global test_caller
.type test_caller,@function
test_caller:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    lea rdi, [rip+init_blob]
    mov esi, 0x20
    mov rdx, 0x1234
    xor ecx, ecx
    call sceAgcInit
    mov eax, 0
    leave
    ret
.section .rodata
init_blob:
    .zero 64
