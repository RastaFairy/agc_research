
/mnt/data/libSceAgcDriver.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    28c0: 55                           	pushq	%rbp
    28c1: 48 89 e5                     	movq	%rsp, %rbp
    28c4: 48 8d 05 3d 80 01 00         	leaq	0x1803d(%rip), %rax     # 0x1a908 <PT_LOAD#0+0x1a908>
    28cb: 83 b8 48 01 00 00 00         	cmpl	$0x0, 0x148(%rax)
    28d2: 74 10                        	je	0x28e4 <PT_LOAD#0+0x28e4>
    28d4: 48 89 fe                     	movq	%rdi, %rsi
    28d7: 48 8d 3d 8a 7f 01 00         	leaq	0x17f8a(%rip), %rdi     # 0x1a868 <PT_LOAD#0+0x1a868>
    28de: 5d                           	popq	%rbp
    28df: e9 cc ef ff ff               	jmp	0x18b0 <PT_LOAD#0+0x18b0>
    28e4: 48 8b 0d f5 17 01 00         	movq	0x117f5(%rip), %rcx     # 0x140e0 <PT_LOAD#0+0x140e0>
    28eb: 48 8d 3d 6c d4 00 00         	leaq	0xd46c(%rip), %rdi      # 0xfd5e <PT_LOAD#0+0xfd5e>
    28f2: be 38 00 00 00               	movl	$0x38, %esi
    28f7: ba 01 00 00 00               	movl	$0x1, %edx
    28fc: e8 6f 82 00 00               	callq	0xab70 <PT_LOAD#0+0xab70>
    2901: b8 03 00 6d 8a               	movl	$0x8a6d0003, %eax       # imm = 0x8A6D0003
    2906: 5d                           	popq	%rbp
    2907: c3                           	retq
