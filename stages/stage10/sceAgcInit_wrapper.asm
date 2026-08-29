
/mnt/data/libSceAgc.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    84a0: 48 8b 04 24                  	movq	(%rsp), %rax
    84a4: 48 ba ff ff ff ff 07 00 00 00	movabsq	$0x7ffffffff, %rdx      # imm = 0x7FFFFFFFF
    84ae: 89 fe                        	movl	%edi, %esi
    84b0: 48 89 c1                     	movq	%rax, %rcx
    84b3: 48 c1 e9 23                  	shrq	$0x23, %rcx
    84b7: 0f 94 c1                     	sete	%cl
    84ba: 48 81 c2 01 00 00 40         	addq	$0x40000001, %rdx       # imm = 0x40000001
    84c1: 48 39 d0                     	cmpq	%rdx, %rax
    84c4: 0f 93 c0                     	setae	%al
    84c7: 31 ff                        	xorl	%edi, %edi
    84c9: 08 c8                        	orb	%cl, %al
    84cb: 0f b6 d0                     	movzbl	%al, %edx
    84ce: e9 0d f1 ff ff               	jmp	0x75e0 <PT_LOAD#0+0x75e0>
