
/mnt/data/libSceAgc.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    75e0: 55                           	pushq	%rbp
    75e1: 48 89 e5                     	movq	%rsp, %rbp
    75e4: 41 57                        	pushq	%r15
    75e6: 41 56                        	pushq	%r14
    75e8: 41 55                        	pushq	%r13
    75ea: 41 54                        	pushq	%r12
    75ec: 53                           	pushq	%rbx
    75ed: 48 81 ec a8 00 00 00         	subq	$0xa8, %rsp
    75f4: 48 8b 05 15 52 02 00         	movq	0x25215(%rip), %rax     # 0x2c810 <PT_LOAD#0+0x2c810>
    75fb: 49 89 fe                     	movq	%rdi, %r14
    75fe: 48 8d 3d 03 bb 02 00         	leaq	0x2bb03(%rip), %rdi     # 0x33108 <PT_LOAD#0+0x33108>
    7605: 41 89 d4                     	movl	%edx, %r12d
    7608: 41 89 f7                     	movl	%esi, %r15d
    760b: 48 8b 00                     	movq	(%rax), %rax
    760e: 48 89 45 d0                  	movq	%rax, -0x30(%rbp)
    7612: e8 09 b0 00 00               	callq	0x12620 <PT_LOAD#0+0x12620>
    7617: 85 c0                        	testl	%eax, %eax
    7619: 74 10                        	je	0x762b <PT_LOAD#0+0x762b>
    761b: 89 c6                        	movl	%eax, %esi
    761d: 48 8d 3d 37 fa 00 00         	leaq	0xfa37(%rip), %rdi      # 0x1705b <PT_LOAD#0+0x1705b>
    7624: 31 c0                        	xorl	%eax, %eax
    7626: e8 05 b0 00 00               	callq	0x12630 <PT_LOAD#0+0x12630>
    762b: 48 8d bd 60 ff ff ff         	leaq	-0xa0(%rbp), %rdi
    7632: e8 29 b0 00 00               	callq	0x12660 <PT_LOAD#0+0x12660>
    7637: 31 db                        	xorl	%ebx, %ebx
    7639: 85 c0                        	testl	%eax, %eax
    763b: 0f 85 88 00 00 00            	jne	0x76c9 <PT_LOAD#0+0x76c9>
    7641: 0f b6 85 63 ff ff ff         	movzbl	-0x9d(%rbp), %eax
    7648: c1 e0 18                     	shll	$0x18, %eax
    764b: 3d 00 00 00 04               	cmpl	$0x4000000, %eax        # imm = 0x4000000
    7650: 75 77                        	jne	0x76c9 <PT_LOAD#0+0x76c9>
    7652: e8 19 b0 00 00               	callq	0x12670 <PT_LOAD#0+0x12670>
    7657: 48 8d b5 70 ff ff ff         	leaq	-0x90(%rbp), %rsi
    765e: 89 c7                        	movl	%eax, %edi
    7660: e8 1b b0 00 00               	callq	0x12680 <PT_LOAD#0+0x12680>
    7665: 85 c0                        	testl	%eax, %eax
    7667: 78 5e                        	js	0x76c7 <PT_LOAD#0+0x76c7>
    7669: 4c 8d 6d a0                  	leaq	-0x60(%rbp), %r13
    766d: 48 8d 95 5c ff ff ff         	leaq	-0xa4(%rbp), %rdx
    7674: be 52 00 00 00               	movl	$0x52, %esi
    7679: 4c 89 ef                     	movq	%r13, %rdi
    767c: e8 0f b0 00 00               	callq	0x12690 <PT_LOAD#0+0x12690>
    7681: 31 db                        	xorl	%ebx, %ebx
    7683: 85 c0                        	testl	%eax, %eax
    7685: 75 42                        	jne	0x76c9 <PT_LOAD#0+0x76c9>
    7687: 8b 85 5c ff ff ff            	movl	-0xa4(%rbp), %eax
    768d: 48 8d 95 5c ff ff ff         	leaq	-0xa4(%rbp), %rdx
    7694: 4c 89 ef                     	movq	%r13, %rdi
    7697: be 53 00 00 00               	movl	$0x53, %esi
    769c: 89 85 50 ff ff ff            	movl	%eax, -0xb0(%rbp)
    76a2: e8 e9 af 00 00               	callq	0x12690 <PT_LOAD#0+0x12690>
    76a7: 85 c0                        	testl	%eax, %eax
    76a9: 75 1e                        	jne	0x76c9 <PT_LOAD#0+0x76c9>
    76ab: 31 c0                        	xorl	%eax, %eax
    76ad: 83 bd 50 ff ff ff 01         	cmpl	$0x1, -0xb0(%rbp)
    76b4: 0f 94 c0                     	sete	%al
    76b7: 31 db                        	xorl	%ebx, %ebx
    76b9: ff c0                        	incl	%eax
    76bb: 83 bd 5c ff ff ff 01         	cmpl	$0x1, -0xa4(%rbp)
    76c2: 0f 45 d8                     	cmovnel	%eax, %ebx
    76c5: eb 02                        	jmp	0x76c9 <PT_LOAD#0+0x76c9>
    76c7: 31 db                        	xorl	%ebx, %ebx
    76c9: 48 83 3d 3f ba 02 00 00      	cmpq	$0x0, 0x2ba3f(%rip)     # 0x33110 <PT_LOAD#0+0x33110>
    76d1: 89 1d 61 b9 02 00            	movl	%ebx, 0x2b961(%rip)     # 0x33038 <PT_LOAD#0+0x33038>
    76d7: 74 51                        	je	0x772a <PT_LOAD#0+0x772a>
    76d9: 45 84 e4                     	testb	%r12b, %r12b
    76dc: 74 0f                        	je	0x76ed <PT_LOAD#0+0x76ed>
    76de: 31 ff                        	xorl	%edi, %edi
    76e0: 41 83 ff 06                  	cmpl	$0x6, %r15d
    76e4: 40 0f 92 c7                  	setb	%dil
    76e8: e8 b3 af 00 00               	callq	0x126a0 <PT_LOAD#0+0x126a0>
    76ed: 8b 05 91 b9 02 00            	movl	0x2b991(%rip), %eax     # 0x33084 <PT_LOAD#0+0x33084>
    76f3: 44 39 f8                     	cmpl	%r15d, %eax
    76f6: 75 04                        	jne	0x76fc <PT_LOAD#0+0x76fc>
    76f8: 31 d2                        	xorl	%edx, %edx
    76fa: eb 10                        	jmp	0x770c <PT_LOAD#0+0x770c>
    76fc: 8b 0d d2 b9 02 00            	movl	0x2b9d2(%rip), %ecx     # 0x330d4 <PT_LOAD#0+0x330d4>
    7702: ba 01 00 00 00               	movl	$0x1, %edx
    7707: 44 39 f9                     	cmpl	%r15d, %ecx
    770a: 75 54                        	jne	0x7760 <PT_LOAD#0+0x7760>
    770c: 45 84 e4                     	testb	%r12b, %r12b
    770f: 74 4a                        	je	0x775b <PT_LOAD#0+0x775b>
    7711: 48 8d 04 92                  	leaq	(%rdx,%rdx,4), %rax
    7715: 48 8d 0d 24 b9 02 00         	leaq	0x2b924(%rip), %rcx     # 0x33040 <PT_LOAD#0+0x33040>
    771c: 45 31 ed                     	xorl	%r13d, %r13d
    771f: 48 c1 e0 04                  	shlq	$0x4, %rax
    7723: c6 44 08 48 01               	movb	$0x1, 0x48(%rax,%rcx)
    7728: eb 4f                        	jmp	0x7779 <PT_LOAD#0+0x7779>
    772a: bf 08 00 00 00               	movl	$0x8, %edi
    772f: be 08 00 00 00               	movl	$0x8, %esi
    7734: e8 97 48 00 00               	callq	0xbfd0 <PT_LOAD#0+0xbfd0>
    7739: 48 89 05 d0 b9 02 00         	movq	%rax, 0x2b9d0(%rip)     # 0x33110 <PT_LOAD#0+0x33110>
    7740: c7 00 00 00 00 00            	movl	$0x0, (%rax)
    7746: 48 8b 05 c3 b9 02 00         	movq	0x2b9c3(%rip), %rax     # 0x33110 <PT_LOAD#0+0x33110>
    774d: c7 40 04 01 00 00 00         	movl	$0x1, 0x4(%rax)
    7754: 45 84 e4                     	testb	%r12b, %r12b
    7757: 75 85                        	jne	0x76de <PT_LOAD#0+0x76de>
    7759: eb 92                        	jmp	0x76ed <PT_LOAD#0+0x76ed>
    775b: 45 31 ed                     	xorl	%r13d, %r13d
    775e: eb 19                        	jmp	0x7779 <PT_LOAD#0+0x7779>
    7760: 41 b5 01                     	movb	$0x1, %r13b
    7763: 85 c0                        	testl	%eax, %eax
    7765: 74 10                        	je	0x7777 <PT_LOAD#0+0x7777>
    7767: bb 04 00 6c 8a               	movl	$0x8a6c0004, %ebx       # imm = 0x8A6C0004
    776c: 85 c9                        	testl	%ecx, %ecx
    776e: 75 34                        	jne	0x77a4 <PT_LOAD#0+0x77a4>
    7770: ba 01 00 00 00               	movl	$0x1, %edx
    7775: eb 02                        	jmp	0x7779 <PT_LOAD#0+0x7779>
    7777: 31 d2                        	xorl	%edx, %edx
    7779: 4d 85 f6                     	testq	%r14, %r14
    777c: 74 03                        	je	0x7781 <PT_LOAD#0+0x7781>
    777e: 41 89 16                     	movl	%edx, (%r14)
    7781: 44 89 ff                     	movl	%r15d, %edi
    7784: 48 89 95 50 ff ff ff         	movq	%rdx, -0xb0(%rbp)
    778b: e8 60 71 00 00               	callq	0xe8f0 <PT_LOAD#0+0xe8f0>
    7790: 89 c3                        	movl	%eax, %ebx
    7792: 85 c0                        	testl	%eax, %eax
    7794: 75 0e                        	jne	0x77a4 <PT_LOAD#0+0x77a4>
    7796: 44 89 ff                     	movl	%r15d, %edi
    7799: e8 02 a2 00 00               	callq	0x119a0 <PT_LOAD#0+0x119a0>
    779e: 89 c3                        	movl	%eax, %ebx
