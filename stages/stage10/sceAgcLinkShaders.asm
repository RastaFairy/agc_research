
/mnt/data/libSceAgc.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    d390: 55                           	pushq	%rbp
    d391: 41 57                        	pushq	%r15
    d393: 41 56                        	pushq	%r14
    d395: 41 55                        	pushq	%r13
    d397: 41 54                        	pushq	%r12
    d399: 53                           	pushq	%rbx
    d39a: 48 89 d3                     	movq	%rdx, %rbx
    d39d: 48 85 ff                     	testq	%rdi, %rdi
    d3a0: 0f 84 b4 03 00 00            	je	0xd75a <PT_LOAD#0+0xd75a>
    d3a6: 48 8d 05 4b 57 02 00         	leaq	0x2574b(%rip), %rax     # 0x32af8 <PT_LOAD#0+0x32af8>
    d3ad: 48 8d 15 0c 57 02 00         	leaq	0x2570c(%rip), %rdx     # 0x32ac0 <PT_LOAD#0+0x32ac0>
    d3b4: 48 8b 00                     	movq	(%rax), %rax
    d3b7: 48 89 87 00 01 00 00         	movq	%rax, 0x100(%rdi)
    d3be: 48 8b 02                     	movq	(%rdx), %rax
    d3c1: 48 89 87 08 01 00 00         	movq	%rax, 0x108(%rdi)
    d3c8: 48 85 c9                     	testq	%rcx, %rcx
    d3cb: 0f 84 5d 03 00 00            	je	0xd72e <PT_LOAD#0+0xd72e>
    d3d1: 48 8b 51 28                  	movq	0x28(%rcx), %rdx
    d3d5: 48 8b 52 08                  	movq	0x8(%rdx), %rdx
    d3d9: 48 0f ba e2 25               	btq	$0x25, %rdx
    d3de: 48 89 97 00 01 00 00         	movq	%rdx, 0x100(%rdi)
    d3e5: 0f 82 9a 02 00 00            	jb	0xd685 <PT_LOAD#0+0xd685>
    d3eb: 48 c1 e8 20                  	shrq	$0x20, %rax
    d3ef: 41 8d 69 ff                  	leal	-0x1(%r9), %ebp
    d3f3: ba 02 00 00 00               	movl	$0x2, %edx
    d3f8: 83 fd 11                     	cmpl	$0x11, %ebp
    d3fb: 77 0e                        	ja	0xd40b <PT_LOAD#0+0xd40b>
    d3fd: 48 63 d5                     	movslq	%ebp, %rdx
    d400: 4c 8d 15 bd b9 01 00         	leaq	0x1b9bd(%rip), %r10     # 0x28dc4 <PT_LOAD#0+0x28dc4>
    d407: 41 8b 14 92                  	movl	(%r10,%rdx,4), %edx
    d40b: 83 e0 f8                     	andl	$-0x8, %eax
    d40e: 09 d0                        	orl	%edx, %eax
    d410: 89 87 0c 01 00 00            	movl	%eax, 0x10c(%rdi)
    d416: 4d 85 c0                     	testq	%r8, %r8
    d419: 0f 84 7e 02 00 00            	je	0xd69d <PT_LOAD#0+0xd69d>
    d41f: 45 8b 68 50                  	movl	0x50(%r8), %r13d
    d423: 4d 85 ed                     	testq	%r13, %r13
    d426: 0f 84 bf 02 00 00            	je	0xd6eb <PT_LOAD#0+0xd6eb>
    d42c: 0f b7 69 56                  	movzwl	0x56(%rcx), %ebp
    d430: 48 89 74 24 f8               	movq	%rsi, -0x8(%rsp)
    d435: 49 8b 70 30                  	movq	0x30(%r8), %rsi
    d439: 4c 8b 51 38                  	movq	0x38(%rcx), %r10
    d43d: 4c 8d 05 f0 b8 01 00         	leaq	0x1b8f0(%rip), %r8      # 0x28d34 <PT_LOAD#0+0x28d34>
    d444: 4c 89 4c 24 e8               	movq	%r9, -0x18(%rsp)
    d449: 48 89 5c 24 f0               	movq	%rbx, -0x10(%rsp)
    d44e: 45 31 f6                     	xorl	%r14d, %r14d
    d451: 44 0f b7 dd                  	movzwl	%bp, %r11d
    d455: 66 66 2e 0f 1f 84 00 00 00 00 00     	nopw	%cs:(%rax,%rax)
    d460: 42 8b 14 b6                  	movl	(%rsi,%r14,4), %edx
    d464: 41 bc 00 00 00 00            	movl	$0x0, %r12d
    d46a: 66 85 ed                     	testw	%bp, %bp
    d46d: 74 34                        	je	0xd4a3 <PT_LOAD#0+0xd4a3>
    d46f: 44 0f b7 e5                  	movzwl	%bp, %r12d
    d473: 31 db                        	xorl	%ebx, %ebx
    d475: 44 89 e5                     	movl	%r12d, %ebp
    d478: 0f 1f 84 00 00 00 00 00      	nopl	(%rax,%rax)
    d480: 41 0f b6 04 9a               	movzbl	(%r10,%rbx,4), %eax
    d485: 30 d0                        	xorb	%dl, %al
    d487: 74 17                        	je	0xd4a0 <PT_LOAD#0+0xd4a0>
    d489: 48 ff c3                     	incq	%rbx
    d48c: 48 39 dd                     	cmpq	%rbx, %rbp
    d48f: 75 ef                        	jne	0xd480 <PT_LOAD#0+0xd480>
    d491: eb 10                        	jmp	0xd4a3 <PT_LOAD#0+0xd4a3>
    d493: 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	nopw	%cs:(%rax,%rax)
    d4a0: 41 89 dc                     	movl	%ebx, %r12d
    d4a3: 48 8d 05 8e 59 02 00         	leaq	0x2598e(%rip), %rax     # 0x32e38 <PT_LOAD#0+0x32e38>
    d4aa: 4c 8b 08                     	movq	(%rax), %r9
    d4ad: 4c 89 cd                     	movq	%r9, %rbp
    d4b0: 48 c1 ed 20                  	shrq	$0x20, %rbp
    d4b4: f7 c2 00 00 30 00            	testl	$0x300000, %edx         # imm = 0x300000
    d4ba: 74 74                        	je	0xd530 <PT_LOAD#0+0xd530>
    d4bc: 41 89 d7                     	movl	%edx, %r15d
    d4bf: 81 e5 ff ff f7 fc            	andl	$0xfcf7ffff, %ebp       # imm = 0xFCF7FFFF
    d4c5: 41 c1 e7 04                  	shll	$0x4, %r15d
    d4c9: 44 89 f8                     	movl	%r15d, %eax
    d4cc: 41 81 e7 00 00 00 02         	andl	$0x2000000, %r15d       # imm = 0x2000000
    d4d3: 25 00 00 00 01               	andl	$0x1000000, %eax        # imm = 0x1000000
    d4d8: 09 c5                        	orl	%eax, %ebp
    d4da: 41 09 ef                     	orl	%ebp, %r15d
    d4dd: 45 39 dc                     	cmpl	%r11d, %r12d
    d4e0: 73 7e                        	jae	0xd560 <PT_LOAD#0+0xd560>
    d4e2: 44 89 e0                     	movl	%r12d, %eax
    d4e5: 41 81 e7 df ff f7 ff         	andl	$0xfff7ffdf, %r15d      # imm = 0xFFF7FFDF
    d4ec: 41 8b 04 82                  	movl	(%r10,%rax,4), %eax
    d4f0: 21 d0                        	andl	%edx, %eax
    d4f2: 89 c3                        	movl	%eax, %ebx
    d4f4: d1 e8                        	shrl	%eax
    d4f6: c1 eb 0f                     	shrl	$0xf, %ebx
    d4f9: f7 d0                        	notl	%eax
    d4fb: 83 e3 20                     	andl	$0x20, %ebx
    d4fe: 25 00 00 10 00               	andl	$0x100000, %eax         # imm = 0x100000
    d503: 41 09 df                     	orl	%ebx, %r15d
    d506: 48 8d 1d 17 b8 01 00         	leaq	0x1b817(%rip), %rbx     # 0x28d24 <PT_LOAD#0+0x28d24>
    d50d: 41 81 f7 20 00 08 00         	xorl	$0x80020, %r15d         # imm = 0x80020
    d514: 41 81 e7 ff ff ef ff         	andl	$0xffefffff, %r15d      # imm = 0xFFEFFFFF
    d51b: 41 09 c7                     	orl	%eax, %r15d
    d51e: 89 d0                        	movl	%edx, %eax
    d520: c1 e8 1e                     	shrl	$0x1e, %eax
    d523: 48 63 04 83                  	movslq	(%rbx,%rax,4), %rax
    d527: 48 01 d8                     	addq	%rbx, %rax
    d52a: ff e0                        	jmpq	*%rax
    d52c: 0f 1f 40 00                  	nopl	(%rax)
    d530: 45 39 dc                     	cmpl	%r11d, %r12d
    d533: 0f 93 c0                     	setae	%al
    d536: f7 c2 00 00 40 01            	testl	$0x1400000, %edx        # imm = 0x1400000
    d53c: 0f 95 c3                     	setne	%bl
    d53f: 83 e5 df                     	andl	$-0x21, %ebp
    d542: 08 c3                        	orb	%al, %bl
    d544: 0f b6 c3                     	movzbl	%bl, %eax
    d547: c1 e0 05                     	shll	$0x5, %eax
    d54a: 09 c5                        	orl	%eax, %ebp
    d54c: 41 89 ef                     	movl	%ebp, %r15d
    d54f: eb 6f                        	jmp	0xd5c0 <PT_LOAD#0+0xd5c0>
    d551: 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
    d560: 41 81 cf 20 00 08 00         	orl	$0x80020, %r15d         # imm = 0x80020
    d567: b8 00 00 10 00               	movl	$0x100000, %eax         # imm = 0x100000
    d56c: 48 8d 1d b1 b7 01 00         	leaq	0x1b7b1(%rip), %rbx     # 0x28d24 <PT_LOAD#0+0x28d24>
    d573: 41 81 e7 ff ff ef ff         	andl	$0xffefffff, %r15d      # imm = 0xFFEFFFFF
    d57a: 41 09 c7                     	orl	%eax, %r15d
    d57d: 89 d0                        	movl	%edx, %eax
    d57f: c1 e8 1e                     	shrl	$0x1e, %eax
    d582: 48 63 04 83                  	movslq	(%rbx,%rax,4), %rax
    d586: 48 01 d8                     	addq	%rbx, %rax
    d589: ff e0                        	jmpq	*%rax
    d58b: 41 81 e7 ff ff 9f ff         	andl	$0xff9fffff, %r15d      # imm = 0xFF9FFFFF
    d592: eb 2c                        	jmp	0xd5c0 <PT_LOAD#0+0xd5c0>
    d594: 41 81 e7 ff ff 9f ff         	andl	$0xff9fffff, %r15d      # imm = 0xFF9FFFFF
    d59b: 41 81 cf 00 00 20 00         	orl	$0x200000, %r15d        # imm = 0x200000
    d5a2: eb 1c                        	jmp	0xd5c0 <PT_LOAD#0+0xd5c0>
    d5a4: 41 81 e7 ff ff 9f ff         	andl	$0xff9fffff, %r15d      # imm = 0xFF9FFFFF
    d5ab: 41 81 cf 00 00 40 00         	orl	$0x400000, %r15d        # imm = 0x400000
    d5b2: eb 0c                        	jmp	0xd5c0 <PT_LOAD#0+0xd5c0>
    d5b4: 41 81 cf 00 00 60 00         	orl	$0x600000, %r15d        # imm = 0x600000
    d5bb: 0f 1f 44 00 00               	nopl	(%rax,%rax)
    d5c0: 4d 01 f1                     	addq	%r14, %r9
    d5c3: 45 39 dc                     	cmpl	%r11d, %r12d
    d5c6: 73 48                        	jae	0xd610 <PT_LOAD#0+0xd610>
    d5c8: 44 89 e0                     	movl	%r12d, %eax
    d5cb: bb 08 05 00 00               	movl	$0x508, %ebx            # imm = 0x508
    d5d0: 41 83 e7 e0                  	andl	$-0x20, %r15d
    d5d4: c4 c2 60 f7 2c 82            	bextrl	%ebx, (%r10,%rax,4), %ebp
    d5da: 31 c0                        	xorl	%eax, %eax
    d5dc: bb 1c 02 00 00               	movl	$0x21c, %ebx            # imm = 0x21C
    d5e1: 44 09 fd                     	orl	%r15d, %ebp
    d5e4: f7 c2 00 00 40 01            	testl	$0x1400000, %edx        # imm = 0x1400000
    d5ea: 0f 95 c0                     	setne	%al
    d5ed: 81 e5 ff fb ff ff            	andl	$0xfffffbff, %ebp       # imm = 0xFFFFFBFF
    d5f3: c1 e0 0a                     	shll	$0xa, %eax
    d5f6: 09 c5                        	orl	%eax, %ebp
    d5f8: c4 e2 60 f7 c2               	bextrl	%ebx, %edx, %eax
    d5fd: 49 63 04 80                  	movslq	(%r8,%rax,4), %rax
    d601: 4c 01 c0                     	addq	%r8, %rax
    d604: ff e0                        	jmpq	*%rax
    d606: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
    d610: 41 83 e7 e0                  	andl	$-0x20, %r15d
    d614: bb 1c 02 00 00               	movl	$0x21c, %ebx            # imm = 0x21C
    d619: 31 c0                        	xorl	%eax, %eax
    d61b: 41 81 e7 ff fb ff ff         	andl	$0xfffffbff, %r15d      # imm = 0xFFFFFBFF
    d622: 41 09 c7                     	orl	%eax, %r15d
    d625: c4 e2 60 f7 c2               	bextrl	%ebx, %edx, %eax
    d62a: 49 63 04 80                  	movslq	(%r8,%rax,4), %rax
    d62e: 44 89 fd                     	movl	%r15d, %ebp
    d631: 4c 01 c0                     	addq	%r8, %rax
    d634: ff e0                        	jmpq	*%rax
    d636: 81 e5 ff fc ff ff            	andl	$0xfffffcff, %ebp       # imm = 0xFFFFFCFF
    d63c: eb 28                        	jmp	0xd666 <PT_LOAD#0+0xd666>
    d63e: 66 90                        	nop
    d640: 81 e5 ff fc ff ff            	andl	$0xfffffcff, %ebp       # imm = 0xFFFFFCFF
    d646: 81 cd 00 02 00 00            	orl	$0x200, %ebp            # imm = 0x200
    d64c: eb 18                        	jmp	0xd666 <PT_LOAD#0+0xd666>
    d64e: 66 90                        	nop
    d650: 81 e5 ff fc ff ff            	andl	$0xfffffcff, %ebp       # imm = 0xFFFFFCFF
    d656: 81 cd 00 01 00 00            	orl	$0x100, %ebp            # imm = 0x100
    d65c: eb 08                        	jmp	0xd666 <PT_LOAD#0+0xd666>
    d65e: 66 90                        	nop
    d660: 81 cd 00 03 00 00            	orl	$0x300, %ebp            # imm = 0x300
    d666: 48 c1 e5 20                  	shlq	$0x20, %rbp
    d66a: 44 89 c8                     	movl	%r9d, %eax
    d66d: 48 09 e8                     	orq	%rbp, %rax
    d670: 4a 89 04 f7                  	movq	%rax, (%rdi,%r14,8)
    d674: 49 ff c6                     	incq	%r14
    d677: 4d 39 ee                     	cmpq	%r13, %r14
    d67a: 74 5a                        	je	0xd6d6 <PT_LOAD#0+0xd6d6>
    d67c: 0f b7 69 56                  	movzwl	0x56(%rcx), %ebp
    d680: e9 db fd ff ff               	jmp	0xd460 <PT_LOAD#0+0xd460>
    d685: 48 8b 41 28                  	movq	0x28(%rcx), %rax
    d689: 48 8b 40 20                  	movq	0x20(%rax), %rax
    d68d: 48 89 87 08 01 00 00         	movq	%rax, 0x108(%rdi)
    d694: 4d 85 c0                     	testq	%r8, %r8
    d697: 0f 85 82 fd ff ff            	jne	0xd41f <PT_LOAD#0+0xd41f>
    d69d: 48 8d 15 94 57 02 00         	leaq	0x25794(%rip), %rdx     # 0x32e38 <PT_LOAD#0+0x32e38>
    d6a4: 31 c0                        	xorl	%eax, %eax
    d6a6: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
    d6b0: 48 8b 2a                     	movq	(%rdx), %rbp
    d6b3: 48 89 2c c7                  	movq	%rbp, (%rdi,%rax,8)
    d6b7: 8b 2a                        	movl	(%rdx), %ebp
    d6b9: 01 c5                        	addl	%eax, %ebp
    d6bb: 89 2c c7                     	movl	%ebp, (%rdi,%rax,8)
    d6be: 8b 6c c7 04                  	movl	0x4(%rdi,%rax,8), %ebp
    d6c2: 83 e5 e0                     	andl	$-0x20, %ebp
    d6c5: 09 c5                        	orl	%eax, %ebp
    d6c7: 89 6c c7 04                  	movl	%ebp, 0x4(%rdi,%rax,8)
    d6cb: 48 ff c0                     	incq	%rax
    d6ce: 48 83 f8 20                  	cmpq	$0x20, %rax
    d6d2: 75 dc                        	jne	0xd6b0 <PT_LOAD#0+0xd6b0>
    d6d4: eb 58                        	jmp	0xd72e <PT_LOAD#0+0xd72e>
    d6d6: 48 8b 74 24 f8               	movq	-0x8(%rsp), %rsi
    d6db: 48 8b 5c 24 f0               	movq	-0x10(%rsp), %rbx
    d6e0: 4c 8b 4c 24 e8               	movq	-0x18(%rsp), %r9
    d6e5: 41 83 fd 1f                  	cmpl	$0x1f, %r13d
    d6e9: 77 43                        	ja	0xd72e <PT_LOAD#0+0xd72e>
    d6eb: 48 8d 15 46 57 02 00         	leaq	0x25746(%rip), %rdx     # 0x32e38 <PT_LOAD#0+0x32e38>
    d6f2: 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	nopw	%cs:(%rax,%rax)
    d700: 48 8b 02                     	movq	(%rdx), %rax
    d703: 44 89 ed                     	movl	%r13d, %ebp
    d706: 83 e5 1f                     	andl	$0x1f, %ebp
    d709: 4a 89 04 ef                  	movq	%rax, (%rdi,%r13,8)
    d70d: 8b 02                        	movl	(%rdx), %eax
    d70f: 44 01 e8                     	addl	%r13d, %eax
    d712: 42 89 04 ef                  	movl	%eax, (%rdi,%r13,8)
    d716: 42 8b 44 ef 04               	movl	0x4(%rdi,%r13,8), %eax
    d71b: 83 e0 e0                     	andl	$-0x20, %eax
    d71e: 09 c5                        	orl	%eax, %ebp
    d720: 42 89 6c ef 04               	movl	%ebp, 0x4(%rdi,%r13,8)
    d725: 49 ff c5                     	incq	%r13
    d728: 49 83 fd 20                  	cmpq	$0x20, %r13
    d72c: 75 d2                        	jne	0xd700 <PT_LOAD#0+0xd700>
    d72e: 48 85 db                     	testq	%rbx, %rbx
    d731: 74 27                        	je	0xd75a <PT_LOAD#0+0xd75a>
    d733: 48 8b 43 28                  	movq	0x28(%rbx), %rax
    d737: 8b 97 04 01 00 00            	movl	0x104(%rdi), %edx
    d73d: 0b 50 0c                     	orl	0xc(%rax), %edx
    d740: 89 97 04 01 00 00            	movl	%edx, 0x104(%rdi)
    d746: f6 c2 20                     	testb	$0x20, %dl
    d749: 75 0f                        	jne	0xd75a <PT_LOAD#0+0xd75a>
    d74b: 48 8b 43 28                  	movq	0x28(%rbx), %rax
    d74f: 48 8b 40 20                  	movq	0x20(%rax), %rax
    d753: 48 89 87 08 01 00 00         	movq	%rax, 0x108(%rdi)
    d75a: 48 85 f6                     	testq	%rsi, %rsi
    d75d: 74 75                        	je	0xd7d4 <PT_LOAD#0+0xd7d4>
    d75f: 48 8d 05 0a 52 02 00         	leaq	0x2520a(%rip), %rax     # 0x32970 <PT_LOAD#0+0x32970>
    d766: 48 8d 15 2b 52 02 00         	leaq	0x2522b(%rip), %rdx     # 0x32998 <PT_LOAD#0+0x32998>
    d76d: 48 8b 00                     	movq	(%rax), %rax
    d770: 48 89 06                     	movq	%rax, (%rsi)
    d773: 48 8b 12                     	movq	(%rdx), %rdx
    d776: 48 89 56 08                  	movq	%rdx, 0x8(%rsi)
    d77a: 48 8d 15 67 53 02 00         	leaq	0x25367(%rip), %rdx     # 0x32ae8 <PT_LOAD#0+0x32ae8>
    d781: 48 8b 12                     	movq	(%rdx), %rdx
    d784: 48 89 56 10                  	movq	%rdx, 0x10(%rsi)
    d788: 48 c1 ea 20                  	shrq	$0x20, %rdx
    d78c: 83 e2 e0                     	andl	$-0x20, %edx
    d78f: 44 09 ca                     	orl	%r9d, %edx
    d792: 89 56 14                     	movl	%edx, 0x14(%rsi)
    d795: 48 85 c9                     	testq	%rcx, %rcx
    d798: 74 16                        	je	0xd7b0 <PT_LOAD#0+0xd7b0>
    d79a: 48 8b 41 28                  	movq	0x28(%rcx), %rax
    d79e: 48 8b 00                     	movq	(%rax), %rax
    d7a1: 48 89 06                     	movq	%rax, (%rsi)
    d7a4: 48 8b 49 28                  	movq	0x28(%rcx), %rcx
    d7a8: 48 8b 49 28                  	movq	0x28(%rcx), %rcx
    d7ac: 48 89 4e 08                  	movq	%rcx, 0x8(%rsi)
    d7b0: 48 85 db                     	testq	%rbx, %rbx
    d7b3: 74 0c                        	je	0xd7c1 <PT_LOAD#0+0xd7c1>
    d7b5: 48 8b 4b 28                  	movq	0x28(%rbx), %rcx
    d7b9: 48 8b 49 28                  	movq	0x28(%rcx), %rcx
    d7bd: 48 89 4e 08                  	movq	%rcx, 0x8(%rsi)
    d7c1: 48 8d 0d 54 59 02 00         	leaq	0x25954(%rip), %rcx     # 0x3311c <PT_LOAD#0+0x3311c>
    d7c8: 81 39 00 0f 84 00            	cmpl	$0x840f00, (%rcx)       # imm = 0x840F00
    d7ce: 75 04                        	jne	0xd7d4 <PT_LOAD#0+0xd7d4>
    d7d0: 48 89 46 08                  	movq	%rax, 0x8(%rsi)
    d7d4: 31 c0                        	xorl	%eax, %eax
    d7d6: 5b                           	popq	%rbx
    d7d7: 41 5c                        	popq	%r12
    d7d9: 41 5d                        	popq	%r13
    d7db: 41 5e                        	popq	%r14
    d7dd: 41 5f                        	popq	%r15
    d7df: 5d                           	popq	%rbp
    d7e0: c3                           	retq
