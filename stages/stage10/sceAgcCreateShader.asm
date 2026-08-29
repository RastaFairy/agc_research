
/mnt/data/libSceAgc.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    c380: 55                           	pushq	%rbp
    c381: 48 89 e5                     	movq	%rsp, %rbp
    c384: 41 57                        	pushq	%r15
    c386: 41 56                        	pushq	%r14
    c388: 41 55                        	pushq	%r13
    c38a: 41 54                        	pushq	%r12
    c38c: 53                           	pushq	%rbx
    c38d: 50                           	pushq	%rax
    c38e: 81 3e 31 32 33 34            	cmpl	$0x34333231, (%rsi)     # imm = 0x34333231
    c394: bb 03 00 6c 8a               	movl	$0x8a6c0003, %ebx       # imm = 0x8A6C0003
    c399: 0f 85 3a 03 00 00            	jne	0xc6d9 <PT_LOAD#0+0xc6d9>
    c39f: 83 7e 04 18                  	cmpl	$0x18, 0x4(%rsi)
    c3a3: 49 89 f4                     	movq	%rsi, %r12
    c3a6: bb 04 00 6c 8a               	movl	$0x8a6c0004, %ebx       # imm = 0x8A6C0004
    c3ab: 0f 85 28 03 00 00            	jne	0xc6d9 <PT_LOAD#0+0xc6d9>
    c3b1: 49 83 7c 24 10 00            	cmpq	$0x0, 0x10(%r12)
    c3b7: bb 1f 00 6c 8a               	movl	$0x8a6c001f, %ebx       # imm = 0x8A6C001F
    c3bc: 0f 85 17 03 00 00            	jne	0xc6d9 <PT_LOAD#0+0xc6d9>
    c3c2: 4c 8d 2d 47 69 02 00         	leaq	0x26947(%rip), %r13     # 0x32d10 <PT_LOAD#0+0x32d10>
    c3c9: bb 2f 00 6c 8a               	movl	$0x8a6c002f, %ebx       # imm = 0x8A6C002F
    c3ce: 41 81 7d 00 00 00 00 10      	cmpl	$0x10000000, (%r13)     # imm = 0x10000000
    c3d6: 0f 84 fd 02 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c3dc: 41 83 7c 24 4c 00            	cmpl	$0x0, 0x4c(%r12)
    c3e2: 49 89 d7                     	movq	%rdx, %r15
    c3e5: 49 89 fe                     	movq	%rdi, %r14
    c3e8: 79 12                        	jns	0xc3fc <PT_LOAD#0+0xc3fc>
    c3ea: bb 42 00 6c 8a               	movl	$0x8a6c0042, %ebx       # imm = 0x8A6C0042
    c3ef: e8 ac 63 00 00               	callq	0x127a0 <PT_LOAD#0+0x127a0>
    c3f4: 84 c0                        	testb	%al, %al
    c3f6: 0f 84 dd 02 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c3fc: 49 8b 44 24 08               	movq	0x8(%r12), %rax
    c401: 49 8d 4c 24 08               	leaq	0x8(%r12), %rcx
    c406: 48 85 c0                     	testq	%rax, %rax
    c409: 74 08                        	je	0xc413 <PT_LOAD#0+0xc413>
    c40b: 48 01 c8                     	addq	%rcx, %rax
    c40e: 48 89 01                     	movq	%rax, (%rcx)
    c411: eb 02                        	jmp	0xc415 <PT_LOAD#0+0xc415>
    c413: 31 c0                        	xorl	%eax, %eax
    c415: 49 8b 54 24 28               	movq	0x28(%r12), %rdx
    c41a: 48 85 d2                     	testq	%rdx, %rdx
    c41d: 74 0b                        	je	0xc42a <PT_LOAD#0+0xc42a>
    c41f: 49 8d 74 24 28               	leaq	0x28(%r12), %rsi
    c424: 48 01 f2                     	addq	%rsi, %rdx
    c427: 48 89 16                     	movq	%rdx, (%rsi)
    c42a: 49 8b 54 24 18               	movq	0x18(%r12), %rdx
    c42f: 48 85 d2                     	testq	%rdx, %rdx
    c432: 74 0b                        	je	0xc43f <PT_LOAD#0+0xc43f>
    c434: 49 8d 74 24 18               	leaq	0x18(%r12), %rsi
    c439: 48 01 f2                     	addq	%rsi, %rdx
    c43c: 48 89 16                     	movq	%rdx, (%rsi)
    c43f: 49 8b 54 24 20               	movq	0x20(%r12), %rdx
    c444: 48 85 d2                     	testq	%rdx, %rdx
    c447: 74 0b                        	je	0xc454 <PT_LOAD#0+0xc454>
    c449: 49 8d 74 24 20               	leaq	0x20(%r12), %rsi
    c44e: 48 01 f2                     	addq	%rsi, %rdx
    c451: 48 89 16                     	movq	%rdx, (%rsi)
    c454: 49 8b 54 24 30               	movq	0x30(%r12), %rdx
    c459: 48 85 d2                     	testq	%rdx, %rdx
    c45c: 74 0b                        	je	0xc469 <PT_LOAD#0+0xc469>
    c45e: 49 8d 74 24 30               	leaq	0x30(%r12), %rsi
    c463: 48 01 f2                     	addq	%rsi, %rdx
    c466: 48 89 16                     	movq	%rdx, (%rsi)
    c469: 49 8b 54 24 38               	movq	0x38(%r12), %rdx
    c46e: 48 85 d2                     	testq	%rdx, %rdx
    c471: 74 0b                        	je	0xc47e <PT_LOAD#0+0xc47e>
    c473: 49 8d 74 24 38               	leaq	0x38(%r12), %rsi
    c478: 48 01 f2                     	addq	%rsi, %rdx
    c47b: 48 89 16                     	movq	%rdx, (%rsi)
    c47e: 48 8b 10                     	movq	(%rax), %rdx
    c481: 48 85 d2                     	testq	%rdx, %rdx
    c484: 74 09                        	je	0xc48f <PT_LOAD#0+0xc48f>
    c486: 48 01 c2                     	addq	%rax, %rdx
    c489: 48 89 10                     	movq	%rdx, (%rax)
    c48c: 48 8b 01                     	movq	(%rcx), %rax
    c48f: 48 8b 48 08                  	movq	0x8(%rax), %rcx
    c493: 48 85 c9                     	testq	%rcx, %rcx
    c496: 74 0a                        	je	0xc4a2 <PT_LOAD#0+0xc4a2>
    c498: 48 8d 50 08                  	leaq	0x8(%rax), %rdx
    c49c: 48 01 d1                     	addq	%rdx, %rcx
    c49f: 48 89 0a                     	movq	%rcx, (%rdx)
    c4a2: 48 8b 48 10                  	movq	0x10(%rax), %rcx
    c4a6: 48 85 c9                     	testq	%rcx, %rcx
    c4a9: 74 0a                        	je	0xc4b5 <PT_LOAD#0+0xc4b5>
    c4ab: 48 8d 50 10                  	leaq	0x10(%rax), %rdx
    c4af: 48 01 d1                     	addq	%rdx, %rcx
    c4b2: 48 89 0a                     	movq	%rcx, (%rdx)
    c4b5: 48 8b 48 18                  	movq	0x18(%rax), %rcx
    c4b9: 48 85 c9                     	testq	%rcx, %rcx
    c4bc: 74 0a                        	je	0xc4c8 <PT_LOAD#0+0xc4c8>
    c4be: 48 8d 50 18                  	leaq	0x18(%rax), %rdx
    c4c2: 48 01 d1                     	addq	%rdx, %rcx
    c4c5: 48 89 0a                     	movq	%rcx, (%rdx)
    c4c8: 48 8b 48 20                  	movq	0x20(%rax), %rcx
    c4cc: 48 85 c9                     	testq	%rcx, %rcx
    c4cf: 74 0a                        	je	0xc4db <PT_LOAD#0+0xc4db>
    c4d1: 48 83 c0 20                  	addq	$0x20, %rax
    c4d5: 48 01 c1                     	addq	%rax, %rcx
    c4d8: 48 89 08                     	movq	%rcx, (%rax)
    c4db: 4d 89 7c 24 10               	movq	%r15, 0x10(%r12)
    c4e0: 41 0f b6 44 24 5a            	movzbl	0x5a(%r12), %eax
    c4e6: 48 83 f8 07                  	cmpq	$0x7, %rax
    c4ea: 0f 87 e4 01 00 00            	ja	0xc6d4 <PT_LOAD#0+0xc6d4>
    c4f0: 48 8d 0d 0d c8 01 00         	leaq	0x1c80d(%rip), %rcx     # 0x28d04 <PT_LOAD#0+0x28d04>
    c4f7: 48 63 04 81                  	movslq	(%rcx,%rax,4), %rax
    c4fb: 48 01 c8                     	addq	%rcx, %rax
    c4fe: ff e0                        	jmpq	*%rax
    c500: 41 0f b6 44 24 5c            	movzbl	0x5c(%r12), %eax
    c506: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c50b: 48 85 c0                     	testq	%rax, %rax
    c50e: 0f 84 c5 01 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c514: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c519: 41 8b 55 00                  	movl	(%r13), %edx
    c51d: 48 c1 e0 03                  	shlq	$0x3, %rax
    c521: 31 f6                        	xorl	%esi, %esi
    c523: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c527: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c52a: 0f 84 75 01 00 00            	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c530: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c534: 48 89 c1                     	movq	%rax, %rcx
    c537: 48 83 c7 08                  	addq	$0x8, %rdi
    c53b: 48 01 f1                     	addq	%rsi, %rcx
    c53e: 75 e7                        	jne	0xc527 <PT_LOAD#0+0xc527>
    c540: e9 94 01 00 00               	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c545: 41 0f b6 4c 24 5c            	movzbl	0x5c(%r12), %ecx
    c54b: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c550: 48 85 c9                     	testq	%rcx, %rcx
    c553: 0f 84 80 01 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c559: 48 8d 05 00 68 02 00         	leaq	0x26800(%rip), %rax     # 0x32d60 <PT_LOAD#0+0x32d60>
    c560: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c565: 48 c1 e1 03                  	shlq	$0x3, %rcx
    c569: 31 f6                        	xorl	%esi, %esi
    c56b: 8b 10                        	movl	(%rax), %edx
    c56d: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c571: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c574: 0f 84 2b 01 00 00            	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c57a: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c57e: 48 89 c8                     	movq	%rcx, %rax
    c581: 48 83 c7 08                  	addq	$0x8, %rdi
    c585: 48 01 f0                     	addq	%rsi, %rax
    c588: 75 e7                        	jne	0xc571 <PT_LOAD#0+0xc571>
    c58a: e9 4a 01 00 00               	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c58f: 41 0f b6 4c 24 5c            	movzbl	0x5c(%r12), %ecx
    c595: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c59a: 48 85 c9                     	testq	%rcx, %rcx
    c59d: 0f 84 36 01 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c5a3: 48 8d 05 76 67 02 00         	leaq	0x26776(%rip), %rax     # 0x32d20 <PT_LOAD#0+0x32d20>
    c5aa: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c5af: 48 c1 e1 03                  	shlq	$0x3, %rcx
    c5b3: 31 f6                        	xorl	%esi, %esi
    c5b5: 8b 10                        	movl	(%rax), %edx
    c5b7: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c5bb: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c5be: 0f 84 e1 00 00 00            	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c5c4: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c5c8: 48 89 c8                     	movq	%rcx, %rax
    c5cb: 48 83 c7 08                  	addq	$0x8, %rdi
    c5cf: 48 01 f0                     	addq	%rsi, %rax
    c5d2: 75 e7                        	jne	0xc5bb <PT_LOAD#0+0xc5bb>
    c5d4: e9 00 01 00 00               	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c5d9: 41 0f b6 4c 24 5c            	movzbl	0x5c(%r12), %ecx
    c5df: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c5e4: 48 85 c9                     	testq	%rcx, %rcx
    c5e7: 0f 84 ec 00 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c5ed: 48 8d 05 5c 67 02 00         	leaq	0x2675c(%rip), %rax     # 0x32d50 <PT_LOAD#0+0x32d50>
    c5f4: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c5f9: 48 c1 e1 03                  	shlq	$0x3, %rcx
    c5fd: 31 f6                        	xorl	%esi, %esi
    c5ff: 8b 10                        	movl	(%rax), %edx
    c601: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c605: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c608: 0f 84 97 00 00 00            	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c60e: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c612: 48 89 c8                     	movq	%rcx, %rax
    c615: 48 83 c7 08                  	addq	$0x8, %rdi
    c619: 48 01 f0                     	addq	%rsi, %rax
    c61c: 75 e7                        	jne	0xc605 <PT_LOAD#0+0xc605>
    c61e: e9 b6 00 00 00               	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c623: 41 0f b6 4c 24 5c            	movzbl	0x5c(%r12), %ecx
    c629: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c62e: 48 85 c9                     	testq	%rcx, %rcx
    c631: 0f 84 a2 00 00 00            	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c637: 48 8d 05 f2 66 02 00         	leaq	0x266f2(%rip), %rax     # 0x32d30 <PT_LOAD#0+0x32d30>
    c63e: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c643: 48 c1 e1 03                  	shlq	$0x3, %rcx
    c647: 31 f6                        	xorl	%esi, %esi
    c649: 8b 10                        	movl	(%rax), %edx
    c64b: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c64f: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c652: 74 51                        	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c654: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c658: 48 89 c8                     	movq	%rcx, %rax
    c65b: 48 83 c7 08                  	addq	$0x8, %rdi
    c65f: 48 01 f0                     	addq	%rsi, %rax
    c662: 75 eb                        	jne	0xc64f <PT_LOAD#0+0xc64f>
    c664: eb 73                        	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c666: 41 0f b6 4c 24 5c            	movzbl	0x5c(%r12), %ecx
    c66c: bb 05 00 6c 8a               	movl	$0x8a6c0005, %ebx       # imm = 0x8A6C0005
    c671: 48 85 c9                     	testq	%rcx, %rcx
    c674: 74 63                        	je	0xc6d9 <PT_LOAD#0+0xc6d9>
    c676: 48 8d 05 c3 66 02 00         	leaq	0x266c3(%rip), %rax     # 0x32d40 <PT_LOAD#0+0x32d40>
    c67d: 4d 8b 44 24 20               	movq	0x20(%r12), %r8
    c682: 48 c1 e1 03                  	shlq	$0x3, %rcx
    c686: 31 f6                        	xorl	%esi, %esi
    c688: 8b 10                        	movl	(%rax), %edx
    c68a: 49 8d 78 0c                  	leaq	0xc(%r8), %rdi
    c68e: 3b 57 f4                     	cmpl	-0xc(%rdi), %edx
    c691: 74 12                        	je	0xc6a5 <PT_LOAD#0+0xc6a5>
    c693: 48 83 c6 f8                  	addq	$-0x8, %rsi
    c697: 48 89 c8                     	movq	%rcx, %rax
    c69a: 48 83 c7 08                  	addq	$0x8, %rdi
    c69e: 48 01 f0                     	addq	%rsi, %rax
    c6a1: 75 eb                        	jne	0xc68e <PT_LOAD#0+0xc68e>
    c6a3: eb 34                        	jmp	0xc6d9 <PT_LOAD#0+0xc6d9>
    c6a5: 49 29 f0                     	subq	%rsi, %r8
    c6a8: 49 8d 48 0c                  	leaq	0xc(%r8), %rcx
    c6ac: 49 83 c0 04                  	addq	$0x4, %r8
    c6b0: 0f b6 01                     	movzbl	(%rcx), %eax
    c6b3: 41 8b 10                     	movl	(%r8), %edx
    c6b6: 48 c1 e2 08                  	shlq	$0x8, %rdx
    c6ba: 48 c1 e0 28                  	shlq	$0x28, %rax
    c6be: 48 09 c2                     	orq	%rax, %rdx
    c6c1: 4c 01 fa                     	addq	%r15, %rdx
    c6c4: 48 89 d0                     	movq	%rdx, %rax
    c6c7: 48 c1 ea 08                  	shrq	$0x8, %rdx
    c6cb: 48 c1 e8 28                  	shrq	$0x28, %rax
    c6cf: 88 01                        	movb	%al, (%rcx)
    c6d1: 41 89 10                     	movl	%edx, (%r8)
    c6d4: 31 db                        	xorl	%ebx, %ebx
    c6d6: 4d 89 26                     	movq	%r12, (%r14)
    c6d9: 89 d8                        	movl	%ebx, %eax
    c6db: 48 83 c4 08                  	addq	$0x8, %rsp
    c6df: 5b                           	popq	%rbx
    c6e0: 41 5c                        	popq	%r12
    c6e2: 41 5d                        	popq	%r13
    c6e4: 41 5e                        	popq	%r14
    c6e6: 41 5f                        	popq	%r15
    c6e8: 5d                           	popq	%rbp
    c6e9: c3                           	retq
    c6ea: cc                           	int3
    c6eb: cc                           	int3
    c6ec: cc                           	int3
    c6ed: cc                           	int3
    c6ee: cc                           	int3
    c6ef: cc                           	int3
    c6f0: 8a 4e 5a                     	movb	0x5a(%rsi), %cl
    c6f3: b8 08 00 6c 8a               	movl	$0x8a6c0008, %eax       # imm = 0x8A6C0008
    c6f8: 80 f9 05                     	cmpb	$0x5, %cl
