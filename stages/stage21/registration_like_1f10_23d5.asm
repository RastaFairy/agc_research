    1fb0: e8 cb 8b 00 00               	callq	0xab80 <PT_LOAD#0+0xab80>
    1fb5: 4c 89 fe                     	movq	%r15, %rsi
    1fb8: 4c 8d 35 f9 88 01 00         	leaq	0x188f9(%rip), %r14     # 0x1a8b8 <PT_LOAD#0+0x1a8b8>
    1fbf: 41 83 fd 04                  	cmpl	$0x4, %r13d
    1fc3: 48 8d 15 9e 88 01 00         	leaq	0x1889e(%rip), %rdx     # 0x1a868 <PT_LOAD#0+0x1a868>
    1fca: 4d 89 f7                     	movq	%r14, %r15
    1fcd: 4c 0f 44 fa                  	cmoveq	%rdx, %r15
    1fd1: 49 c7 47 08 00 00 00 00      	movq	$0x0, 0x8(%r15)
    1fd9: 45 89 6f 04                  	movl	%r13d, 0x4(%r15)
    1fdd: 41 c7 07 38 00 00 00         	movl	$0x38, (%r15)
    1fe4: 41 c7 47 10 00 00 00 00      	movl	$0x0, 0x10(%r15)
    1fec: 41 83 fd 58                  	cmpl	$0x58, %r13d
    1ff0: 0f 82 9b 00 00 00            	jb	0x2091 <PT_LOAD#0+0x2091>
    1ff6: 41 8d 45 a8                  	leal	-0x58(%r13), %eax
    1ffa: 48 8d 0c c0                  	leaq	(%rax,%rax,8), %rcx
    1ffe: 48 8d 05 db 83 01 00         	leaq	0x183db(%rip), %rax     # 0x1a3e0 <PT_LOAD#0+0x1a3e0>
    2005: e9 a0 00 00 00               	jmp	0x20aa <PT_LOAD#0+0x20aa>
    200a: 48 8b 1d 4f 88 01 00         	movq	0x1884f(%rip), %rbx     # 0x1a860 <PT_LOAD#0+0x1a860>
    2011: 48 8d 05 48 64 01 00         	leaq	0x16448(%rip), %rax     # 0x18460 <PT_LOAD#0+0x18460>
    2018: 4c 89 a5 b8 fe ff ff         	movq	%r12, -0x148(%rbp)
    201f: 41 8d 55 a8                  	leal	-0x58(%r13), %edx
    2023: 45 8d 65 e0                  	leal	-0x20(%r13), %r12d
    2027: bf 08 00 00 00               	movl	$0x8, %edi
    202c: 48 39 c3                     	cmpq	%rax, %rbx
    202f: b8 38 00 00 00               	movl	$0x38, %eax
    2034: 44 0f 45 e2                  	cmovnel	%edx, %r12d
    2038: 0f 44 f8                     	cmovel	%eax, %edi
    203b: 41 39 fc                     	cmpl	%edi, %r12d
    203e: 73 2d                        	jae	0x206d <PT_LOAD#0+0x206d>
    2040: 44 89 e0                     	movl	%r12d, %eax
    2043: 4c 8d 3c c0                  	leaq	(%rax,%rax,8), %r15
    2047: 49 c1 e7 04                  	shlq	$0x4, %r15
    204b: 84 c9                        	testb	%cl, %cl
    204d: 75 67                        	jne	0x20b6 <PT_LOAD#0+0x20b6>
    204f: 42 83 7c 3b 78 00            	cmpl	$0x0, 0x78(%rbx,%r15)
    2055: 74 5f                        	je	0x20b6 <PT_LOAD#0+0x20b6>
    2057: 48 8b 3d 82 20 01 00         	movq	0x12082(%rip), %rdi     # 0x140e0 <PT_LOAD#0+0x140e0>
    205e: 48 8d 35 5b d8 00 00         	leaq	0xd85b(%rip), %rsi      # 0xf8c0 <PT_LOAD#0+0xf8c0>
    2065: 45 31 ff                     	xorl	%r15d, %r15d
    2068: 44 89 ea                     	movl	%r13d, %edx
    206b: eb 11                        	jmp	0x207e <PT_LOAD#0+0x207e>
    206d: 48 8b 3d 6c 20 01 00         	movq	0x1206c(%rip), %rdi     # 0x140e0 <PT_LOAD#0+0x140e0>
    2074: 48 8d 35 a0 d2 00 00         	leaq	0xd2a0(%rip), %rsi      # 0xf31b <PT_LOAD#0+0xf31b>
    207b: 44 89 e2                     	movl	%r12d, %edx
    207e: 31 c0                        	xorl	%eax, %eax
    2080: e8 fb 8a 00 00               	callq	0xab80 <PT_LOAD#0+0xab80>
    2085: 48 8b 1d 5c 20 01 00         	movq	0x1205c(%rip), %rbx     # 0x140e8 <PT_LOAD#0+0x140e8>
    208c: e9 a1 02 00 00               	jmp	0x2332 <PT_LOAD#0+0x2332>
    2091: 41 83 fd 20                  	cmpl	$0x20, %r13d
    2095: 0f 82 a9 01 00 00            	jb	0x2244 <PT_LOAD#0+0x2244>
    209b: 41 8d 45 e0                  	leal	-0x20(%r13), %eax
    209f: 48 8d 0c c0                  	leaq	(%rax,%rax,8), %rcx
    20a3: 48 8d 05 b6 63 01 00         	leaq	0x163b6(%rip), %rax     # 0x18460 <PT_LOAD#0+0x18460>
    20aa: 48 c1 e1 04                  	shlq	$0x4, %rcx
    20ae: 48 01 c8                     	addq	%rcx, %rax
    20b1: e9 90 01 00 00               	jmp	0x2246 <PT_LOAD#0+0x2246>
    20b6: 48 8d 05 4b 88 01 00         	leaq	0x1884b(%rip), %rax     # 0x1a908 <PT_LOAD#0+0x1a908>
    20bd: 48 89 b5 e8 fe ff ff         	movq	%rsi, -0x118(%rbp)
    20c4: 48 8d b5 10 ff ff ff         	leaq	-0xf0(%rbp), %rsi
    20cb: 8b 78 04                     	movl	0x4(%rax), %edi
    20ce: e8 8d 62 00 00               	callq	0x8360 <PT_LOAD#0+0x8360>
    20d3: 83 f8 01                     	cmpl	$0x1, %eax
    20d6: 0f 85 10 02 00 00            	jne	0x22ec <PT_LOAD#0+0x22ec>
    20dc: 48 8b 45 b8                  	movq	-0x48(%rbp), %rax
    20e0: 44 89 e1                     	movl	%r12d, %ecx
    20e3: c5 f8 10 05 35 e1 00 00      	vmovups	0xe135(%rip), %xmm0     # 0x10220 <PT_LOAD#0+0x10220>
    20eb: c1 e1 0f                     	shll	$0xf, %ecx
    20ee: 48 8d 14 08                  	leaq	(%rax,%rcx), %rdx
    20f2: 48 89 95 c8 fe ff ff         	movq	%rdx, -0x138(%rbp)
    20f9: 4a 89 54 3b 60               	movq	%rdx, 0x60(%rbx,%r15)
    20fe: 48 8d 94 08 00 40 00 00      	leaq	0x4000(%rax,%rcx), %rdx
    2106: 48 89 95 c0 fe ff ff         	movq	%rdx, -0x140(%rbp)
    210d: 4a 89 54 3b 70               	movq	%rdx, 0x70(%rbx,%r15)
    2112: 44 89 e2                     	movl	%r12d, %edx
    2115: c1 e2 0c                     	shll	$0xc, %edx
    2118: 48 03 95 58 ff ff ff         	addq	-0xa8(%rbp), %rdx
    211f: 4a 89 54 3b 68               	movq	%rdx, 0x68(%rbx,%r15)
    2124: c4 a1 78 11 44 3b 7c         	vmovups	%xmm0, 0x7c(%rbx,%r15)
    212b: c7 84 08 00 40 00 00 00 00 00 00     	movl	$0x0, 0x4000(%rax,%rcx)
    2136: 48 8d 05 cb 87 01 00         	leaq	0x187cb(%rip), %rax     # 0x1a908 <PT_LOAD#0+0x1a908>
    213d: 48 89 95 d0 fe ff ff         	movq	%rdx, -0x130(%rbp)
    2144: 42 8b 7c 3b 7c               	movl	0x7c(%rbx,%r15), %edi
    2149: 8b 40 04                     	movl	0x4(%rax), %eax
    214c: c1 ef 02                     	shrl	$0x2, %edi
    214f: 89 85 dc fe ff ff            	movl	%eax, -0x124(%rbp)
    2155: b8 03 02 00 00               	movl	$0x203, %eax            # imm = 0x203
    215a: c4 c2 78 f7 c5               	bextrl	%eax, %r13d, %eax
    215f: 89 85 e0 fe ff ff            	movl	%eax, -0x120(%rbp)
    2165: 44 89 e8                     	movl	%r13d, %eax
    2168: 83 e0 07                     	andl	$0x7, %eax
    216b: 89 85 e4 fe ff ff            	movl	%eax, -0x11c(%rbp)
    2171: e8 6a 02 00 00               	callq	0x23e0 <PT_LOAD#0+0x23e0>
    2176: 46 8b 9c 3b 80 00 00 00      	movl	0x80(%rbx,%r15), %r11d
    217e: 8b bd dc fe ff ff            	movl	-0x124(%rbp), %edi
    2184: 8b 95 e0 fe ff ff            	movl	-0x120(%rbp), %edx
    218a: 8b 8d e4 fe ff ff            	movl	-0x11c(%rbp), %ecx
    2190: 4c 8b 85 c8 fe ff ff         	movq	-0x138(%rbp), %r8
    2197: 41 ff c4                     	incl	%r12d
    219a: 4e 8d 54 3b 58               	leaq	0x58(%rbx,%r15), %r10
    219f: 44 89 f6                     	movl	%r14d, %esi
    21a2: 41 89 c1                     	movl	%eax, %r9d
    21a5: 41 53                        	pushq	%r11
    21a7: ff b5 d0 fe ff ff            	pushq	-0x130(%rbp)
    21ad: 6a 00                        	pushq	$0x0
    21af: 41 52                        	pushq	%r10
    21b1: ff b5 c0 fe ff ff            	pushq	-0x140(%rbp)
    21b7: 41 54                        	pushq	%r12
    21b9: e8 c2 6b 00 00               	callq	0x8d80 <PT_LOAD#0+0x8d80>
    21be: 48 83 c4 30                  	addq	$0x30, %rsp
    21c2: 83 f8 01                     	cmpl	$0x1, %eax
    21c5: 0f 85 40 01 00 00            	jne	0x230b <PT_LOAD#0+0x230b>
    21cb: 4a 8d 14 3b                  	leaq	(%rbx,%r15), %rdx
    21cf: 48 89 df                     	movq	%rbx, %rdi
    21d2: 4e 8d 74 3b 08               	leaq	0x8(%rbx,%r15), %r14
    21d7: 48 8b 8d b8 fe ff ff         	movq	-0x148(%rbp), %rcx
    21de: 44 89 2a                     	movl	%r13d, (%rdx)
    21e1: 42 c7 44 3b 78 01 00 00 00   	movl	$0x1, 0x78(%rbx,%r15)
    21ea: 42 c7 84 3b 88 00 00 00 00 00 00 00  	movl	$0x0, 0x88(%rbx,%r15)
    21f6: 48 8b 1d eb 1e 01 00         	movq	0x11eeb(%rip), %rbx     # 0x140e8 <PT_LOAD#0+0x140e8>
    21fd: 48 89 f8                     	movq	%rdi, %rax
    2200: 48 85 c9                     	testq	%rcx, %rcx
    2203: 0f 84 4b 01 00 00            	je	0x2354 <PT_LOAD#0+0x2354>
    2209: c5 fc 10 01                  	vmovups	(%rcx), %ymm0
    220d: c5 fc 10 49 18               	vmovups	0x18(%rcx), %ymm1
    2212: c4 c1 7c 11 4e 18            	vmovups	%ymm1, 0x18(%r14)
    2218: c4 c1 7c 11 06               	vmovups	%ymm0, (%r14)
    221d: e9 42 01 00 00               	jmp	0x2364 <PT_LOAD#0+0x2364>
    2222: 48 8b 3d b7 1e 01 00         	movq	0x11eb7(%rip), %rdi     # 0x140e0 <PT_LOAD#0+0x140e0>
    2229: 89 c2                        	movl	%eax, %edx
    222b: 48 8d 35 b2 da 00 00         	leaq	0xdab2(%rip), %rsi      # 0xfce4 <PT_LOAD#0+0xfce4>
    2232: 31 c0                        	xorl	%eax, %eax
    2234: e8 47 89 00 00               	callq	0xab80 <PT_LOAD#0+0xab80>
    2239: 41 bf ff ff 6d 8a            	movl	$0x8a6dffff, %r15d      # imm = 0x8A6DFFFF
    223f: e9 ee 00 00 00               	jmp	0x2332 <PT_LOAD#0+0x2332>
    2244: 31 c0                        	xorl	%eax, %eax
    2246: 41 83 fd 04                  	cmpl	$0x4, %r13d
    224a: 4c 89 f1                     	movq	%r14, %rcx
    224d: 48 0f 44 ca                  	cmoveq	%rdx, %rcx
    2251: 48 89 41 40                  	movq	%rax, 0x40(%rcx)
    2255: 4d 85 e4                     	testq	%r12, %r12
    2258: 74 1a                        	je	0x2274 <PT_LOAD#0+0x2274>
    225a: c4 c1 7c 10 04 24            	vmovups	(%r12), %ymm0
    2260: c4 c1 7c 10 4c 24 18         	vmovups	0x18(%r12), %ymm1
    2267: c4 c1 7c 11 4f 18            	vmovups	%ymm1, 0x18(%r15)
    226d: c4 c1 7c 11 07               	vmovups	%ymm0, (%r15)
    2272: eb 08                        	jmp	0x227c <PT_LOAD#0+0x227c>
    2274: 41 c7 47 08 00 00 02 00      	movl	$0x20000, 0x8(%r15)     # imm = 0x20000
    227c: 41 83 fd 04                  	cmpl	$0x4, %r13d
    2280: 4d 89 f4                     	movq	%r14, %r12
    2283: 4c 0f 44 e2                  	cmoveq	%rdx, %r12
    2287: 41 80 7c 24 48 00            	cmpb	$0x0, 0x48(%r12)
    228d: 75 55                        	jne	0x22e4 <PT_LOAD#0+0x22e4>
    228f: 48 89 b5 e8 fe ff ff         	movq	%rsi, -0x118(%rbp)
    2296: 48 8d 15 9b d3 00 00         	leaq	0xd39b(%rip), %rdx      # 0xf638 <PT_LOAD#0+0xf638>
    229d: 48 8d bd 10 ff ff ff         	leaq	-0xf0(%rbp), %rdi
    22a4: be 20 00 00 00               	movl	$0x20, %esi
    22a9: 44 89 e9                     	movl	%r13d, %ecx
    22ac: 31 c0                        	xorl	%eax, %eax
    22ae: e8 9d 89 00 00               	callq	0xac50 <PT_LOAD#0+0xac50>
    22b3: 41 83 fd 04                  	cmpl	$0x4, %r13d
    22b7: 48 8d 05 aa 85 01 00         	leaq	0x185aa(%rip), %rax     # 0x1a868 <PT_LOAD#0+0x1a868>
    22be: 48 8d 95 10 ff ff ff         	leaq	-0xf0(%rbp), %rdx
    22c5: 4c 0f 44 f0                  	cmoveq	%rax, %r14
    22c9: 31 f6                        	xorl	%esi, %esi
    22cb: 49 83 c6 38                  	addq	$0x38, %r14
    22cf: 4c 89 f7                     	movq	%r14, %rdi
    22d2: e8 29 89 00 00               	callq	0xac00 <PT_LOAD#0+0xac00>
    22d7: 48 8b b5 e8 fe ff ff         	movq	-0x118(%rbp), %rsi
    22de: 41 c6 44 24 48 01            	movb	$0x1, 0x48(%r12)
    22e4: 4c 89 3e                     	movq	%r15, (%rsi)
    22e7: 45 31 ff                     	xorl	%r15d, %r15d
    22ea: eb 46                        	jmp	0x2332 <PT_LOAD#0+0x2332>
    22ec: 48 8b 0d ed 1d 01 00         	movq	0x11ded(%rip), %rcx     # 0x140e0 <PT_LOAD#0+0x140e0>
    22f3: 48 8d 3d 62 d5 00 00         	leaq	0xd562(%rip), %rdi      # 0xf85c <PT_LOAD#0+0xf85c>
    22fa: be 2d 00 00 00               	movl	$0x2d, %esi
    22ff: ba 01 00 00 00               	movl	$0x1, %edx
    2304: e8 67 88 00 00               	callq	0xab70 <PT_LOAD#0+0xab70>
    2309: eb 1a                        	jmp	0x2325 <PT_LOAD#0+0x2325>
    230b: 48 8b 3d ce 1d 01 00         	movq	0x11dce(%rip), %rdi     # 0x140e0 <PT_LOAD#0+0x140e0>
    2312: 89 c1                        	movl	%eax, %ecx
    2314: 48 8d 35 b8 d0 00 00         	leaq	0xd0b8(%rip), %rsi      # 0xf3d3 <PT_LOAD#0+0xf3d3>
    231b: 44 89 ea                     	movl	%r13d, %edx
    231e: 31 c0                        	xorl	%eax, %eax
    2320: e8 5b 88 00 00               	callq	0xab80 <PT_LOAD#0+0xab80>
    2325: 48 8b 1d bc 1d 01 00         	movq	0x11dbc(%rip), %rbx     # 0x140e8 <PT_LOAD#0+0x140e8>
    232c: 41 bf 00 00 6d 8a            	movl	$0x8a6d0000, %r15d      # imm = 0x8A6D0000
    2332: 48 8b 03                     	movq	(%rbx), %rax
    2335: 48 3b 45 d0                  	cmpq	-0x30(%rbp), %rax
    2339: 0f 85 91 00 00 00            	jne	0x23d0 <PT_LOAD#0+0x23d0>
    233f: 44 89 f8                     	movl	%r15d, %eax
    2342: 48 81 c4 28 01 00 00         	addq	$0x128, %rsp            # imm = 0x128
    2349: 5b                           	popq	%rbx
    234a: 41 5c                        	popq	%r12
    234c: 41 5d                        	popq	%r13
    234e: 41 5e                        	popq	%r14
    2350: 41 5f                        	popq	%r15
    2352: 5d                           	popq	%rbp
    2353: c3                           	retq
    2354: 41 c7 06 38 00 00 00         	movl	$0x38, (%r14)
    235b: 4a c7 44 38 14 00 00 00 00   	movq	$0x0, 0x14(%rax,%r15)
    2364: 4a 89 54 38 48               	movq	%rdx, 0x48(%rax,%r15)
    2369: 46 89 6c 38 0c               	movl	%r13d, 0xc(%rax,%r15)
    236e: 48 8b 8d e8 fe ff ff         	movq	-0x118(%rbp), %rcx
    2375: 42 80 7c 38 50 00            	cmpb	$0x0, 0x50(%rax,%r15)
    237b: 75 4b                        	jne	0x23c8 <PT_LOAD#0+0x23c8>
    237d: 48 8d 15 b4 d2 00 00         	leaq	0xd2b4(%rip), %rdx      # 0xf638 <PT_LOAD#0+0xf638>
    2384: 48 8d bd f0 fe ff ff         	leaq	-0x110(%rbp), %rdi
    238b: be 20 00 00 00               	movl	$0x20, %esi
    2390: 44 89 e9                     	movl	%r13d, %ecx
    2393: 4e 8d 64 38 50               	leaq	0x50(%rax,%r15), %r12
    2398: 48 89 c3                     	movq	%rax, %rbx
    239b: 31 c0                        	xorl	%eax, %eax
    239d: e8 ae 88 00 00               	callq	0xac50 <PT_LOAD#0+0xac50>
    23a2: 4a 8d 7c 3b 40               	leaq	0x40(%rbx,%r15), %rdi
    23a7: 48 8d 95 f0 fe ff ff         	leaq	-0x110(%rbp), %rdx
    23ae: 31 f6                        	xorl	%esi, %esi
    23b0: e8 4b 88 00 00               	callq	0xac00 <PT_LOAD#0+0xac00>
    23b5: 48 8b 8d e8 fe ff ff         	movq	-0x118(%rbp), %rcx
    23bc: 48 8b 1d 25 1d 01 00         	movq	0x11d25(%rip), %rbx     # 0x140e8 <PT_LOAD#0+0x140e8>
    23c3: 41 c6 04 24 01               	movb	$0x1, (%r12)
    23c8: 4c 89 31                     	movq	%r14, (%rcx)
    23cb: e9 17 ff ff ff               	jmp	0x22e7 <PT_LOAD#0+0x22e7>
    23d0: e8 5b 88 00 00               	callq	0xac30 <PT_LOAD#0+0xac30>
    23d5: 0f 0b                        	ud2
    23d7: cc                           	int3
    23d8: cc                           	int3
