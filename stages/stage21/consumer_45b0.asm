
/tmp/libSceAgcDriver.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    45b0: 55                           	push	rbp
    45b1: 48 89 e5                     	mov	rbp, rsp
    45b4: 41 57                        	push	r15
    45b6: 41 56                        	push	r14
    45b8: 41 55                        	push	r13
    45ba: 41 54                        	push	r12
    45bc: 53                           	push	rbx
    45bd: 50                           	push	rax
    45be: 48 8d 05 43 63 01 00         	lea	rax, [rip + 0x16343]    # 0x1a908 <PT_LOAD#0+0x1a908>
    45c5: 41 89 d6                     	mov	r14d, edx
    45c8: 49 89 f7                     	mov	r15, rsi
    45cb: 49 89 fd                     	mov	r13, rdi
    45ce: 8b 80 a0 00 00 00            	mov	eax, dword ptr [rax + 0xa0]
    45d4: 85 c0                        	test	eax, eax
    45d6: 74 48                        	je	0x4620 <PT_LOAD#0+0x4620>
    45d8: 48 8d 0d 29 63 01 00         	lea	rcx, [rip + 0x16329]    # 0x1a908 <PT_LOAD#0+0x1a908>
    45df: 45 31 e4                     	xor	r12d, r12d
    45e2: 48 8d 59 48                  	lea	rbx, [rcx + 0x48]
    45e6: eb 16                        	jmp	0x45fe <PT_LOAD#0+0x45fe>
    45e8: 0f 1f 84 00 00 00 00 00      	nop	dword ptr [rax + rax]
    45f0: 49 ff c4                     	inc	r12
    45f3: 89 c1                        	mov	ecx, eax
    45f5: 48 83 c3 78                  	add	rbx, 0x78
    45f9: 49 39 cc                     	cmp	r12, rcx
    45fc: 73 22                        	jae	0x4620 <PT_LOAD#0+0x4620>
    45fe: 48 8b 0b                     	mov	rcx, qword ptr [rbx]
    4601: 48 85 c9                     	test	rcx, rcx
    4604: 74 ea                        	je	0x45f0 <PT_LOAD#0+0x45f0>
    4606: 4c 89 ef                     	mov	rdi, r13
    4609: 4c 89 fe                     	mov	rsi, r15
    460c: 44 89 f2                     	mov	edx, r14d
    460f: ff d1                        	call	rcx
    4611: 48 8d 05 f0 62 01 00         	lea	rax, [rip + 0x162f0]    # 0x1a908 <PT_LOAD#0+0x1a908>
    4618: 8b 80 a0 00 00 00            	mov	eax, dword ptr [rax + 0xa0]
    461e: eb d0                        	jmp	0x45f0 <PT_LOAD#0+0x45f0>
    4620: 48 8d 0d e1 62 01 00         	lea	rcx, [rip + 0x162e1]    # 0x1a908 <PT_LOAD#0+0x1a908>
    4627: 4c 89 ef                     	mov	rdi, r13
    462a: 4c 89 fe                     	mov	rsi, r15
    462d: 44 89 f2                     	mov	edx, r14d
    4630: 8b 81 a4 00 00 00            	mov	eax, dword ptr [rcx + 0xa4]
    4636: 48 6b c0 78                  	imul	rax, rax, 0x78
    463a: 48 8b 44 01 58               	mov	rax, qword ptr [rcx + rax + 0x58]
    463f: 48 83 c4 08                  	add	rsp, 0x8
    4643: 5b                           	pop	rbx
    4644: 41 5c                        	pop	r12
    4646: 41 5d                        	pop	r13
    4648: 41 5e                        	pop	r14
    464a: 41 5f                        	pop	r15
    464c: 5d                           	pop	rbp
    464d: ff e0                        	jmp	rax
    464f: cc                           	int3
