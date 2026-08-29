
/tmp/libSceAgcDriver.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    1820: 55                           	push	rbp
    1821: 48 89 e5                     	mov	rbp, rsp
    1824: 41 57                        	push	r15
    1826: 41 56                        	push	r14
    1828: 41 55                        	push	r13
    182a: 41 54                        	push	r12
    182c: 53                           	push	rbx
    182d: 50                           	push	rax
    182e: 4c 8d 3d d3 90 01 00         	lea	r15, [rip + 0x190d3]    # 0x1a908 <PT_LOAD#0+0x1a908>
    1835: 49 89 f6                     	mov	r14, rsi
    1838: 49 89 fc                     	mov	r12, rdi
    183b: 41 8b 87 a0 00 00 00         	mov	eax, dword ptr [r15 + 0xa0]
    1842: 85 c0                        	test	eax, eax
    1844: 74 37                        	je	0x187d <PT_LOAD#0+0x187d>
    1846: 4d 8d 6f 48                  	lea	r13, [r15 + 0x48]
    184a: 31 db                        	xor	ebx, ebx
    184c: eb 10                        	jmp	0x185e <PT_LOAD#0+0x185e>
    184e: 66 90                        	nop
    1850: 48 ff c3                     	inc	rbx
    1853: 89 c1                        	mov	ecx, eax
    1855: 49 83 c5 78                  	add	r13, 0x78
    1859: 48 39 cb                     	cmp	rbx, rcx
    185c: 73 1f                        	jae	0x187d <PT_LOAD#0+0x187d>
    185e: 49 8b 4d 00                  	mov	rcx, qword ptr [r13]
    1862: 48 85 c9                     	test	rcx, rcx
    1865: 74 e9                        	je	0x1850 <PT_LOAD#0+0x1850>
    1867: 4c 89 e7                     	mov	rdi, r12
    186a: 4c 89 f6                     	mov	rsi, r14
    186d: ba 01 00 00 00               	mov	edx, 0x1
    1872: ff d1                        	call	rcx
    1874: 41 8b 87 a0 00 00 00         	mov	eax, dword ptr [r15 + 0xa0]
    187b: eb d3                        	jmp	0x1850 <PT_LOAD#0+0x1850>
    187d: 41 8b 87 a4 00 00 00         	mov	eax, dword ptr [r15 + 0xa4]
    1884: 4c 89 e7                     	mov	rdi, r12
    1887: 4c 89 f6                     	mov	rsi, r14
    188a: 48 6b c0 78                  	imul	rax, rax, 0x78
    188e: 49 8b 44 07 50               	mov	rax, qword ptr [r15 + rax + 0x50]
    1893: 48 83 c4 08                  	add	rsp, 0x8
    1897: 5b                           	pop	rbx
    1898: 41 5c                        	pop	r12
    189a: 41 5d                        	pop	r13
    189c: 41 5e                        	pop	r14
    189e: 41 5f                        	pop	r15
    18a0: 5d                           	pop	rbp
    18a1: ff e0                        	jmp	rax
    18a3: cc                           	int3
    18a4: cc                           	int3
    18a5: cc                           	int3
    18a6: cc                           	int3
    18a7: cc                           	int3
