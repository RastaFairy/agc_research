
/mnt/data/libSceAgc.sprx:	file format elf64-x86-64

Disassembly of section PT_LOAD#0:

0000000000000000 <PT_LOAD#0>:
    8770: 83 ff 09                     	cmpl	$0x9, %edi
    8773: 77 46                        	ja	0x87bb <PT_LOAD#0+0x87bb>
    8775: 89 f8                        	movl	%edi, %eax
    8777: 48 8d 0d 32 e8 00 00         	leaq	0xe832(%rip), %rcx      # 0x16fb0 <PT_LOAD#0+0x16fb0>
    877e: 48 63 04 81                  	movslq	(%rcx,%rax,4), %rax
    8782: 48 01 c8                     	addq	%rcx, %rax
    8785: ff e0                        	jmpq	*%rax
    8787: 48 8d 05 8e a9 02 00         	leaq	0x2a98e(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    878e: 8b 00                        	movl	(%rax), %eax
    8790: 83 e0 e0                     	andl	$-0x20, %eax
    8793: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    8798: 0f 84 90 00 00 00            	je	0x882e <PT_LOAD#0+0x882e>
    879e: e9 8d 3a 00 00               	jmp	0xc230 <PT_LOAD#0+0xc230>
    87a3: 48 8d 05 72 a9 02 00         	leaq	0x2a972(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    87aa: 8b 00                        	movl	(%rax), %eax
    87ac: 83 e0 e0                     	andl	$-0x20, %eax
    87af: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    87b4: 74 78                        	je	0x882e <PT_LOAD#0+0x882e>
    87b6: e9 f5 3a 00 00               	jmp	0xc2b0 <PT_LOAD#0+0xc2b0>
    87bb: 48 8d 05 5a a9 02 00         	leaq	0x2a95a(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    87c2: 8b 00                        	movl	(%rax), %eax
    87c4: 83 e0 e0                     	andl	$-0x20, %eax
    87c7: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    87cc: 74 60                        	je	0x882e <PT_LOAD#0+0x882e>
    87ce: e9 1d 3a 00 00               	jmp	0xc1f0 <PT_LOAD#0+0xc1f0>
    87d3: 48 8d 05 42 a9 02 00         	leaq	0x2a942(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    87da: 8b 00                        	movl	(%rax), %eax
    87dc: 83 e0 e0                     	andl	$-0x20, %eax
    87df: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    87e4: 74 48                        	je	0x882e <PT_LOAD#0+0x882e>
    87e6: e9 85 3a 00 00               	jmp	0xc270 <PT_LOAD#0+0xc270>
    87eb: 48 8d 05 2a a9 02 00         	leaq	0x2a92a(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    87f2: 8b 00                        	movl	(%rax), %eax
    87f4: 83 e0 e0                     	andl	$-0x20, %eax
    87f7: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    87fc: 74 30                        	je	0x882e <PT_LOAD#0+0x882e>
    87fe: e9 ed 3a 00 00               	jmp	0xc2f0 <PT_LOAD#0+0xc2f0>
    8803: 48 8d 05 12 a9 02 00         	leaq	0x2a912(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    880a: 8b 00                        	movl	(%rax), %eax
    880c: 83 e0 e0                     	andl	$-0x20, %eax
    880f: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    8814: 74 18                        	je	0x882e <PT_LOAD#0+0x882e>
    8816: e9 55 3b 00 00               	jmp	0xc370 <PT_LOAD#0+0xc370>
    881b: 48 8d 05 fa a8 02 00         	leaq	0x2a8fa(%rip), %rax     # 0x3311c <PT_LOAD#0+0x3311c>
    8822: 8b 00                        	movl	(%rax), %eax
    8824: 83 e0 e0                     	andl	$-0x20, %eax
    8827: 3d 00 0f 84 00               	cmpl	$0x840f00, %eax         # imm = 0x840F00
    882c: 75 05                        	jne	0x8833 <PT_LOAD#0+0x8833>
    882e: e9 7d 39 00 00               	jmp	0xc1b0 <PT_LOAD#0+0xc1b0>
    8833: e9 f8 3a 00 00               	jmp	0xc330 <PT_LOAD#0+0xc330>
