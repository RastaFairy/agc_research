
/mnt/data/libSceAgcDriver.sprx:     file format binary


Disassembly of section .data:

0000000000006240 <.data+0x6240>:
    6240:	ee                   	out    %al,(%dx)
    6241:	00 00                	add    %al,(%rax)
    6243:	00 31                	add    %dh,(%rcx)
    6245:	c0 41 83 fd          	rolb   $0xfd,-0x7d(%rcx)
    6249:	04 4c                	add    $0x4c,%al
    624b:	89 f1                	mov    %esi,%ecx
    624d:	48 0f 44 ca          	cmove  %rdx,%rcx
    6251:	48 89 41 40          	mov    %rax,0x40(%rcx)
    6255:	4d 85 e4             	test   %r12,%r12
    6258:	74 1a                	je     0x6274
    625a:	c4 c1 7c 10 04 24    	vmovups (%r12),%ymm0
    6260:	c4 c1 7c 10 4c 24 18 	vmovups 0x18(%r12),%ymm1
    6267:	c4 c1 7c 11 4f 18    	vmovups %ymm1,0x18(%r15)
    626d:	c4 c1 7c 11 07       	vmovups %ymm0,(%r15)
    6272:	eb 08                	jmp    0x627c
    6274:	41 c7 47 08 00 00 02 	movl   $0x20000,0x8(%r15)
    627b:	00 
    627c:	41 83 fd 04          	cmp    $0x4,%r13d
    6280:	4d 89 f4             	mov    %r14,%r12
    6283:	4c 0f 44 e2          	cmove  %rdx,%r12
    6287:	41 80 7c 24 48 00    	cmpb   $0x0,0x48(%r12)
    628d:	75 55                	jne    0x62e4
    628f:	48 89 b5 e8 fe ff ff 	mov    %rsi,-0x118(%rbp)
    6296:	48 8d 15 9b d3 00 00 	lea    0xd39b(%rip),%rdx        # 0x13638
    629d:	48 8d bd 10 ff ff ff 	lea    -0xf0(%rbp),%rdi
    62a4:	be 20 00 00 00       	mov    $0x20,%esi
    62a9:	44 89 e9             	mov    %r13d,%ecx
    62ac:	31 c0                	xor    %eax,%eax
    62ae:	e8 9d 89 00 00       	call   0xec50
    62b3:	41 83 fd 04          	cmp    $0x4,%r13d
    62b7:	48 8d 05 aa 85 01 00 	lea    0x185aa(%rip),%rax        # 0x1e868
    62be:	48 8d 95 10 ff ff ff 	lea    -0xf0(%rbp),%rdx
    62c5:	4c 0f 44 f0          	cmove  %rax,%r14
    62c9:	31 f6                	xor    %esi,%esi
    62cb:	49 83 c6 38          	add    $0x38,%r14
    62cf:	4c 89 f7             	mov    %r14,%rdi
    62d2:	e8 29 89 00 00       	call   0xec00
    62d7:	48 8b b5 e8 fe ff ff 	mov    -0x118(%rbp),%rsi
    62de:	41 c6 44 24 48 01    	movb   $0x1,0x48(%r12)
    62e4:	4c 89 3e             	mov    %r15,(%rsi)
    62e7:	45 31 ff             	xor    %r15d,%r15d
    62ea:	eb 46                	jmp    0x6332
    62ec:	48 8b 0d ed 1d 01 00 	mov    0x11ded(%rip),%rcx        # 0x180e0
    62f3:	48 8d 3d 62 d5 00 00 	lea    0xd562(%rip),%rdi        # 0x1385c
    62fa:	be 2d 00 00 00       	mov    $0x2d,%esi
    62ff:	ba 01 00 00 00       	mov    $0x1,%edx
    6304:	e8 67 88 00 00       	call   0xeb70
    6309:	eb 1a                	jmp    0x6325
    630b:	48 8b 3d ce 1d 01 00 	mov    0x11dce(%rip),%rdi        # 0x180e0
    6312:	89 c1                	mov    %eax,%ecx
    6314:	48 8d 35 b8 d0 00 00 	lea    0xd0b8(%rip),%rsi        # 0x133d3
    631b:	44 89 ea             	mov    %r13d,%edx
    631e:	31 c0                	xor    %eax,%eax
    6320:	e8 5b 88 00 00       	call   0xeb80
    6325:	48 8b 1d bc 1d 01 00 	mov    0x11dbc(%rip),%rbx        # 0x180e8
    632c:	41 bf 00 00 6d 8a    	mov    $0x8a6d0000,%r15d
    6332:	48 8b 03             	mov    (%rbx),%rax
    6335:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
    6339:	0f 85 91 00 00 00    	jne    0x63d0
    633f:	44 89 f8             	mov    %r15d,%eax
    6342:	48 81 c4 28 01 00 00 	add    $0x128,%rsp
    6349:	5b                   	pop    %rbx
    634a:	41 5c                	pop    %r12
    634c:	41 5d                	pop    %r13
    634e:	41 5e                	pop    %r14
    6350:	41 5f                	pop    %r15
    6352:	5d                   	pop    %rbp
    6353:	c3                   	ret
    6354:	41 c7 06 38 00 00 00 	movl   $0x38,(%r14)
    635b:	4a c7 44 38 14 00 00 	movq   $0x0,0x14(%rax,%r15,1)
    6362:	00 00 
    6364:	4a 89 54 38 48       	mov    %rdx,0x48(%rax,%r15,1)
    6369:	46 89 6c 38 0c       	mov    %r13d,0xc(%rax,%r15,1)
    636e:	48 8b 8d e8 fe ff ff 	mov    -0x118(%rbp),%rcx
    6375:	42 80 7c 38 50 00    	cmpb   $0x0,0x50(%rax,%r15,1)
    637b:	75 4b                	jne    0x63c8
    637d:	48 8d 15 b4 d2 00 00 	lea    0xd2b4(%rip),%rdx        # 0x13638
    6384:	48 8d bd f0 fe ff ff 	lea    -0x110(%rbp),%rdi
    638b:	be 20 00 00 00       	mov    $0x20,%esi
    6390:	44 89 e9             	mov    %r13d,%ecx
    6393:	4e 8d 64 38 50       	lea    0x50(%rax,%r15,1),%r12
    6398:	48 89 c3             	mov    %rax,%rbx
    639b:	31 c0                	xor    %eax,%eax
    639d:	e8 ae 88 00 00       	call   0xec50
    63a2:	4a 8d 7c 3b 40       	lea    0x40(%rbx,%r15,1),%rdi
    63a7:	48 8d 95 f0 fe ff ff 	lea    -0x110(%rbp),%rdx
    63ae:	31 f6                	xor    %esi,%esi
    63b0:	e8 4b 88 00 00       	call   0xec00
    63b5:	48 8b 8d e8 fe ff ff 	mov    -0x118(%rbp),%rcx
    63bc:	48 8b 1d 25 1d 01 00 	mov    0x11d25(%rip),%rbx        # 0x180e8
    63c3:	41 c6 04 24 01       	movb   $0x1,(%r12)
    63c8:	4c 89 31             	mov    %r14,(%rcx)
    63cb:	e9 17 ff ff ff       	jmp    0x62e7
    63d0:	e8 5b 88 00 00       	call   0xec30
    63d5:	0f 0b                	ud2
    63d7:	cc                   	int3
    63d8:	cc                   	int3
    63d9:	cc                   	int3
    63da:	cc                   	int3
    63db:	cc                   	int3
    63dc:	cc                   	int3
    63dd:	cc                   	int3
    63de:	cc                   	int3
    63df:	cc                   	int3
    63e0:	31 c0                	xor    %eax,%eax
    63e2:	83 ff 01             	cmp    $0x1,%edi
    63e5:	0f 84 ac 02 00 00    	je     0x6697
    63eb:	89 f9                	mov    %edi,%ecx
    63ed:	b8 01 00 00 00       	mov    $0x1,%eax
    63f2:	83 e1 fe             	and    $0xfffffffe,%ecx
    63f5:	83 f9 02             	cmp    $0x2,%ecx
    63f8:	0f 84 99 02 00 00    	je     0x6697
    63fe:	89 f9                	mov    %edi,%ecx
    6400:	b8 02 00 00 00       	mov    $0x2,%eax
    6405:	83 e1 fc             	and    $0xfffffffc,%ecx
    6408:	83 f9 04             	cmp    $0x4,%ecx
    640b:	0f 84 86 02 00     	je     0x6697
