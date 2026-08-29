
/mnt/data/libSceAgcDriver.sprx:     file format binary


Disassembly of section .data:

0000000000005f80 <.data+0x5f80>:
    5f80:	49 89 f7             	mov    %rsi,%r15
    5f83:	e8 08 66 00 00       	call   0xc590
    5f88:	83 f8 01             	cmp    $0x1,%eax
    5f8b:	0f 85 91 02 00 00    	jne    0x6222
    5f91:	41 c7 86 e8 00 00 00 	movl   $0x0,0xe8(%r14)
    5f98:	00 00 00 00 
    5f9c:	48 8b 3d 4d 21 01 00 	mov    0x1214d(%rip),%rdi        # 0x180f0
    5fa3:	48 8d 35 fd d3 00 00 	lea    0xd3fd(%rip),%rsi        # 0x133a7
    5faa:	31 c0                	xor    %eax,%eax
    5fac:	41 8b 56 04          	mov    0x4(%r14),%edx
    5fb0:	e8 cb 8b 00 00       	call   0xeb80
    5fb5:	4c 89 fe             	mov    %r15,%rsi
    5fb8:	4c 8d 35 f9 88 01 00 	lea    0x188f9(%rip),%r14        # 0x1e8b8
    5fbf:	41 83 fd 04          	cmp    $0x4,%r13d
    5fc3:	48 8d 15 9e 88 01 00 	lea    0x1889e(%rip),%rdx        # 0x1e868
    5fca:	4d 89 f7             	mov    %r14,%r15
    5fcd:	4c 0f 44 fa          	cmove  %rdx,%r15
    5fd1:	49 c7 47 08 00 00 00 	movq   $0x0,0x8(%r15)
    5fd8:	00 
    5fd9:	45 89 6f 04          	mov    %r13d,0x4(%r15)
    5fdd:	41 c7 07 38 00 00 00 	movl   $0x38,(%r15)
    5fe4:	41 c7 47 10 00 00 00 	movl   $0x0,0x10(%r15)
    5feb:	00 
    5fec:	41 83 fd 58          	cmp    $0x58,%r13d
    5ff0:	0f 82 9b 00 00 00    	jb     0x6091
    5ff6:	41 8d 45 a8          	lea    -0x58(%r13),%eax
    5ffa:	48 8d 0c c0          	lea    (%rax,%rax,8),%rcx
    5ffe:	48 8d 05 db 83 01 00 	lea    0x183db(%rip),%rax        # 0x1e3e0
    6005:	e9 a0 00 00 00       	jmp    0x60aa
    600a:	48 8b 1d 4f 88 01 00 	mov    0x1884f(%rip),%rbx        # 0x1e860
    6011:	48 8d 05 48 64 01 00 	lea    0x16448(%rip),%rax        # 0x1c460
    6018:	4c 89 a5 b8 fe ff ff 	mov    %r12,-0x148(%rbp)
    601f:	41 8d 55 a8          	lea    -0x58(%r13),%edx
    6023:	45 8d 65 e0          	lea    -0x20(%r13),%r12d
    6027:	bf 08 00 00 00       	mov    $0x8,%edi
    602c:	48 39 c3             	cmp    %rax,%rbx
    602f:	b8 38 00 00 00       	mov    $0x38,%eax
    6034:	44 0f 45 e2          	cmovne %edx,%r12d
    6038:	0f 44 f8             	cmove  %eax,%edi
    603b:	41 39 fc             	cmp    %edi,%r12d
    603e:	73 2d                	jae    0x606d
    6040:	44 89 e0             	mov    %r12d,%eax
    6043:	4c 8d 3c c0          	lea    (%rax,%rax,8),%r15
    6047:	49 c1 e7 04          	shl    $0x4,%r15
    604b:	84 c9                	test   %cl,%cl
    604d:	75 67                	jne    0x60b6
    604f:	42 83 7c 3b 78 00    	cmpl   $0x0,0x78(%rbx,%r15,1)
    6055:	74 5f                	je     0x60b6
    6057:	48 8b 3d 82 20 01 00 	mov    0x12082(%rip),%rdi        # 0x180e0
    605e:	48 8d 35 5b d8 00 00 	lea    0xd85b(%rip),%rsi        # 0x138c0
    6065:	45 31 ff             	xor    %r15d,%r15d
    6068:	44 89 ea             	mov    %r13d,%edx
    606b:	eb 11                	jmp    0x607e
    606d:	48 8b 3d 6c 20 01 00 	mov    0x1206c(%rip),%rdi        # 0x180e0
    6074:	48 8d 35 a0 d2 00 00 	lea    0xd2a0(%rip),%rsi        # 0x1331b
    607b:	44 89 e2             	mov    %r12d,%edx
    607e:	31 c0                	xor    %eax,%eax
    6080:	e8 fb 8a 00 00       	call   0xeb80
    6085:	48 8b 1d 5c 20 01 00 	mov    0x1205c(%rip),%rbx        # 0x180e8
    608c:	e9 a1 02 00 00       	jmp    0x6332
    6091:	41 83 fd 20          	cmp    $0x20,%r13d
    6095:	0f 82 a9 01 00 00    	jb     0x6244
    609b:	41 8d 45 e0          	lea    -0x20(%r13),%eax
    609f:	48 8d 0c c0          	lea    (%rax,%rax,8),%rcx
    60a3:	48 8d 05 b6 63 01 00 	lea    0x163b6(%rip),%rax        # 0x1c460
    60aa:	48 c1 e1 04          	shl    $0x4,%rcx
    60ae:	48 01 c8             	add    %rcx,%rax
    60b1:	e9 90 01 00 00       	jmp    0x6246
    60b6:	48 8d 05 4b 88 01 00 	lea    0x1884b(%rip),%rax        # 0x1e908
    60bd:	48 89 b5 e8 fe ff ff 	mov    %rsi,-0x118(%rbp)
    60c4:	48 8d b5 10 ff ff ff 	lea    -0xf0(%rbp),%rsi
    60cb:	8b 78 04             	mov    0x4(%rax),%edi
    60ce:	e8 8d 62 00 00       	call   0xc360
    60d3:	83 f8 01             	cmp    $0x1,%eax
    60d6:	0f 85 10 02 00 00    	jne    0x62ec
    60dc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    60e0:	44 89 e1             	mov    %r12d,%ecx
    60e3:	c5 f8 10 05 35 e1 00 	vmovups 0xe135(%rip),%xmm0        # 0x14220
    60ea:	00 
    60eb:	c1 e1 0f             	shl    $0xf,%ecx
    60ee:	48 8d 14 08          	lea    (%rax,%rcx,1),%rdx
    60f2:	48 89 95 c8 fe ff ff 	mov    %rdx,-0x138(%rbp)
    60f9:	4a 89 54 3b 60       	mov    %rdx,0x60(%rbx,%r15,1)
    60fe:	48 8d 94 08 00 40 00 	lea    0x4000(%rax,%rcx,1),%rdx
    6105:	00 
    6106:	48 89 95 c0 fe ff ff 	mov    %rdx,-0x140(%rbp)
    610d:	4a 89 54 3b 70       	mov    %rdx,0x70(%rbx,%r15,1)
    6112:	44 89 e2             	mov    %r12d,%edx
    6115:	c1 e2 0c             	shl    $0xc,%edx
    6118:	48 03 95 58 ff ff ff 	add    -0xa8(%rbp),%rdx
    611f:	4a 89 54 3b 68       	mov    %rdx,0x68(%rbx,%r15,1)
    6124:	c4 a1 78 11 44 3b 7c 	vmovups %xmm0,0x7c(%rbx,%r15,1)
    612b:	c7 84 08 00 40 00 00 	movl   $0x0,0x4000(%rax,%rcx,1)
    6132:	00 00 00 00 
    6136:	48 8d 05 cb 87 01 00 	lea    0x187cb(%rip),%rax        # 0x1e908
    613d:	48 89 95 d0 fe ff ff 	mov    %rdx,-0x130(%rbp)
    6144:	42 8b 7c 3b 7c       	mov    0x7c(%rbx,%r15,1),%edi
    6149:	8b 40 04             	mov    0x4(%rax),%eax
    614c:	c1 ef 02             	shr    $0x2,%edi
    614f:	89 85 dc fe ff ff    	mov    %eax,-0x124(%rbp)
    6155:	b8 03 02 00 00       	mov    $0x203,%eax
    615a:	c4 c2 78 f7 c5       	bextr  %eax,%r13d,%eax
    615f:	89 85 e0 fe ff ff    	mov    %eax,-0x120(%rbp)
    6165:	44 89 e8             	mov    %r13d,%eax
    6168:	83 e0 07             	and    $0x7,%eax
    616b:	89 85 e4 fe ff ff    	mov    %eax,-0x11c(%rbp)
    6171:	e8 6a 02 00 00       	call   0x63e0
    6176:	46 8b 9c 3b 80 00 00 	mov    0x80(%rbx,%r15,1),%r11d
    617d:	00 
    617e:	8b bd dc fe ff ff    	mov    -0x124(%rbp),%edi
    6184:	8b 95 e0 fe ff ff    	mov    -0x120(%rbp),%edx
    618a:	8b 8d e4 fe ff ff    	mov    -0x11c(%rbp),%ecx
    6190:	4c 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%r8
    6197:	41 ff c4             	inc    %r12d
    619a:	4e 8d 54 3b 58       	lea    0x58(%rbx,%r15,1),%r10
    619f:	44 89 f6             	mov    %r14d,%esi
    61a2:	41 89 c1             	mov    %eax,%r9d
    61a5:	41 53                	push   %r11
    61a7:	ff b5 d0 fe ff ff    	push   -0x130(%rbp)
    61ad:	6a 00                	push   $0x0
    61af:	41 52                	push   %r10
    61b1:	ff b5 c0 fe ff ff    	push   -0x140(%rbp)
    61b7:	41 54                	push   %r12
    61b9:	e8 c2 6b 00 00       	call   0xcd80
    61be:	48 83 c4 30          	add    $0x30,%rsp
    61c2:	83 f8 01             	cmp    $0x1,%eax
    61c5:	0f 85 40 01 00 00    	jne    0x630b
    61cb:	4a 8d 14 3b          	lea    (%rbx,%r15,1),%rdx
    61cf:	48 89 df             	mov    %rbx,%rdi
    61d2:	4e 8d 74 3b 08       	lea    0x8(%rbx,%r15,1),%r14
    61d7:	48 8b 8d b8 fe ff ff 	mov    -0x148(%rbp),%rcx
    61de:	44 89 2a             	mov    %r13d,(%rdx)
    61e1:	42 c7 44 3b 78 01 00 	movl   $0x1,0x78(%rbx,%r15,1)
    61e8:	00 00 
    61ea:	42 c7 84 3b 88 00 00 	movl   $0x0,0x88(%rbx,%r15,1)
    61f1:	00 00 00 00 00 
    61f6:	48 8b 1d eb 1e 01 00 	mov    0x11eeb(%rip),%rbx        # 0x180e8
    61fd:	48 89 f8             	mov    %rdi,%rax
    6200:	48 85 c9             	test   %rcx,%rcx
    6203:	0f 84 4b 01 00 00    	je     0x6354
    6209:	c5 fc 10 01          	vmovups (%rcx),%ymm0
    620d:	c5 fc 10 49 18       	vmovups 0x18(%rcx),%ymm1
    6212:	c4 c1 7c 11 4e 18    	vmovups %ymm1,0x18(%r14)
    6218:	c4 c1 7c 11 06       	vmovups %ymm0,(%r14)
    621d:	e9 42 01 00 00       	jmp    0x6364
    6222:	48 8b 3d b7 1e 01 00 	mov    0x11eb7(%rip),%rdi        # 0x180e0
    6229:	89 c2                	mov    %eax,%edx
    622b:	48 8d 35 b2 da 00 00 	lea    0xdab2(%rip),%rsi        # 0x13ce4
    6232:	31 c0                	xor    %eax,%eax
    6234:	e8 47 89 00 00       	call   0xeb80
    6239:	41 bf ff ff 6d 8a    	mov    $0x8a6dffff,%r15d
    623f:	e9 ee 00 00 00       	jmp    0x6332
    6244:	31                 	xor    %eax,%eax
