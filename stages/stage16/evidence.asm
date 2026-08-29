    1820:	55                   	push   %rbp
    1821:	48 89 e5             	mov    %rsp,%rbp
    1824:	41 57                	push   %r15
    1826:	41 56                	push   %r14
    1828:	41 55                	push   %r13
    182a:	41 54                	push   %r12
    182c:	53                   	push   %rbx
    182d:	50                   	push   %rax
    182e:	4c 8d 3d d3 90 01 00 	lea    0x190d3(%rip),%r15        # 0x1a908
    1835:	49 89 f6             	mov    %rsi,%r14
    1838:	49 89 fc             	mov    %rdi,%r12
    183b:	41 8b 87 a0 00 00 00 	mov    0xa0(%r15),%eax
    1842:	85 c0                	test   %eax,%eax
    1844:	74 37                	je     0x187d
    1846:	4d 8d 6f 48          	lea    0x48(%r15),%r13
    184a:	31 db                	xor    %ebx,%ebx
    184c:	eb 10                	jmp    0x185e
    184e:	66 90                	xchg   %ax,%ax
    1850:	48 ff c3             	inc    %rbx
    1853:	89 c1                	mov    %eax,%ecx
    1855:	49 83 c5 78          	add    $0x78,%r13
    1859:	48 39 cb             	cmp    %rcx,%rbx
    185c:	73 1f                	jae    0x187d
    185e:	49 8b 4d 00          	mov    0x0(%r13),%rcx
    1862:	48 85 c9             	test   %rcx,%rcx
    1865:	74 e9                	je     0x1850
    1867:	4c 89 e7             	mov    %r12,%rdi
    186a:	4c 89 f6             	mov    %r14,%rsi
    186d:	ba 01 00 00 00       	mov    $0x1,%edx
    1872:	ff d1                	call   *%rcx
    1874:	41 8b 87 a0 00 00 00 	mov    0xa0(%r15),%eax
    187b:	eb d3                	jmp    0x1850
    187d:	41 8b 87 a4 00 00 00 	mov    0xa4(%r15),%eax
    1884:	4c 89 e7             	mov    %r12,%rdi
    1887:	4c 89 f6             	mov    %r14,%rsi
    188a:	48 6b c0 78          	imul   $0x78,%rax,%rax
    188e:	49 8b 44 07 50       	mov    0x50(%r15,%rax,1),%rax
    1893:	48 83 c4 08          	add    $0x8,%rsp
    1897:	5b                   	pop    %rbx
    1898:	41 5c                	pop    %r12
    189a:	41 5d                	pop    %r13
    189c:	41 5e                	pop    %r14
    189e:	41 5f                	pop    %r15
    18a0:	5d                   	pop    %rbp
    18a1:	ff e0                	jmp    *%rax
    20b6:	48 8d 05 4b 88 01 00 	lea    0x1884b(%rip),%rax        # 0x1a908
    20bd:	48 89 b5 e8 fe ff ff 	mov    %rsi,-0x118(%rbp)
    20c4:	48 8d b5 10 ff ff ff 	lea    -0xf0(%rbp),%rsi
    20cb:	8b 78 04             	mov    0x4(%rax),%edi
    20ce:	e8 8d 62 00 00       	call   0x8360
    20d3:	83 f8 01             	cmp    $0x1,%eax
    20d6:	0f 85 10 02 00 00    	jne    0x22ec
    20dc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    20e0:	44 89 e1             	mov    %r12d,%ecx
    20e3:	c5 f8 10 05 35 e1 00 	vmovups 0xe135(%rip),%xmm0        # 0x10220
    20ea:	00 
    20eb:	c1 e1 0f             	shl    $0xf,%ecx
    20ee:	48 8d 14 08          	lea    (%rax,%rcx,1),%rdx
    20f2:	48 89 95 c8 fe ff ff 	mov    %rdx,-0x138(%rbp)
    20f9:	4a 89 54 3b 60       	mov    %rdx,0x60(%rbx,%r15,1)
    20fe:	48 8d 94 08 00 40 00 	lea    0x4000(%rax,%rcx,1),%rdx
    2105:	00 
    2106:	48 89 95 c0 fe ff ff 	mov    %rdx,-0x140(%rbp)
    210d:	4a 89 54 3b 70       	mov    %rdx,0x70(%rbx,%r15,1)
    2112:	44 89 e2             	mov    %r12d,%edx
    2115:	c1 e2 0c             	shl    $0xc,%edx
    2118:	48 03 95 58 ff ff ff 	add    -0xa8(%rbp),%rdx
    211f:	4a 89 54 3b 68       	mov    %rdx,0x68(%rbx,%r15,1)
    2124:	c4 a1 78 11 44 3b 7c 	vmovups %xmm0,0x7c(%rbx,%r15,1)
    212b:	c7 84 08 00 40 00 00 	movl   $0x0,0x4000(%rax,%rcx,1)
    2132:	00 00 00 00 
    2136:	48 8d 05 cb 87 01 00 	lea    0x187cb(%rip),%rax        # 0x1a908
    213d:	48 89 95 d0 fe ff ff 	mov    %rdx,-0x130(%rbp)
    2144:	42 8b 7c 3b 7c       	mov    0x7c(%rbx,%r15,1),%edi
    2149:	8b 40 04             	mov    0x4(%rax),%eax
    214c:	c1 ef 02             	shr    $0x2,%edi
    214f:	89 85 dc fe ff ff    	mov    %eax,-0x124(%rbp)
    2155:	b8 03 02 00 00       	mov    $0x203,%eax
    215a:	c4 c2 78 f7 c5       	bextr  %eax,%r13d,%eax
    215f:	89 85 e0 fe ff ff    	mov    %eax,-0x120(%rbp)
    2165:	44 89 e8             	mov    %r13d,%eax
    2168:	83 e0 07             	and    $0x7,%eax
    216b:	89 85 e4 fe ff ff    	mov    %eax,-0x11c(%rbp)
    2171:	e8 6a 02 00 00       	call   0x23e0
    2176:	46 8b 9c 3b 80 00 00 	mov    0x80(%rbx,%r15,1),%r11d
    217d:	00 
    217e:	8b bd dc fe ff ff    	mov    -0x124(%rbp),%edi
    2184:	8b 95 e0 fe ff ff    	mov    -0x120(%rbp),%edx
    218a:	8b 8d e4 fe ff ff    	mov    -0x11c(%rbp),%ecx
    2190:	4c 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%r8
    2197:	41 ff c4             	inc    %r12d
    219a:	4e 8d 54 3b 58       	lea    0x58(%rbx,%r15,1),%r10
    219f:	44 89 f6             	mov    %r14d,%esi
    21a2:	41 89 c1             	mov    %eax,%r9d
    21a5:	41 53                	push   %r11
    21a7:	ff b5 d0 fe ff ff    	push   -0x130(%rbp)
    21ad:	6a 00                	push   $0x0
    21af:	41 52                	push   %r10
    21b1:	ff b5 c0 fe ff ff    	push   -0x140(%rbp)
    21b7:	41 54                	push   %r12
    21b9:	e8 c2 6b 00 00       	call   0x8d80
    21be:	48 83 c4 30          	add    $0x30,%rsp
    21c2:	83 f8 01             	cmp    $0x1,%eax
    21c5:	0f 85 40 01 00 00    	jne    0x230b
    21cb:	4a 8d 14 3b          	lea    (%rbx,%r15,1),%rdx
    21cf:	48 89 df             	mov    %rbx,%rdi
    21d2:	4e 8d 74 3b 08       	lea    0x8(%rbx,%r15,1),%r14
    21d7:	48 8b 8d b8 fe ff ff 	mov    -0x148(%rbp),%rcx
    21de:	44 89 2a             	mov    %r13d,(%rdx)
    21e1:	42 c7 44 3b 78 01 00 	movl   $0x1,0x78(%rbx,%r15,1)
    21e8:	00 00 
    21ea:	42 c7 84 3b 88 00 00 	movl   $0x0,0x88(%rbx,%r15,1)
    21f1:	00 00 00 00 00 
    21f6:	48 8b 1d eb 1e 01 00 	mov    0x11eeb(%rip),%rbx        # 0x140e8
    21fd:	48 89 f8             	mov    %rdi,%rax
    2200:	48 85 c9             	test   %rcx,%rcx
    2203:	0f 84 4b 01 00 00    	je     0x2354
    2209:	c5 fc 10 01          	vmovups (%rcx),%ymm0
    220d:	c5 fc 10 49 18       	vmovups 0x18(%rcx),%ymm1
    2212:	c4 c1 7c 11 4e 18    	vmovups %ymm1,0x18(%r14)
    2218:	c4 c1 7c 11 06       	vmovups %ymm0,(%r14)
    221d:	e9 42 01 00 00       	jmp    0x2364
    2332:	48 8b 03             	mov    (%rbx),%rax
    2335:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
    2339:	0f 85 91 00 00 00    	jne    0x23d0
    233f:	44 89 f8             	mov    %r15d,%eax
    2342:	48 81 c4 28 01 00 00 	add    $0x128,%rsp
    2349:	5b                   	pop    %rbx
    234a:	41 5c                	pop    %r12
    234c:	41 5d                	pop    %r13
    234e:	41 5e                	pop    %r14
    2350:	41 5f                	pop    %r15
    2352:	5d                   	pop    %rbp
    2353:	c3                   	ret
    2354:	41 c7 06 38 00 00 00 	movl   $0x38,(%r14)
    235b:	4a c7 44 38 14 00 00 	movq   $0x0,0x14(%rax,%r15,1)
    2362:	00 00 
    2364:	4a 89 54 38 48       	mov    %rdx,0x48(%rax,%r15,1)
    2369:	46 89 6c 38 0c       	mov    %r13d,0xc(%rax,%r15,1)
    236e:	48 8b 8d e8 fe ff ff 	mov    -0x118(%rbp),%rcx
    2375:	42 80 7c 38 50 00    	cmpb   $0x0,0x50(%rax,%r15,1)
    237b:	75 4b                	jne    0x23c8
    237d:	48 8d 15 b4 d2 00 00 	lea    0xd2b4(%rip),%rdx        # 0xf638
    2384:	48 8d bd f0 fe ff ff 	lea    -0x110(%rbp),%rdi
    238b:	be 20 00 00 00       	mov    $0x20,%esi
    2390:	44 89 e9             	mov    %r13d,%ecx
    2393:	4e 8d 64 38 50       	lea    0x50(%rax,%r15,1),%r12
    2398:	48 89 c3             	mov    %rax,%rbx
    239b:	31 c0                	xor    %eax,%eax
    239d:	e8 ae 88 00 00       	call   0xac50
    23a2:	4a 8d 7c 3b 40       	lea    0x40(%rbx,%r15,1),%rdi
    23a7:	48 8d 95 f0 fe ff ff 	lea    -0x110(%rbp),%rdx
    23ae:	31 f6                	xor    %esi,%esi
    23b0:	e8 4b 88 00 00       	call   0xac00
    23b5:	48 8b 8d e8 fe ff ff 	mov    -0x118(%rbp),%rcx
    23bc:	48 8b 1d 25 1d 01 00 	mov    0x11d25(%rip),%rbx        # 0x140e8
    23c3:	41 c6 04 24 01       	movb   $0x1,(%r12)
    23c8:	4c 89 31             	mov    %r14,(%rcx)
      d0:	48 63 c7             	movslq %edi,%rax
      d3:	48 8d 0d 2e a8 01 00 	lea    0x1a82e(%rip),%rcx        # 0x1a908
      da:	48 8d 35 1f 0f 00 00 	lea    0xf1f(%rip),%rsi        # 0x1000
      e1:	48 ba 78 00 00 00 0e 	movabs $0x1000e00000078,%rdx
      e8:	00 01 00 
      eb:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
      ef:	48 8d 3d ca 3b 00 00 	lea    0x3bca(%rip),%rdi        # 0x3cc0
      f6:	48 6b c0 78          	imul   $0x78,%rax,%rax
      fa:	c5 fc 11 84 01 80 00 	vmovups %ymm0,0x80(%rcx,%rax,1)
     101:	00 00 
     103:	c5 fc 11 44 01 30    	vmovups %ymm0,0x30(%rcx,%rax,1)
     109:	c5 fc 11 44 01 50    	vmovups %ymm0,0x50(%rcx,%rax,1)
     10f:	c5 fc 11 44 01 70    	vmovups %ymm0,0x70(%rcx,%rax,1)
     115:	48 89 54 01 28       	mov    %rdx,0x28(%rcx,%rax,1)
     11a:	c6 44 01 35 ff       	movb   $0xff,0x35(%rcx,%rax,1)
     11f:	48 89 74 01 50       	mov    %rsi,0x50(%rcx,%rax,1)
     124:	48 8d 35 05 19 00 00 	lea    0x1905(%rip),%rsi        # 0x1a30
     12b:	48 89 7c 01 58       	mov    %rdi,0x58(%rcx,%rax,1)
     130:	48 8d 3d a9 66 00 00 	lea    0x66a9(%rip),%rdi        # 0x67e0
     137:	48 89 74 01 68       	mov    %rsi,0x68(%rcx,%rax,1)
     13c:	48 8d 35 cd 66 00 00 	lea    0x66cd(%rip),%rsi        # 0x6810
     143:	48 89 bc 01 80 00 00 	mov    %rdi,0x80(%rcx,%rax,1)
     14a:	00 
     14b:	48 89 b4 01 88 00 00 	mov    %rsi,0x88(%rcx,%rax,1)
     152:	00 
     153:	c3                   	ret
