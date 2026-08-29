
/tmp/agcdrv.bin:     file format binary


Disassembly of section .data:

00000000000000d0 <.data+0xd0>:
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
     154:	cc                   	int3
     155:	cc                   	int3
     156:	cc                   	int3
     157:	cc                   	int3
     158:	cc                   	int3
     159:	cc                   	int3
     15a:	cc                   	int3
     15b:	cc                   	int3
     15c:	cc                   	int3
     15d:	cc                   	int3
     15e:	cc                   	int3
     15f:	cc                   	int3
     160:	55                   	push   %rbp
     161:	48 89 e5             	mov    %rsp,%rbp
     164:	48 8d 05 9d a7 01 00 	lea    0x1a79d(%rip),%rax        # 0x1a908
     16b:	83 b8 a0 00 00 00 00 	cmpl   $0x0,0xa0(%rax)
     172:	74 24                	je     0x198
     174:	48 8b 0d 65 3f 01 00 	mov    0x13f65(%rip),%rcx        # 0x140e0
     17b:	48 8d 3d bf f5 00 00 	lea    0xf5bf(%rip),%rdi        # 0xf741
     182:	be 30 00 00 00       	mov    $0x30,%esi
     187:	ba 01 00 00 00       	mov    $0x1,%edx
     18c:	e8 df a9 00 00       	call   0xab70
     191:	b8 06 00 6d 8a       	mov    $0x8a6d0006,%eax
     196:	5d                   	pop    %rbp
     197:	c3                   	ret
     198:	48 8d 15 61 0e 00 00 	lea    0xe61(%rip),%rdx        # 0x1000
     19f:	48 b9 78 00 00 00 0e 	movabs $0x1000e00000078,%rcx
     1a6:	00 01 00 
     1a9:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
     1ad:	c5 fc 11 80 80 00 00 	vmovups %ymm0,0x80(%rax)
     1b4:	00 
     1b5:	c5 fc 11 40 30       	vmovups %ymm0,0x30(%rax)
     1ba:	c5 fc 11 40 50       	vmovups %ymm0,0x50(%rax)
     1bf:	c5 fc 11 40 70       	vmovups %ymm0,0x70(%rax)
     1c4:	48 8d 35 f5 3a 00 00 	lea    0x3af5(%rip),%rsi        # 0x3cc0
     1cb:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
     1cf:	48 89 48 28          	mov    %rcx,0x28(%rax)
     1d3:	c6 40 35 ff          	movb   $0xff,0x35(%rax)
     1d7:	48 89 50 50          	mov    %rdx,0x50(%rax)
     1db:	48 8d 15 4e 18 00 00 	lea    0x184e(%rip),%rdx        # 0x1a30
     1e2:	48 89 70 58          	mov    %rsi,0x58(%rax)
     1e6:	48 8d 35 f3 65 00 00 	lea    0x65f3(%rip),%rsi        # 0x67e0
     1ed:	48 89 50 68          	mov    %rdx,0x68(%rax)
     1f1:	48 8d 15 18 66 00 00 	lea    0x6618(%rip),%rdx        # 0x6810
     1f8:	48 89 b0 80 00 00 00 	mov    %rsi,0x80(%rax)
     1ff:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
     206:	c7 80 a0 00 00 00 01 	movl   $0x1,0xa0(%rax)
     20d:	00 00 00 
     210:	c5 f8 11 80 a4 00 00 	vmovups %xmm0,0xa4(%rax)
     217:	00 
     218:	31 c0                	xor    %eax,%eax
     21a:	5d                   	pop    %rbp
     21b:	c3                   	ret
     21c:	cc                   	int3
     21d:	cc                   	int3
     21e:	cc                   	int3
     21f:	cc                   	int3
     220:	55                   	push   %rbp
     221:	48 89 e5             	mov    %rsp,%rbp
     224:	4c 8d 05 dd a6 01 00 	lea    0x1a6dd(%rip),%r8        # 0x1a908
     22b:	41 8b b0 a0 00 00 00 	mov    0xa0(%r8),%esi
     232:	89 f0                	mov    %esi,%eax
     234:	ff c8                	dec    %eax
     236:	74 1c                	je     0x254
     238:	49 8d 78 35          	lea    0x35(%r8),%rdi
     23c:	89 c0                	mov    %eax,%eax
     23e:	31 d2                	xor    %edx,%edx
     240:	8b 4f fb             	mov    -0x5(%rdi),%ecx
     243:	83 f9 ff             	cmp    $0xffffffff,%ecx
     246:	75 3f                	jne    0x287
     248:	48 ff c2             	inc    %rdx
     24b:	48 83 c7 78          	add    $0x78,%rdi
     24f:	48 39 d0             	cmp    %rdx,%rax
     252:	75 ec                	jne    0x240
     254:	48 6b c6 78          	imul   $0x78,%rsi,%rax
     258:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
     25c:	c4 c1 7c 11 44 00 08 	vmovups %ymm0,0x8(%r8,%rax,1)
     263:	c4 c1 7c 11 44 00 f0 	vmovups %ymm0,-0x10(%r8,%rax,1)
     26a:	c4 c1 7c 11 44 00 d0 	vmovups %ymm0,-0x30(%r8,%rax,1)
     271:	c4 c1 7c 11 44 00 b0 	vmovups %ymm0,-0x50(%r8,%rax,1)
     278:	41 c7 80 a0 00 00 00 	movl   $0x0,0xa0(%r8)
     27f:	00 00 00 00 
     283:	31 c0                	xor    %eax,%eax
     285:	5d                   	pop    %rbp
     286:	c3                   	ret
     287:	44 0f b6 0f          	movzbl (%rdi),%r9d
     28b:	44 0f b6 47 ff       	movzbl -0x1(%rdi),%r8d
     290:	48 8b 3d 49 3e 01 00 	mov    0x13e49(%rip),%rdi        # 0x140e0
     297:	48 8d 35 be ef 00 00 	lea    0xefbe(%rip),%rsi        # 0xf25c
     29e:	31 c0                	xor    %eax,%eax
     2a0:	e8 db a8 00 00       	call   0xab80
     2a5:	b8 06 00 6d 8a       	mov    $0x8a6d0006,%eax
     2aa:	5d                   	pop    %rbp
     2ab:	c3                   	ret
     2ac:	cc                   	int3
     2ad:	cc                   	int3
     2ae:	cc                   	int3
     2af:	cc                   	int3
