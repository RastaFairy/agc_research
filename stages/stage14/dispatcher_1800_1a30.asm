
/tmp/agcdrv.bin:     file format binary


Disassembly of section .data:

0000000000001800 <.data+0x1800>:
    1800:	75 0f                	jne    0x1811
    1802:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
    1806:	5b                   	pop    %rbx
    1807:	41 5c                	pop    %r12
    1809:	41 5d                	pop    %r13
    180b:	41 5e                	pop    %r14
    180d:	41 5f                	pop    %r15
    180f:	5d                   	pop    %rbp
    1810:	c3                   	ret
    1811:	e8 1a 94 00 00       	call   0xac30
    1816:	0f 0b                	ud2
    1818:	cc                   	int3
    1819:	cc                   	int3
    181a:	cc                   	int3
    181b:	cc                   	int3
    181c:	cc                   	int3
    181d:	cc                   	int3
    181e:	cc                   	int3
    181f:	cc                   	int3
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
    18a3:	cc                   	int3
    18a4:	cc                   	int3
    18a5:	cc                   	int3
    18a6:	cc                   	int3
    18a7:	cc                   	int3
    18a8:	cc                   	int3
    18a9:	cc                   	int3
    18aa:	cc                   	int3
    18ab:	cc                   	int3
    18ac:	cc                   	int3
    18ad:	cc                   	int3
    18ae:	cc                   	int3
    18af:	cc                   	int3
    18b0:	55                   	push   %rbp
    18b1:	48 89 e5             	mov    %rsp,%rbp
    18b4:	41 57                	push   %r15
    18b6:	41 56                	push   %r14
    18b8:	41 55                	push   %r13
    18ba:	41 54                	push   %r12
    18bc:	53                   	push   %rbx
    18bd:	48 83 ec 38          	sub    $0x38,%rsp
    18c1:	48 8b 1d 20 28 01 00 	mov    0x12820(%rip),%rbx        # 0x140e8
    18c8:	4c 8d 6f 38          	lea    0x38(%rdi),%r13
    18cc:	49 89 fc             	mov    %rdi,%r12
    18cf:	49 89 f6             	mov    %rsi,%r14
    18d2:	4c 89 ef             	mov    %r13,%rdi
    18d5:	48 8b 03             	mov    (%rbx),%rax
    18d8:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    18dc:	e8 2f 93 00 00       	call   0xac10
    18e1:	85 c0                	test   %eax,%eax
    18e3:	0f 88 b3 00 00 00    	js     0x199c
    18e9:	41 bf 00 00 6d 8a    	mov    $0x8a6d0000,%r15d
    18ef:	0f 85 15 01 00 00    	jne    0x1a0a
    18f5:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    18fc:	00 
    18fd:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    1904:	c6 45 bc 00          	movb   $0x0,-0x44(%rbp)
    1908:	48 8d 1d f9 8f 01 00 	lea    0x18ff9(%rip),%rbx        # 0x1a908
    190f:	4c 89 6d a8          	mov    %r13,-0x58(%rbp)
    1913:	49 8b 06             	mov    (%r14),%rax
    1916:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    191a:	41 8b 46 08          	mov    0x8(%r14),%eax
    191e:	89 45 c8             	mov    %eax,-0x38(%rbp)
    1921:	41 8a 46 0c          	mov    0xc(%r14),%al
    1925:	88 45 cc             	mov    %al,-0x34(%rbp)
    1928:	b8 01 00 00 00       	mov    $0x1,%eax
    192d:	f0 48 0f c1 83 40 01 	lock xadd %rax,0x140(%rbx)
    1934:	00 00 
    1936:	49 89 44 24 20       	mov    %rax,0x20(%r12)
    193b:	49 ff 44 24 28       	incq   0x28(%r12)
    1940:	49 c7 44 24 14 00 00 	movq   $0x0,0x14(%r12)
    1947:	00 00 
    1949:	41 80 64 24 08 fe    	andb   $0xfe,0x8(%r12)
    194f:	49 c7 44 24 30 00 00 	movq   $0x0,0x30(%r12)
    1956:	00 00 
    1958:	8b 83 a0 00 00 00    	mov    0xa0(%rbx),%eax
    195e:	85 c0                	test   %eax,%eax
    1960:	74 5f                	je     0x19c1
    1962:	4c 8d 6b 48          	lea    0x48(%rbx),%r13
    1966:	4c 8d 7d b0          	lea    -0x50(%rbp),%r15
    196a:	45 31 f6             	xor    %r14d,%r14d
    196d:	eb 0f                	jmp    0x197e
    196f:	90                   	nop
    1970:	49 ff c6             	inc    %r14
    1973:	89 c1                	mov    %eax,%ecx
    1975:	49 83 c5 78          	add    $0x78,%r13
    1979:	49 39 ce             	cmp    %rcx,%r14
    197c:	73 43                	jae    0x19c1
    197e:	49 8b 4d 00          	mov    0x0(%r13),%rcx
    1982:	48 85 c9             	test   %rcx,%rcx
    1985:	74 e9                	je     0x1970
    1987:	4c 89 e7             	mov    %r12,%rdi
    198a:	4c 89 fe             	mov    %r15,%rsi
    198d:	ba 01 00 00 00       	mov    $0x1,%edx
    1992:	ff d1                	call   *%rcx
    1994:	8b 83 a0 00 00 00    	mov    0xa0(%rbx),%eax
    199a:	eb d4                	jmp    0x1970
    199c:	48 8b 0d 3d 27 01 00 	mov    0x1273d(%rip),%rcx        # 0x140e0
    19a3:	48 8d 3d 7a da 00 00 	lea    0xda7a(%rip),%rdi        # 0xf424
    19aa:	be 34 00 00 00       	mov    $0x34,%esi
    19af:	ba 01 00 00 00       	mov    $0x1,%edx
    19b4:	e8 b7 91 00 00       	call   0xab70
    19b9:	41 bf 00 00 6d 8a    	mov    $0x8a6d0000,%r15d
    19bf:	eb 49                	jmp    0x1a0a
    19c1:	8b 83 a4 00 00 00    	mov    0xa4(%rbx),%eax
    19c7:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    19cb:	4c 89 e7             	mov    %r12,%rdi
    19ce:	48 6b c0 78          	imul   $0x78,%rax,%rax
    19d2:	ff 54 03 50          	call   *0x50(%rbx,%rax,1)
    19d6:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    19da:	41 89 c7             	mov    %eax,%r15d
    19dd:	e8 3e 92 00 00       	call   0xac20
    19e2:	85 c0                	test   %eax,%eax
    19e4:	79 1d                	jns    0x1a03
    19e6:	48 8b 0d f3 26 01 00 	mov    0x126f3(%rip),%rcx        # 0x140e0
    19ed:	48 8d 3d 7c df 00 00 	lea    0xdf7c(%rip),%rdi        # 0xf970
    19f4:	be 32 00 00 00       	mov    $0x32,%esi
    19f9:	ba 01 00 00 00       	mov    $0x1,%edx
    19fe:	e8 6d 91 00 00       	call   0xab70
    1a03:	48 8b 1d de 26 01 00 	mov    0x126de(%rip),%rbx        # 0x140e8
    1a0a:	48 8b 03             	mov    (%rbx),%rax
    1a0d:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
    1a11:	75 12                	jne    0x1a25
    1a13:	44 89 f8             	mov    %r15d,%eax
    1a16:	48 83 c4 38          	add    $0x38,%rsp
    1a1a:	5b                   	pop    %rbx
    1a1b:	41 5c                	pop    %r12
    1a1d:	41 5d                	pop    %r13
    1a1f:	41 5e                	pop    %r14
    1a21:	41 5f                	pop    %r15
    1a23:	5d                   	pop    %rbp
    1a24:	c3                   	ret
    1a25:	e8 06 92 00 00       	call   0xac30
    1a2a:	0f 0b                	ud2
    1a2c:	cc                   	int3
    1a2d:	cc                   	int3
    1a2e:	cc                   	int3
    1a2f:	cc                   	int3
    1a30:	55                   	push   %rbp
    1a31:	48 89 e5             	mov    %rsp,%rbp
    1a34:	41 57                	push   %r15
    1a36:	41 56                	push   %r14
    1a38:	41 55                	push   %r13
    1a3a:	41 54                	push   %r12
    1a3c:	53                   	push   %rbx
    1a3d:	50                   	push   %rax
    1a3e:	44 8b 6f 04          	mov    0x4(%rdi),%r13d
    1a42:	45 31 f6             	xor    %r14d,%r14d
    1a45:	48 8d 1d bc 8e 01 00 	lea    0x18ebc(%rip),%rbx        # 0x1a908
    1a4c:	49 89 fc             	mov    %rdi,%r12
    1a4f:	48 89 55 d0          	mov    %rdx,-0x30(%rbp)
    1a53:	41 83 fd 04          	cmp    $0x4,%r13d
    1a57:	41 0f 94 c6          	sete   %r14b
    1a5b:	4c 89 f0             	mov    %r14,%rax
    1a5e:	48 c1 e0 05          	shl    $0x5,%rax
    1a62:	48 83 bc 03 68 01 00 	cmpq   $0x0,0x168(%rbx,%rax,1)
    1a69:	00 00 
    1a6b:	4c 8d bc 03 58 01 00 	lea    0x158(%rbx,%rax,1),%r15
    1a72:	00 
    1a73:	74 17                	je     0x1a8c
    1a75:	4c 89 e7             	mov    %r12,%rdi
    1a78:	48 89 f3             	mov    %rsi,%rbx
    1a7b:	31 f6                	xor    %esi,%esi
    1a7d:	e8 be f8 ff ff       	call   0x1340
    1a82:	48 89 de             	mov    %rbx,%rsi
    1a85:	48 8d 1d 7c 8e 01 00 	lea    0x18e7c(%rip),%rbx        # 0x1a908
    1a8c:	c5 fc 10 06          	vmovups (%rsi),%ymm0
    1a90:	c4 c1 7c 11 07       	vmovups %ymm0,(%r15)
    1a95:	42 83 bc b3 50 01 00 	cmpl   $0x0,0x150(%rbx,%r14,4)
    1a9c:	00 00 
    1a9e:	74 19                	je     0x1ab9
    1aa0:	8b 7b 04             	mov    0x4(%rbx),%edi
    1aa3:	41 8b 74 24 04       	mov    0x4(%r12),%esi
    1aa8:	e8 63 8a 00 00       	call   0xa510
    1aad:	42 c7 84 b3 50 01 00 	movl   $0x0,0x150(%rbx,%r14,4)
    1ab4:	00 00 00 00 00 
    1ab9:	45 31 ff             	xor    %r15d,%r15d
    1abc:	41 83 fd 04          	cmp    $0x4,%r13d
    1ac0:	74 67                	je     0x1b29
    1ac2:	8b 7b 04             	mov    0x4(%rbx),%edi
    1ac5:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    1ac9:	48 8d 93 98 01 00 00 	lea    0x198(%rbx),%rdx
    1ad0:	e8 bb 85 00 00       	call   0xa090
    1ad5:	41 89 c6             	mov    %eax,%r14d
    1ad8:	0f 31                	rdtsc
    1ada:	89 c0                	mov    %eax,%eax
    1adc:	48 c1 e2 20          	shl    $0x20,%rdx
    1ae0:	48 09 c2             	or     %rax,%rdx
    1ae3:	48 c1 ea 04          	shr    $0x4,%rdx
    1ae7:	48 89 93 a0 01 00 00 	mov    %rdx,0x1a0(%rbx)
    1aee:	e8 4d 91 00 00       	call   0xac40
    1af3:	48 c1 e8 04          	shr    $0x4,%rax
    1af7:	48 89 83 a8 01 00 00 	mov    %rax,0x1a8(%rbx)
    1afe:	41 83 fe 01          	cmp    $0x1,%r14d
    1b02:	74 25                	je     0x1b29
    1b04:	48 8b 3d d5 25 01 00 	mov    0x125d5(%rip),%rdi        # 0x140e0
    1b0b:	48 8d 35 d0 d7 00 00 	lea    0xd7d0(%rip),%rsi        # 0xf2e2
    1b12:	48 8d 15 99 e0 00 00 	lea    0xe099(%rip),%rdx        # 0xfbb2
    1b19:	44 89 f1             	mov    %r14d,%ecx
    1b1c:	31 c0                	xor    %eax,%eax
    1b1e:	e8 5d 90 00 00       	call   0xab80
    1b23:	41 bf 00 00 6d 8a    	mov    $0x8a6d0000,%r15d
    1b29:	44 89 f8             	mov    %r15d,%eax
    1b2c:	48 83 c4 08          	add    $0x8,%rsp
    1b30:	5b                   	pop    %rbx
    1b31:	41 5c                	pop    %r12
    1b33:	41 5d                	pop    %r13
    1b35:	41 5e                	pop    %r14
    1b37:	41 5f                	pop    %r15
    1b39:	5d                   	pop    %rbp
    1b3a:	c3                   	ret
    1b3b:	cc                   	int3
    1b3c:	cc                   	int3
    1b3d:	cc                   	int3
    1b3e:	cc                   	int3
    1b3f:	cc                   	int3
    1b40:	55                   	push   %rbp
    1b41:	48 89 e5             	mov    %rsp,%rbp
    1b44:	41 57                	push   %r15
    1b46:	41 56                	push   %r14
    1b48:	41 55                	push   %r13
    1b4a:	41 54                	push   %r12
    1b4c:	53                   	push   %rbx
    1b4d:	50                   	push   %rax
    1b4e:	4c 8d 25 b3 8d 01 00 	lea    0x18db3(%rip),%r12        # 0x1a908
    1b55:	48 89 55 d0          	mov    %rdx,-0x30(%rbp)
    1b59:	b8 01 00 00 00       	mov    $0x1,%eax
    1b5e:	49 89 f7             	mov    %rsi,%r15
    1b61:	49 89 fd             	mov    %rdi,%r13
    1b64:	f0 49 0f c1 84 24 40 	lock xadd %rax,0x140(%r12)
    1b6b:	01 00 00 
    1b6e:	48 89 47 20          	mov    %rax,0x20(%rdi)
    1b72:	48 ff 47 28          	incq   0x28(%rdi)
    1b76:	48 c7 47 14 00 00 00 	movq   $0x0,0x14(%rdi)
    1b7d:	00 
    1b7e:	80 67 08 fe          	andb   $0xfe,0x8(%rdi)
    1b82:	48 c7 47 30 00 00 00 	movq   $0x0,0x30(%rdi)
    1b89:	00 
    1b8a:	41 8b 84 24 a0 00 00 	mov    0xa0(%r12),%eax
    1b91:	00 
    1b92:	85 c0                	test   %eax,%eax
    1b94:	74 32                	je     0x1bc8
    1b96:	49 8d 5c 24 60       	lea    0x60(%r12),%rbx
    1b9b:	45 31 f6             	xor    %r14d,%r14d
    1b9e:	eb 0e                	jmp    0x1bae
    1ba0:	49 ff c6             	inc    %r14
    1ba3:	89 c1                	mov    %eax,%ecx
    1ba5:	48 83 c3 78          	add    $0x78,%rbx
    1ba9:	49 39 ce             	cmp    %rcx,%r14
    1bac:	73 1a                	jae    0x1bc8
    1bae:	48 8b 0b             	mov    (%rbx),%rcx
    1bb1:	48 85 c9             	test   %rcx,%rcx
    1bb4:	74 ea                	je     0x1ba0
    1bb6:	4c 89 ef             	mov    %r13,%rdi
    1bb9:	4c 89 fe             	mov    %r15,%rsi
    1bbc:	ff d1                	call   *%rcx
    1bbe:	41 8b 84 24 a0 00 00 	mov    0xa0(%r12),%eax
    1bc5:	00 
    1bc6:	eb d8                	jmp    0x1ba0
    1bc8:	41 8b 84 24 a8 00 00 	mov    0xa8(%r12),%eax
    1bcf:	00 
    1bd0:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1bd4:	4c 89 ef             	mov    %r13,%rdi
    1bd7:	4c 89 fe             	mov    %r15,%rsi
    1bda:	48 6b c0 78          	imul   $0x78,%rax,%rax
    1bde:	49 8b 44 04 68       	mov    0x68(%r12,%rax,1),%rax
    1be3:	48 83 c4 08          	add    $0x8,%rsp
    1be7:	5b                   	pop    %rbx
    1be8:	41 5c                	pop    %r12
    1bea:	41 5d                	pop    %r13
    1bec:	41 5e                	pop    %r14
    1bee:	41 5f                	pop    %r15
    1bf0:	5d                   	pop    %rbp
    1bf1:	ff e0                	jmp    *%rax
    1bf3:	cc                   	int3
    1bf4:	cc                   	int3
    1bf5:	cc                   	int3
    1bf6:	cc                   	int3
    1bf7:	cc                   	int3
    1bf8:	cc                   	int3
    1bf9:	cc                   	int3
    1bfa:	cc                   	int3
    1bfb:	cc                   	int3
    1bfc:	cc                   	int3
    1bfd:	cc                   	int3
    1bfe:	cc                   	int3
    1bff:	cc                   	int3
    1c00:	55                   	push   %rbp
    1c01:	48 89 e5             	mov    %rsp,%rbp
    1c04:	41 57                	push   %r15
    1c06:	41 56                	push   %r14
    1c08:	41 55                	push   %r13
    1c0a:	41 54                	push   %r12
    1c0c:	53                   	push   %rbx
    1c0d:	48 83 ec 38          	sub    $0x38,%rsp
    1c11:	48 8b 1d d0 24 01 00 	mov    0x124d0(%rip),%rbx        # 0x140e8
    1c18:	4c 8d 2d e9 8c 01 00 	lea    0x18ce9(%rip),%r13        # 0x1a908
    1c1f:	49 89 f7             	mov    %rsi,%r15
    1c22:	49 89 fc             	mov    %rdi,%r12
    1c25:	41 be 00 00 6d 8a    	mov    $0x8a6d0000,%r14d
    1c2b:	48 8b 03             	mov    (%rbx),%rax
    1c2e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    1c32:	41 83 bd 48 01 00 00 	cmpl   $0x0,0x148(%r13)
    1c39:	00 
    1c3a:	0f 84 53 01 00 00    	je     0x1d93
    1c40:	48 8d 3d 59 8c 01 00 	lea    0x18c59(%rip),%rdi        # 0x1a8a0
    1c47:	e8 c4 8f 00 00       	call   0xac10
    1c4c:	85 c0                	test   %eax,%eax
    1c4e:	0f 88 c3 00 00 00    	js     0x1d17
    1c54:	0f 85 39 01 00 00    	jne    0x1d93
    1c5a:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    1c61:	00 
    1c62:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    1c69:	c6 45 bc 00          	movb   $0x0,-0x44(%rbp)
    1c6d:	4c 89 7d a8          	mov    %r15,-0x58(%rbp)
    1c71:	4c 89 65 a0          	mov    %r12,-0x60(%rbp)
    1c75:	49 8b 04 24          	mov    (%r12),%rax
    1c79:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    1c7d:	41 8b 44 24 08       	mov    0x8(%r12),%eax
    1c82:	89 45 c8             	mov    %eax,-0x38(%rbp)
    1c85:	41 8a 44 24 0c       	mov    0xc(%r12),%al
    1c8a:	88 45 cc             	mov    %al,-0x34(%rbp)
    1c8d:	b8 01 00 00 00       	mov    $0x1,%eax
    1c92:	f0 49 0f c1 85 40 01 	lock xadd %rax,0x140(%r13)
    1c99:	00 00 
    1c9b:	48 89 05 e6 8b 01 00 	mov    %rax,0x18be6(%rip)        # 0x1a888
    1ca2:	48 ff 05 e7 8b 01 00 	incq   0x18be7(%rip)        # 0x1a890
    1ca9:	48 c7 05 c8 8b 01 00 	movq   $0x0,0x18bc8(%rip)        # 0x1a87c
    1cb0:	00 00 00 00 
    1cb4:	80 25 b5 8b 01 00 fe 	andb   $0xfe,0x18bb5(%rip)        # 0x1a870
    1cbb:	41 8b 85 a0 00 00 00 	mov    0xa0(%r13),%eax
    1cc2:	48 c7 05 cb 8b 01 00 	movq   $0x0,0x18bcb(%rip)        # 0x1a898
    1cc9:	00 00 00 00 
    1ccd:	85 c0                	test   %eax,%eax
    1ccf:	74 65                	je     0x1d36
    1cd1:	4d 8d 75 60          	lea    0x60(%r13),%r14
    1cd5:	4c 8d 25 8c 8b 01 00 	lea    0x18b8c(%rip),%r12        # 0x1a868
    1cdc:	48 8d 5d b0          	lea    -0x50(%rbp),%rbx
    1ce0:	45 31 ff             	xor    %r15d,%r15d
    1ce3:	eb 19                	jmp    0x1cfe
    1ce5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    1cec:	00 00 00 00 
    1cf0:	49 ff c7             	inc    %r15
    1cf3:	89 c1                	mov    %eax,%ecx
    1cf5:	49 83 c6 78          	add    $0x78,%r14
    1cf9:	49 39 cf             	cmp    %rcx,%r15
    1cfc:	73 38                	jae    0x1d36
    1cfe:	49 8b 0e             	mov    (%r14),%rcx
    1d01:	48 85 c9             	test   %rcx,%rcx
    1d04:	74 ea                	je     0x1cf0
    1d06:	4c 89 e7             	mov    %r12,%rdi
    1d09:	48 89 de             	mov    %rbx,%rsi
    1d0c:	ff d1                	call   *%rcx
    1d0e:	41 8b 85 a0 00 00 00 	mov    0xa0(%r13),%eax
    1d15:	eb d9                	jmp    0x1cf0
    1d17:	48 8b 0d c2 23 01 00 	mov    0x123c2(%rip),%rcx        # 0x140e0
    1d1e:	48 8d 3d ff d6 00 00 	lea    0xd6ff(%rip),%rdi        # 0xf424
    1d25:	be 34 00 00 00       	mov    $0x34,%esi
    1d2a:	ba 01 00 00 00       	mov    $0x1,%edx
    1d2f:	e8 3c 8e 00 00       	call   0xab70
    1d34:	eb 5d                	jmp    0x1d93
    1d36:	41 8b 85 a8 00 00 00 	mov    0xa8(%r13),%eax
    1d3d:	4c 8b 7d a8          	mov    -0x58(%rbp),%r15
    1d41:	48 8d 3d 20 8b 01 00 	lea    0x18b20(%rip),%rdi        # 0x1a868
    1d48:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    1d4c:	48 6b c0 78          	imul   $0x78,%rax,%rax
    1d50:	4c 89 fa             	mov    %r15,%rdx
    1d53:	41 ff 54 05 68       	call   *0x68(%r13,%rax,1)
    1d58:	48 8d 3d 41 8b 01 00 	lea    0x18b41(%rip),%rdi        # 0x1a8a0
    1d5f:	41 89 c6             	mov    %eax,%r14d
    1d62:	e8 b9 8e 00 00       	call   0xac20
    1d67:	85 c0                	test   %eax,%eax
    1d69:	79 1d                	jns    0x1d88
    1d6b:	48 8b 0d 6e 23 01 00 	mov    0x1236e(%rip),%rcx        # 0x140e0
    1d72:	48 8d 3d f7 db 00 00 	lea    0xdbf7(%rip),%rdi        # 0xf970
    1d79:	be 32 00 00 00       	mov    $0x32,%esi
    1d7e:	ba 01 00 00 00       	mov    $0x1,%edx
    1d83:	e8 e8 8d 00 00       	call   0xab70
    1d88:	48 8b 1d 59 23 01 00 	mov    0x12359(%rip),%rbx        # 0x140e8
    1d8f:	4c 8b 65 a0          	mov    -0x60(%rbp),%r12
    1d93:	48 8d 3d 56 8b 01 00 	lea    0x18b56(%rip),%rdi        # 0x1a8f0
    1d9a:	e8 71 8e 00 00       	call   0xac10
    1d9f:	85 c0                	test   %eax,%eax
    1da1:	0f 88 c1 00 00 00    	js     0x1e68
    1da7:	0f 85 30 01 00 00    	jne    0x1edd
    1dad:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    1db4:	00 
    1db5:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    1dbc:	c6 45 bc 00          	movb   $0x0,-0x44(%rbp)
    1dc0:	4c 89 7d a8          	mov    %r15,-0x58(%rbp)
    1dc4:	49 8b 04 24          	mov    (%r12),%rax
    1dc8:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    1dcc:	41 8b 44 24 08       	mov    0x8(%r12),%eax
    1dd1:	89 45 c8             	mov    %eax,-0x38(%rbp)
    1dd4:	41 8a 44 24 0c       	mov    0xc(%r12),%al
    1dd9:	88 45 cc             	mov    %al,-0x34(%rbp)
    1ddc:	b8 01 00 00 00       	mov    $0x1,%eax
    1de1:	f0 49 0f c1 85 40 01 	lock xadd %rax,0x140(%r13)
    1de8:	00 00 
    1dea:	48 89 05 e7 8a 01 00 	mov    %rax,0x18ae7(%rip)        # 0x1a8d8
    1df1:	48 ff 05 e8 8a 01 00 	incq   0x18ae8(%rip)        # 0x1a8e0
    1df8:	48 c7 05 c9 8a 01 00 	movq   $0x0,0x18ac9(%rip)        # 0x1a8cc
    1dff:	00 00 00 00 
    1e03:	80 25 b6 8a 01 00 fe 	andb   $0xfe,0x18ab6(%rip)        # 0x1a8c0
    1e0a:	41 8b 85 a0 00 00 00 	mov    0xa0(%r13),%eax
    1e11:	48 c7 05 cc 8a 01 00 	movq   $0x0,0x18acc(%rip)        # 0x1a8e8
    1e18:	00 00 00 00 
    1e1c:	85 c0                	test   %eax,%eax
    1e1e:	74 67                	je     0x1e87
    1e20:	4d 8d 65 60          	lea    0x60(%r13),%r12
    1e24:	4c 8d 3d 8d 8a 01 00 	lea    0x18a8d(%rip),%r15        # 0x1a8b8
    1e2b:	4c 8d 75 b0          	lea    -0x50(%rbp),%r14
    1e2f:	31 db                	xor    %ebx,%ebx
    1e31:	eb 1b                	jmp    0x1e4e
    1e33:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
    1e3a:	84 00 00 00 00 00 
    1e40:	48 ff c3             	inc    %rbx
    1e43:	89 c1                	mov    %eax,%ecx
    1e45:	49 83 c4 78          	add    $0x78,%r12
    1e49:	48 39 cb             	cmp    %rcx,%rbx
    1e4c:	73 39                	jae    0x1e87
    1e4e:	49 8b 0c 24          	mov    (%r12),%rcx
    1e52:	48 85 c9             	test   %rcx,%rcx
    1e55:	74 e9                	je     0x1e40
    1e57:	4c 89 ff             	mov    %r15,%rdi
    1e5a:	4c 89 f6             	mov    %r14,%rsi
    1e5d:	ff d1                	call   *%rcx
    1e5f:	41 8b 85 a0 00 00 00 	mov    0xa0(%r13),%eax
    1e66:	eb d8                	jmp    0x1e40
    1e68:	48 8b 0d 71 22 01 00 	mov    0x12271(%rip),%rcx        # 0x140e0
    1e6f:	48 8d 3d ae d5 00 00 	lea    0xd5ae(%rip),%rdi        # 0xf424
    1e76:	be 34 00 00 00       	mov    $0x34,%esi
    1e7b:	ba 01 00 00 00       	mov    $0x1,%edx
    1e80:	e8 eb 8c 00 00       	call   0xab70
    1e85:	eb 56                	jmp    0x1edd
    1e87:	41 8b 85 a8 00 00 00 	mov    0xa8(%r13),%eax
    1e8e:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    1e92:	48 8d 3d 1f 8a 01 00 	lea    0x18a1f(%rip),%rdi        # 0x1a8b8
    1e99:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    1e9d:	48 6b c0 78          	imul   $0x78,%rax,%rax
    1ea1:	41 ff 54 05 68       	call   *0x68(%r13,%rax,1)
    1ea6:	48 8d 3d 43 8a 01 00 	lea    0x18a43(%rip),%rdi        # 0x1a8f0
    1ead:	41 89 c6             	mov    %eax,%r14d
    1eb0:	e8 6b 8d 00 00       	call   0xac20
    1eb5:	85 c0                	test   %eax,%eax
    1eb7:	79 1d                	jns    0x1ed6
    1eb9:	48 8b 0d 20 22 01 00 	mov    0x12220(%rip),%rcx        # 0x140e0
    1ec0:	48 8d 3d a9 da 00 00 	lea    0xdaa9(%rip),%rdi        # 0xf970
    1ec7:	be 32 00 00 00       	mov    $0x32,%esi
    1ecc:	ba 01 00 00 00       	mov    $0x1,%edx
    1ed1:	e8 9a 8c 00 00       	call   0xab70
    1ed6:	48 8b 1d 0b 22 01 00 	mov    0x1220b(%rip),%rbx        # 0x140e8
    1edd:	48 8b 03             	mov    (%rbx),%rax
    1ee0:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
    1ee4:	75 12                	jne    0x1ef8
    1ee6:	44 89 f0             	mov    %r14d,%eax
    1ee9:	48 83 c4 38          	add    $0x38,%rsp
    1eed:	5b                   	pop    %rbx
    1eee:	41 5c                	pop    %r12
