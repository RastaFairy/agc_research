	.text
	.file	"stage80_probe.c"
	.section	.text.stage80_probe,"ax",@progbits
	.globl	stage80_probe                   # -- Begin function stage80_probe
	.p2align	4, 0x90
	.type	stage80_probe,@function
stage80_probe:                          # @stage80_probe
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	$0, -12(%rbp)
	movq	-8(%rbp), %rdi
	leaq	g_record(%rip), %rsi
	callq	*agcProjectSubmitCommandBuffer@GOTPCREL(%rip)
	addl	-12(%rbp), %eax
	movl	%eax, -12(%rbp)
	movq	-8(%rbp), %rdi
	leaq	g_record(%rip), %rsi
	callq	*agcProjectSubmitDcb@GOTPCREL(%rip)
	addl	-12(%rbp), %eax
	movl	%eax, -12(%rbp)
	movq	-8(%rbp), %rdi
	leaq	g_record(%rip), %rsi
	callq	*agcProjectAgrSubmitDcb@GOTPCREL(%rip)
	addl	-12(%rbp), %eax
	movl	%eax, -12(%rbp)
	movl	-12(%rbp), %eax
	addq	$16, %rsp
	popq	%rbp
	retq
.Lfunc_end0:
	.size	stage80_probe, .Lfunc_end0-stage80_probe
                                        # -- End function
	.section	.text.stage80_multi_probe,"ax",@progbits
	.globl	stage80_multi_probe             # -- Begin function stage80_multi_probe
	.p2align	4, 0x90
	.type	stage80_multi_probe,@function
stage80_multi_probe:                    # @stage80_multi_probe
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$48, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movl	%ecx, -28(%rbp)
	movq	%r8, -40(%rbp)
	movl	$0, -44(%rbp)
	movq	-8(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-24(%rbp), %rdx
	movl	-28(%rbp), %ecx
	callq	*agcProjectSubmitMultiCommandBuffers@GOTPCREL(%rip)
	addl	-44(%rbp), %eax
	movl	%eax, -44(%rbp)
	movq	-8(%rbp), %rdi
	movq	-40(%rbp), %rsi
	callq	*agcProjectSubmitMultiDcbs@GOTPCREL(%rip)
	addl	-44(%rbp), %eax
	movl	%eax, -44(%rbp)
	movq	-8(%rbp), %rdi
	movq	-40(%rbp), %rsi
	callq	*agcProjectAgrSubmitMultiDcbs@GOTPCREL(%rip)
	addl	-44(%rbp), %eax
	movl	%eax, -44(%rbp)
	movq	-8(%rbp), %rdi
	movq	-40(%rbp), %rsi
	callq	*agcProjectSubmitAcb@GOTPCREL(%rip)
	addl	-44(%rbp), %eax
	movl	%eax, -44(%rbp)
	movq	-8(%rbp), %rdi
	movq	-40(%rbp), %rsi
	callq	*agcProjectSubmitMultiAcbs@GOTPCREL(%rip)
	addl	-44(%rbp), %eax
	movl	%eax, -44(%rbp)
	movl	-44(%rbp), %eax
	addq	$48, %rsp
	popq	%rbp
	retq
.Lfunc_end1:
	.size	stage80_multi_probe, .Lfunc_end1-stage80_multi_probe
                                        # -- End function
	.type	g_record,@object                # @g_record
	.section	.bss.g_record,"aw",@nobits
	.p2align	3, 0x0
g_record:
	.zero	16
	.size	g_record, 16

	.ident	"Ubuntu clang version 18.1.3 (1ubuntu1)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym agcProjectSubmitCommandBuffer
	.addrsig_sym agcProjectSubmitDcb
	.addrsig_sym agcProjectAgrSubmitDcb
	.addrsig_sym agcProjectSubmitMultiCommandBuffers
	.addrsig_sym agcProjectSubmitMultiDcbs
	.addrsig_sym agcProjectAgrSubmitMultiDcbs
	.addrsig_sym agcProjectSubmitAcb
	.addrsig_sym agcProjectSubmitMultiAcbs
	.addrsig_sym g_record
