	.text
	.file	"stage79_probe.c"
	.section	.text.stage79_probe,"ax",@progbits
	.globl	stage79_probe                   # -- Begin function stage79_probe
	.p2align	4, 0x90
	.type	stage79_probe,@function
stage79_probe:                          # @stage79_probe
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	-8(%rbp), %rdi
	movq	-16(%rbp), %rsi
	callq	*sceAgcDriverSubmitCommandBuffer@GOTPCREL(%rip)
	addq	$16, %rsp
	popq	%rbp
	retq
.Lfunc_end0:
	.size	stage79_probe, .Lfunc_end0-stage79_probe
                                        # -- End function
	.section	.text.stage79_probe_dcb,"ax",@progbits
	.globl	stage79_probe_dcb               # -- Begin function stage79_probe_dcb
	.p2align	4, 0x90
	.type	stage79_probe_dcb,@function
stage79_probe_dcb:                      # @stage79_probe_dcb
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	-8(%rbp), %rdi
	movq	-16(%rbp), %rsi
	callq	*sceAgcDriverSubmitDcb@GOTPCREL(%rip)
	addq	$16, %rsp
	popq	%rbp
	retq
.Lfunc_end1:
	.size	stage79_probe_dcb, .Lfunc_end1-stage79_probe_dcb
                                        # -- End function
	.section	.text.stage79_probe_multi,"ax",@progbits
	.globl	stage79_probe_multi             # -- Begin function stage79_probe_multi
	.p2align	4, 0x90
	.type	stage79_probe_multi,@function
stage79_probe_multi:                    # @stage79_probe_multi
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movl	%ecx, -28(%rbp)
	movq	-8(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-24(%rbp), %rdx
	movl	-28(%rbp), %ecx
	callq	*sceAgcDriverSubmitMultiCommandBuffers@GOTPCREL(%rip)
	addq	$32, %rsp
	popq	%rbp
	retq
.Lfunc_end2:
	.size	stage79_probe_multi, .Lfunc_end2-stage79_probe_multi
                                        # -- End function
	.ident	"Ubuntu clang version 18.1.3 (1ubuntu1)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym sceAgcDriverSubmitCommandBuffer
	.addrsig_sym sceAgcDriverSubmitDcb
	.addrsig_sym sceAgcDriverSubmitMultiCommandBuffers
