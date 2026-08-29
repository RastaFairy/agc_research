	.text
	.file	"prototype_probe.c"
	.section	.text.stage53_call_target,"ax",@progbits
	.globl	stage53_call_target             # -- Begin function stage53_call_target
	.p2align	4, 0x90
	.type	stage53_call_target,@function
stage53_call_target:                    # @stage53_call_target
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
	.size	stage53_call_target, .Lfunc_end0-stage53_call_target
                                        # -- End function
	.section	.text.stage53_call_dcb,"ax",@progbits
	.globl	stage53_call_dcb                # -- Begin function stage53_call_dcb
	.p2align	4, 0x90
	.type	stage53_call_dcb,@function
stage53_call_dcb:                       # @stage53_call_dcb
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rdi
	callq	*sceAgcDriverSubmitDcb@GOTPCREL(%rip)
	addq	$16, %rsp
	popq	%rbp
	retq
.Lfunc_end1:
	.size	stage53_call_dcb, .Lfunc_end1-stage53_call_dcb
                                        # -- End function
	.section	.text.stage53_call_agr,"ax",@progbits
	.globl	stage53_call_agr                # -- Begin function stage53_call_agr
	.p2align	4, 0x90
	.type	stage53_call_agr,@function
stage53_call_agr:                       # @stage53_call_agr
# %bb.0:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rdi
	callq	*sceAgcDriverAgrSubmitDcb@GOTPCREL(%rip)
	addq	$16, %rsp
	popq	%rbp
	retq
.Lfunc_end2:
	.size	stage53_call_agr, .Lfunc_end2-stage53_call_agr
                                        # -- End function
	.ident	"Ubuntu clang version 18.1.3 (1ubuntu1)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym sceAgcDriverSubmitCommandBuffer
	.addrsig_sym sceAgcDriverSubmitDcb
	.addrsig_sym sceAgcDriverAgrSubmitDcb
