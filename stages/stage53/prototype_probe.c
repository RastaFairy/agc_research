#include <stdint.h>

struct SceAgcSubmitCommandBufferArgsCandidate {
    uint64_t field_00;
    uint32_t field_08;
    uint8_t  field_0c;
};

extern int
sceAgcDriverSubmitCommandBuffer(
    void *context,
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

extern int
sceAgcDriverSubmitDcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

extern int
sceAgcDriverAgrSubmitDcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

int
stage53_call_target(
    void *context,
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverSubmitCommandBuffer(
        context,
        args
    );
}

int
stage53_call_dcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverSubmitDcb(
        args
    );
}

int
stage53_call_agr(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverAgrSubmitDcb(
        args
    );
}
