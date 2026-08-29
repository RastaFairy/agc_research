#include "agc_ps5_abi_manifest.h"

static const agc_ps5_symbol_t g_symbols[] = {
    {"sceAgcInit", "kW3GLb7QfPg", AGC_PS5_SYMBOL_AGC},
    {"sceAgcGetRegisterDefaults", "Wi82ArQtAwg", AGC_PS5_SYMBOL_AGC},
    {"sceAgcGetRegisterDefaults2", "2JtWUUiYBXs", AGC_PS5_SYMBOL_AGC},
    {"sceAgcCreateShader", "f3dg2CSgRKY", AGC_PS5_SYMBOL_AGC},
    {"sceAgcLinkShaders", "MqAdbRMdNz4", AGC_PS5_SYMBOL_AGC},
    {"sceAgcDcbSetIndexBuffer", "l4fM9K-Lyks", AGC_PS5_SYMBOL_AGC},
    {"sceAgcDcbSetIndexCount", "8N2tmT3jmC8", AGC_PS5_SYMBOL_AGC},
    {"sceAgcDcbDrawIndex", "q88lQ+GP5Yk", AGC_PS5_SYMBOL_AGC},
    {"sceAgcDcbWaitUntilSafeForRendering", "MWiElSNE8j8", AGC_PS5_SYMBOL_AGC},
    {"sceAgcCbBranch", "w1KFAHVqpaU", AGC_PS5_SYMBOL_AGC},
    {"sceAgcDriverGetReservedDmemForAgc", "Um-jkyDy9rI", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverInitResourceRegistration", "F0Y42t-3e18", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverNotifyDefaultStates", "nR6xhiFsOoc", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverSubmitDcb", "UglJIZjGssM", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverAgrSubmitDcb", "AhGvpITrf4M", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverSubmitCommandBuffer", "b4fpgH5ZXxQ", AGC_PS5_SYMBOL_AGC_DRIVER},
    {"sceAgcDriverSubmitMultiCommandBuffers", "Fj7r9EHzF38", AGC_PS5_SYMBOL_AGC_DRIVER}
};

const agc_ps5_symbol_t *agc_ps5_abi_manifest(size_t *count)
{
    if (count)
        *count = sizeof(g_symbols) / sizeof(g_symbols[0]);
    return g_symbols;
}
