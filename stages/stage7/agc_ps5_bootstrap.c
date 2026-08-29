#include "agc_ps5_bootstrap.h"

static const agc_ps5_nid_entry_t g_table[] = {
    {"sceAgcInit", "kW3GLb7QfPg"},
    {"sceAgcGetRegisterDefaults", "Wi82ArQtAwg"},
    {"sceAgcGetRegisterDefaults2", "2JtWUUiYBXs"},
    {"sceAgcCreateShader", "f3dg2CSgRKY"},
    {"sceAgcLinkShaders", "MqAdbRMdNz4"},
    {"sceAgcGetDataPacketPayloadAddress", "CQsSq6l6+kA"},
    {"sceAgcGetPacketSize", "Lkf86B98qPc"},
    {"sceAgcDriverNotifyDefaultStates", "nR6xhiFsOoc"},
    {"sceAgcDriverGetReservedDmemForAgc", "Um-jkyDy9rI"},
    {"sceAgcDriverInitResourceRegistration", "F0Y42t-3e18"},
    {"sceAgcDriverSubmitDcb", "UglJIZjGssM"},
    {"sceAgcDriverAgrSubmitDcb", "AhGvpITrf4M"}
};

const agc_ps5_nid_entry_t *agc_ps5_bootstrap_table(size_t *count)
{
    if (count)
        *count = sizeof(g_table) / sizeof(g_table[0]);
    return g_table;
}

int agc_ps5_bootstrap_advance(agc_ps5_boot_state_t *state,
                              agc_ps5_boot_state_t next)
{
    if (!state)
        return -1;

    if (next != (agc_ps5_boot_state_t)(*state + 1))
        return -2;

    *state = next;
    return 0;
}

const char *agc_ps5_bootstrap_state_name(agc_ps5_boot_state_t state)
{
    switch (state) {
        case AGC_PS5_BOOT_UNLOADED:           return "UNLOADED";
        case AGC_PS5_BOOT_ABI_RESOLVED:      return "ABI_RESOLVED";
        case AGC_PS5_BOOT_AGC_READY:         return "AGC_READY";
        case AGC_PS5_BOOT_REG_DEFAULTS_READY:return "REG_DEFAULTS_READY";
        case AGC_PS5_BOOT_DCB_READY:         return "DCB_READY";
        case AGC_PS5_BOOT_SUBMIT_READY:      return "SUBMIT_READY";
        default:                              return "UNKNOWN";
    }
}
