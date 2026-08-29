# Next ABI targets

1. `sceAgcInit`: recuperar call-sites en un consumidor PS5 3.20 o en una biblioteca que invoque el export.
2. `sceAgcGetRegisterDefaults2`: correlacionar los selectores `EDI=0..9` con los bloques devueltos.
3. `sceAgcDriverSubmitDcb`: analizar el thunk y seguir la rutina `0x18b0` para identificar la estructura real del argumento.
4. `sceAgcCreateShader` / `sceAgcLinkShaders`: extraer validaciones de estructuras antes de escribir headers C.

Regla: ningún prototipo nativo se marcará como VERIFIED sólo a partir del desmontado de una rutina exportada; se necesita además un call-site o documentación tipada compatible.
