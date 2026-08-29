# AGC PS5 Stage 7 — bootstrap ABI map

Esta etapa congela la información que ya está demostrada para FW 3.20 y evita
inventar prototipos C.

Fuentes utilizadas:
- PS5-3.20_Libs/libSceAgc.c: NIDs de sceAgcInit, sceAgcGetRegisterDefaults2,
  sceAgcCreateShader, sceAgcLinkShaders y constructores DCB.
- PS5-3.20_Libs/libSceAgcDriver.c: NIDs de la capa driver.
- prosper/src/hle/graphics/hle_agc.cpp: qué operaciones AGC/PM4 implementa
  actualmente prosper y cómo registra sus handlers.

NIDs congelados:
  sceAgcInit                  = kW3GLb7QfPg
  sceAgcGetRegisterDefaults   = Wi82ArQtAwg
  sceAgcGetRegisterDefaults2  = 2JtWUUiYBXs
  sceAgcCreateShader          = f3dg2CSgRKY
  sceAgcLinkShaders           = MqAdbRMdNz4
  sceAgcGetDataPacketPayload  = CQsSq6l6+kA
  sceAgcGetPacketSize         = Lkf86B98qPc
  sceAgcDriverNotifyDefaultStates = nR6xhiFsOoc
  sceAgcDriverGetReservedDmemForAgc = Um-jkyDy9rI
  sceAgcDriverInitResourceRegistration = F0Y42t-3e18
  sceAgcDriverSubmitDcb       = UglJIZjGssM
  sceAgcDriverAgrSubmitDcb    = AhGvpITrf4M

Lo que NO se congela aquí:
- firmas C;
- tamaños/formatos exactos de las estructuras de init;
- significado completo de cada campo de los argumentos.
Eso requiere otra fuente o contraste sobre un binario real.

El bootstrap propuesto es una máquina de estados:
  UNLOADED -> ABI_RESOLVED -> AGC_READY -> REG_DEFAULTS_READY
            -> DCB_READY -> SUBMIT_READY

La implementación de esta etapa sólo valida el inventario y las transiciones.
No ejecuta funciones SCE.
