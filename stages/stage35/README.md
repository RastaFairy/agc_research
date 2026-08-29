# AGC PS5 Stage 35 — native submit evidence boundary

Objetivo:
- sustituir el dry-run conceptual por una frontera de submit que pueda conectarse al stub real de `libSceAgcDriver`;
- congelar únicamente lo que está demostrado por el proyecto 3.20 + prosper;
- no declarar como prototipo Sony una firma que todavía no ha sido demostrada en un payload PS5 real.

Fuentes:
- PS5-3.20_Libs: NID `UglJIZjGssM` para `sceAgcDriverSubmitDcb` y `AhGvpITrf4M` para `sceAgcDriverAgrSubmitDcb`.
- Prosper v0.1/v0.2: el flujo `real submitted Dcb -> SubmitDcb -> CommandProcessor` está implementado y probado en HLE; su documentación trata el DCB como stream de command words.
- Prosper issue #2173: `w1KFAHVqpaU` es `sceAgcCbBranch`, no un segundo submit; no se reutiliza para SubmitDcb.
- PS5 payload SDK: los stubs se generan desde SPRX y resuelven dinámicamente NID/símbolos.

Regla:
El `submit_packet` de 16 bytes se conserva como estructura experimental ya usada en Stages 6+; el código de este stage NO declara un prototipo nativo de Sony ni invoca el símbolo en host.
