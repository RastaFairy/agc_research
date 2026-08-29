# Golden AGC trace schema

La prueba siguiente debe registrar, por cada DCB:

1. opcode / packet type
2. packet length
3. register writes (`context`, `SH`, `UCONFIG`)
4. draw initiator + index parameters
5. shader addresses/handles
6. render target base/format/extent
7. synchronization packets
8. present/flip event

La intención es crear un trace pequeño y determinista para que el mismo stream pueda compararse entre:

- decoder propio;
- referencia SharpEmu;
- referencia semántica KytyPlus.

Esto sigue la idea de pruebas deterministas de command streams que se está proponiendo también en el ecosistema SharpEmu. No se importa código de esos proyectos; sólo se adopta el modelo de validación.
