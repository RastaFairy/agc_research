# Next phase

Stage 25 debe implementar un decoder propio de P0 que:

- acepte un stream de dwords;
- decodifique sólo P0;
- produzca un IR pequeño (`SetReg`, `Draw`, `WriteData`, `Sync`, `Present`);
- rechace con diagnóstico cualquier opcode fuera de P0;
- permita ejecutar el trace en host sin PS5.

Después se podrá conectar ese IR a una capa PS5 específica sin que el renderer dependa del callback interno `entry+0x48`.
