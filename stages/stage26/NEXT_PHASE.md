# Next phase — Vulkan adapter boundary

Stage 27 debe reemplazar únicamente la ejecución visual de `AGC_IR_DRAW` por un adapter Vulkan.

No debe introducir:
- prototipos Sony inventados;
- comandos PM4 adicionales sin evidencia;
- equivalencias 1:1 no demostradas entre registros AGC y estados Vulkan.

La IR P0 permanece como contrato estable entre decoder y backend.
