# Backend contract

SetReg: actualizar estado lógico, no asumir todavía un mapeo directo a un registro Vulkan.
Draw: consumir estado lógico y emitir una operación de dibujo cuando el backend disponga de pipeline/vertex input válidos.
WriteData: escribir memoria del backend con las reglas de direccionamiento que se hayan demostrado.
Sync: traducir sólo los subconjuntos cuyo significado esté validado.
Present: frontera explícita de presentación; fuera del opcode PM4.
