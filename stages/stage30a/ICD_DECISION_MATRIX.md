# ICD decision matrix

| Candidato | Evidencia | Estado | Motivo |
|---|---|---|---|
| Mesa RADV/ANV/Lavapipe | No hay manifests ICD; `mesa-vulkan-drivers` ausente | DESCARTADO | No hay runtime seleccionable en este entorno |
| NVIDIA | Sin ICD / sin GPU visible | DESCARTADO | No hay dispositivo ni runtime NVIDIA |
| AMD | Sin ICD / `/dev/dri` ausente | DESCARTADO | No hay hardware/runtime disponible |
| Intel | Sin ICD / `/dev/dri` ausente | DESCARTADO | No hay hardware/runtime disponible |
| MoltenVK | KytyPlus lo usa en macOS | DESCARTADO PARA ESTE HOST | No aplica a Linux/x86-64 |
| SwiftShader | Manifest + `libvk_swiftshader.so`; instancia/device/queue reales | **CANDIDATO** | ICD funcional y reproducible |
| Vulkan PS5 nativo | No demostrado por las fuentes revisadas | NO VERIFICADO | No asumir API/ICD pública |
