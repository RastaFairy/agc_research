# Herramientas utilizadas

Documento generado automáticamente por `publish_agc_research.py` (1.0.0) el 2026-08-29T00:01:18+00:00.

La presencia de una herramienta aquí se basa en referencias encontradas en scripts, documentación o artefactos reales del área de trabajo. No implica que el ejecutable concreto se distribuya con este repositorio.

| Herramienta | Evidencias detectadas | Uso documentado |
|---|---:|---|
| PowerShell | 136 | Automatización de stages desde Windows. |
| WSL | 1222 | Ejecución Linux desde los scripts PowerShell. |
| Python | 762 | Verificadores, analizadores y generadores reproducibles. |
| Prospero Clang | 316 | Compilación con el toolchain PS5 usado por los stages. |
| Prospero LLD | 159 | Enlazado de artefactos PS5. |
| Prospero/LLVM nm | 392 | Inspección de símbolos de objetos/bibliotecas. |
| objdump / llvm-objdump | 785 | Desensamblado y extracción de evidencia. |
| pyelftools | 898 | Inspección estructural de ELF desde Python. |
| KytyPlus | 219 | Referencia externa para correlación semántica. |
| RetroArch | 601 | Objetivo de integración del proyecto AGC. |
| radare2 | 7 | Herramienta mencionada por los artefactos históricos. |
| GitHub | 284 | Destino de publicación y trazabilidad. |

## Trazabilidad

Ejemplos de ficheros que documentan cada herramienta:

### PowerShell
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`
- `D:\rpcs3_ps5\gestor.txt`
- `D:\agc_ps5_stage33\run_stage33.ps1`

### WSL
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`
- `D:\agc_work\stage82_results\analyze_dispatch_pointer_origin.py`
- `D:\agc_work\stage82_results\dispatch_pointer_origin_summary.txt`

### Python
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`
- `D:\rpcs3_ps5\gestor.txt`
- `D:\agc_ps5_stage9\test_stage9.sh`

### Prospero Clang
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\rpcs3_ps5\dev.txt`
- `D:\rpcs3_ps5\gestor.txt`
- `D:\agc_work\sce_stubs\stage38_compile_stubs.ps1`
- `D:\agc_work\stage81_results\END_TO_END_LINK_CONTRACT.txt`

### Prospero LLD
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\rpcs3_ps5\gestor.txt`
- `D:\agc_work\stage81_results\END_TO_END_LINK_CONTRACT.txt`
- `D:\agc_work\stage82_link_results\STAGE82_FINAL_LINK_CONTRACT.txt`
- `D:\agc_ps5_stage39\stage39_link.ps1`

### Prospero/LLVM nm
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\environment_probe.ps1`
- `D:\agc_work\stage58_results\analyze_backend_consumers.py`
- `D:\agc_work\stage59_results\analyze_dispatch.py`
- `D:\agc_work\stage60_results\analyze_dispatch_provenance.py`

### objdump / llvm-objdump
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`
- `D:\rpcs3_ps5\auditor.txt`
- `D:\agc_ps5_stage9\test_stage9.sh`

### pyelftools
- `D:\Prompt maestro de continuidad — AGC PS5 - libSceAgcDriver - Stage 81.md`
- `D:\publish_agc_research.py`
- `D:\agc_work\sce_stubs\genstub.py`
- `D:\agc_work\stage42_results\extract_submitdcb.py`
- `D:\agc_work\stage42_results\nearby_exports.py`

### KytyPlus
- `D:\chatgpt.txt`
- `D:\chatgpt_2.txt`
- `D:\chatgpt_3.txt`
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`

### RetroArch
- `D:\qwen.txt`
- `D:\chatgpt.txt`
- `D:\chatgpt_2.txt`
- `D:\chatgpt_3.txt`
- `D:\environment_probe.ps1`

### radare2
- `D:\environment_probe.ps1`
- `D:\publish_agc_research.py`
- `D:\agc_work\environment_probe\ENVIRONMENT_REPORT.txt`
- `D:\Garlic-SaveMgr-GitHub\docs\research\agc-ps5\TOOLS.md`

### GitHub
- `D:\qwen.txt`
- `D:\publish_agc_research.py`
- `D:\rpcs3_ps5\auditor.txt`
- `D:\rpcs3_ps5\dev.txt`
- `D:\rpcs3_ps5\gestor.txt`
