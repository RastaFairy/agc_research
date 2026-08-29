# Expected results

Minimum expected outcome:

- `stage39_probe.o` compiles for `x86_64-sie-ps5`.
- Before link, `nm -u` shows `sceAgcDriverSubmitDcb` as unresolved.
- Final ELF links with `libSceAgcDriver.o`.
- `nm` on final ELF shows `sceAgcDriverSubmitDcb` as a resolved symbol.
- `EXECUTED_SUBMIT_DCB=NO`.

A link failure is useful evidence and should be returned unchanged.
