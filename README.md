# psp2-core-parse

Analyze a PlayStation Vita psp2core dump:

```sh
./psp2-core-parse analyze dump.psp2dmp
```

Use a matching decrypted Vita ELF for symbols, source locations, disassembly, and unwinding:

```sh
./psp2-core-parse analyze dump.psp2dmp \
  --image application=application.elf
```

VitaSDK must be available through `PATH` or `VITASDK` when using these image-backed features.

Write the complete analysis as JSON:

```sh
./psp2-core-parse analyze dump.psp2dmp --json
```

Other basic commands:

```sh
./psp2-core-parse info dump.psp2dmp
./psp2-core-parse notes dump.psp2dmp
./psp2-core-parse notes dump.psp2dmp THREAD_INFO --raw
./psp2-core-parse threads dump.psp2dmp
./psp2-core-parse thread dump.psp2dmp crash
./psp2-core-parse registers dump.psp2dmp crash
./psp2-core-parse stack dump.psp2dmp crash --bytes 0x200
./psp2-core-parse backtrace dump.psp2dmp crash --image application=application.elf
./psp2-core-parse modules dump.psp2dmp
./psp2-core-parse memory-blocks dump.psp2dmp --captured-only
./psp2-core-parse libraries dump.psp2dmp --nid 0x00000000
./psp2-core-parse files dump.psp2dmp
./psp2-core-parse apps dump.psp2dmp
./psp2-core-parse processes dump.psp2dmp
./psp2-core-parse budgets dump.psp2dmp
./psp2-core-parse events dump.psp2dmp
./psp2-core-parse callbacks dump.psp2dmp
./psp2-core-parse timers dump.psp2dmp
./psp2-core-parse devices dump.psp2dmp
./psp2-core-parse summary dump.psp2dmp
./psp2-core-parse context dump.psp2dmp
./psp2-core-parse system2 dump.psp2dmp --output display.caf
./psp2-core-parse map dump.psp2dmp
./psp2-core-parse address dump.psp2dmp 0x81000000 --image application=application.elf
./psp2-core-parse memory dump.psp2dmp 0x81000000 0x40
./psp2-core-parse xref dump.psp2dmp 0x81000000
./psp2-core-parse search dump.psp2dmp --ascii "example"
./psp2-core-parse disasm dump.psp2dmp --image application=application.elf
./psp2-core-parse waits dump.psp2dmp
./psp2-core-parse object dump.psp2dmp 0x40010001
./psp2-core-parse tty dump.psp2dmp --tail 40
./psp2-core-parse validate dump.psp2dmp
./psp2-core-parse triage *.psp2dmp
./psp2-core-parse compare first.psp2dmp second.psp2dmp
./psp2-core-parse extract dump.psp2dmp --note THREAD_REG_INFO --output note.bin
```

Add `--json` to query commands for machine-readable output. Add `--strict` to reject structurally incomplete dumps.
