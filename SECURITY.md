# Security Policy

## Scope

This policy covers security vulnerabilities in `avb_verify` and its yocto build
tooling (`avb-verity.bbclass`). Issues in the upstream
[libavb](https://android.googlesource.com/platform/external/avb/) submodule
should be reported to the Android Open Source Project directly.

`avb_verify` is security-critical software: it runs in the initramfs as part
of the verified boot chain and gates dm-verity setup. A vulnerability here
could allow an attacker to bypass secureboot chain entirely.

## Supported Versions

Only the latest commit on the `master` branch receives security fixes.
No backport branches are maintained.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by e-mail to:

```
info@embetrix.com
```

Include in your report:

- A clear description of the vulnerability and its impact
- The affected code path (file and function if known)
- A proof-of-concept or reproduction steps
- Whether you intend to publish and on what timeline (coordinated disclosure
  is strongly preferred)

PGP encryption is welcome; key available on request.

## Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment | 7 business days |
| Fix or mitigation | 30 days (critical), 90 days (others) |
| Public disclosure | Coordinated with reporter |

## Threat Model

`avb_verify` is designed to defend against the following adversary:

- **Persistent attacker with flash write access**: can modify rootfs data in
  flash and must be stopped by dm-verity + root hash signature verification.
- **Runtime memory attacker**: can overwrite files in the initramfs (e.g.
  `pubkey.bin`) after the bootloader hands off to Linux but before `avb_verify`
  runs. The `roothash_sig` feature and the `-x` key digest option are the
  primary mitigations.

The following are **out of scope** (assumed trusted):

- The bootloader and its verification of the kernel/initramfs
- The kernel and its built-in keyring (`CONFIG_SYSTEM_TRUSTED_KEYS`)
- Physical attackers with JTAG/debug access

### Dependency on earlier boot stages

`avb_verify` sits at the end of a chain of trust, its guarantees are only as
strong as every stage before it:

- **ROM / BootROM**: if the SoC's immutable boot code is vulnerable or
  bypassed (e.g. via voltage glitching or a ROM exploit), an attacker can
  substitute an unsigned bootloader before the chain of trust is even
  established.
- **Bootloader (e.g. U-Boot, TF-A)**: must verify the initramfs with its own
  key before handing off to Linux. A compromised or misconfigured bootloader
  can load a tampered initramfs, making `avb_verify` itself attacker-controlled.
- **Secure Boot not enforced**: if the platform does not have hardware-enforced
  secure boot (e.g. HAB/AHAB on i.MX, TrustZone on ARM, Secure Boot on RPi),
  any attacker with flash access can replace the bootloader entirely, bypassing
  all subsequent verification including `avb_verify`.
- **Kernel cmdline tampering**: if the bootloader does not lock the kernel
  command line, an attacker can remove `dm_verity.require_signatures=1` and
  disable root hash signature enforcement before `avb_verify` runs.

**Mitigation**: enable and lock hardware secure boot on the SoC, verify the
full boot chain (ROM → bootloader →  kernel + initramfs), and protect the
kernel cmdline from modification (e.g. sign it as part of the FIT image or
use U-Boot with a locked/signed environment).

## Known Hardening Measures

| Measure | How to enable |
|---|---|
| Verify pubkey by digest (OTP) | `-x <sha256>` flag |
| Kernel-side root hash verification | `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y` |
| Enforce root hash signature | `dm_verity.require_signatures=1` on kernel cmdline |
| Post-quantum signing | Use `MLDSA65` or `MLDSA87` algorithm (Linux 7.x+) |