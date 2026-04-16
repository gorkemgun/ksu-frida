# KsuFrida

Frida gadget injection module for KernelSU/Magisk via Zygisk.

- Gadget is not embedded into the APK — APK integrity/signature checks still pass
- No ptrace — avoids ptrace-based detection
- Library remapping hides injected libraries from /proc/self/maps
- Configurable injection delay, child gating, and multiple library injection
- WebUI for managing targets from KernelSU Manager

## Prerequisites

- Rooted device with KernelSU or Magisk
- Zygisk enabled

## Quick Start

1. Download the latest release from the [Releases](https://github.com/gorkemgun/ksu-frida/releases) page
2. Install the ZIP via KernelSU/Magisk Manager
3. Reboot

### Option A: WebUI (KernelSU only)

Open KernelSU Manager → Modules → KsuFrida → WebUI. Add target apps, configure delay, toggle child gating.

### Option B: Manual config

```shell
adb shell su -c 'cp /data/local/tmp/libsec/config.json.example /data/local/tmp/libsec/config.json'
adb shell su -c "sed -i 's/com.example.package/your.target.app/' /data/local/tmp/libsec/config.json"
```

### Connecting

The default gadget config uses **listen mode** on port 27042. After opening the target app:

```shell
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l your_script.js
```

## Configuration

Config files are stored at `/data/local/tmp/libsec/`:

| File | Purpose |
|------|---------|
| `config.json` | Target apps, delay, child gating settings |
| `libsecmon.config.so` | Frida gadget config (listen/script mode) |
| `libsecmon.so` | Frida gadget binary (auto-installed) |

Example `config.json`:
```json
{
    "targets": [
        {
            "app_name": "com.example.app",
            "enabled": true,
            "kernel_assisted_evasion": false,
            "start_up_delay_ms": 0,
            "injected_libraries": [
                { "path": "/data/local/tmp/libsec/libsecmon.so" }
            ],
            "child_gating": {
                "enabled": false,
                "mode": "freeze",
                "injected_libraries": []
            }
        }
    ]
}
```

## Building

```shell
./gradlew :module:assembleRelease
```

Output ZIP will be in the `out/` directory.

To build, install and reboot directly:
```shell
./gradlew :module:flashAndRebootZygiskRelease
```

## Credits

- [lico-n](https://github.com/lico-n) — Original author of [ZygiskFrida](https://github.com/lico-n/ZygiskFrida)
- [electrondefuser](https://github.com/electrondefuser) — Library remapper, child gating, advanced config system
- [xDL](https://github.com/hexhacking/xDL)
- Inspired by [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)
