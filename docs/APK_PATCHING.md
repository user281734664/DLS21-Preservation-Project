# Reproducing the DLS21 v8.13 LAB / USER-CA APK

This repository does **not** contain or download the Dream League Soccer 2021 APK. Researchers must provide their own compatible DLS21 v8.13 APK.

## Target

```text
Package:     com.firsttouchgames.dls7
Version:     8.13
versionCode: 38
```

## Purpose

The preservation environment needs two application-level capabilities:

1. `android:debuggable="true"` so Android research tools such as `run-as` can access the application's private laboratory files.
2. Trust for a **user-installed CA** on `api.ftpub.net`, allowing mitmproxy to inspect the DLS Frontline HTTPS traffic in the controlled research environment.

The previously tested USER-CA LAB build demonstrated that this approach works on the project's Android test device. `tools/make_lab.py` turns that working setup into a reproducible recipe without redistributing the proprietary APK.

## Deliberate changes

### 1. Debuggable application

The LAB build sets:

```xml
<application
    android:debuggable="true"
    ... />
```

This enables workflows such as:

```bash
adb shell run-as com.firsttouchgames.dls7 id
```

### 2. Network Security Config / USER CA

The LAB build sets/retains:

```xml
android:networkSecurityConfig="@xml/network_security_config"
android:usesCleartextTraffic="true"
```

and writes:

```text
res/xml/network_security_config.xml
```

The config keeps normal Android system trust and additionally trusts certificates from the Android **user certificate store** for:

```text
api.ftpub.net
```

The relevant DLS21 v8.13 Frontline endpoint is:

```text
https://api.ftpub.net/DLSFrontlineStage/lambdastart_8130
```

## What the patcher intentionally does NOT modify

`tools/make_lab.py` does not intentionally patch:

- `libDLS21.so`
- game assets
- `players.dat`
- `teams.dat`
- `teamplayerlinks.dat`
- Frontline protocol logic
- application/game logic in smali

Apktool is invoked with `-s` / `--no-src`, so the original `classes*.dex` payload is carried through rather than being disassembled to smali and rebuilt.

After the APK is produced, the script compares SHA-256 hashes of every `classes*.dex` and every `lib/*/libDLS21.so` between the input APK and generated LAB APK. If any of those bytes change, the builder prints a warning and returns a non-zero exit status.

## Requirements

Install:

- Python 3.10+
- Java/JDK (`keytool`)
- Apktool
- Android SDK Build-Tools (`zipalign` and `apksigner`)

No third-party Python packages are required.

On Windows, the builder automatically checks common Android SDK locations such as:

```text
%LOCALAPPDATA%\Android\Sdk\build-tools\
```

It also checks `PATH`, `JAVA_HOME`, common JDK locations and common Apktool locations.

## Usage

From the repository root:

```bash
python tools/make_lab.py DLS21_813_original.apk
```

Windows shortcut:

```bat
tools\make_lab_windows.bat "C:\path\to\DLS21_813_original.apk"
```

Default output:

```text
DLS21_813_USERCA_LAB_signed.apk
```

## Local signing key

On first use, the builder creates:

```text
.dls21-lab.keystore
```

This is a **local research signing key**. Do not commit it to GitHub.

Keep the same keystore if later LAB builds need to install over previous LAB builds signed by the same researcher.

For a private persistent key, set a password through `DLS21_LAB_KS_PASS`.

Windows CMD:

```bat
set DLS21_LAB_KS_PASS=your-private-password
py tools\make_lab.py DLS21_813_original.apk
```

PowerShell:

```powershell
$env:DLS21_LAB_KS_PASS="your-private-password"
py tools/make_lab.py DLS21_813_original.apk
```

## Build without signing

```bash
python tools/make_lab.py DLS21_813_original.apk --no-sign -o DLS21_813_USERCA_LAB_aligned.apk
```

## Installation / signature warning

The generated LAB APK is signed with the researcher's local key, not the original publisher signature. Android therefore normally will **not** install it as an update over an official differently signed installation.

For a clean LAB device:

```bash
adb uninstall com.firsttouchgames.dls7
adb install DLS21_813_USERCA_LAB_signed.apk
```

For later LAB builds signed with the **same** local keystore:

```bash
adb install -r DLS21_813_USERCA_LAB_signed.apk
```

Uninstalling an Android application normally deletes its private app data, so preserve anything important first.

## mitmproxy

Install the mitmproxy CA on the Android research device as a **user certificate**. Configure the Android Wi-Fi proxy to the computer running mitmproxy, then run the project mock:

```bash
mitmdump -s mock/dls_mock.py --listen-port 8080
```

See:

- `proxy/MITMPROXY_SETUP.md`
- `proxy/ANDROID_PROXY_SETUP.md`
- `proxy/TROUBLESHOOTING.md`
- `mock/README.md`

## Preservation / distribution note

This patcher contains no DLS21 game binaries and does not download the game.

```text
researcher's own DLS21 v8.13 APK
        |
        v
tools/make_lab.py
        |
        +-- debuggable=true
        +-- USER CA trust for api.ftpub.net
        +-- rebuild / zipalign / local signature
        |
        v
DLS21_813_USERCA_LAB_signed.apk
```
