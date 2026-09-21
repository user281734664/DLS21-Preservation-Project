# DLS21 Preservation Project

Reverse-engineering and preservation research for **Dream League Soccer 2021**, focused primarily on the original **DLS21 v8.13** engine and offline preservation.

> **Status:** research handoff / work in progress.  
> This project is not affiliated with or endorsed by First Touch Games.

## Primary target

```text
Dream League Soccer 2021
Version: 8.13
versionCode: 38
Package: com.firsttouchgames.dls7
Native engine: DLS21
```

Official DLS 8.11 was also useful during some extraction/runtime experiments.

Third-party DLS19/DLS20-derived mods made to look like DLS21 are **not** treated as original DLS21 data sources.

## Project goals

- Preserve technical knowledge about the original DLS21 engine.
- Document the original player/database runtime behavior.
- Reproduce a controlled offline research environment.
- Document the local **mitmproxy + mock server** workflow.
- Reconstruct compatible local databases while clearly separating reconstructed data from untouched official data.
- Allow another researcher to continue from the exact point where the investigation stopped.

## Research architecture

```text
DLS21 Android
     |
     | HTTPS
     v
Wi-Fi proxy
PC_IP:8080
     |
     v
mitmproxy / mitmdump
     |
     v
mock/dls_mock.py
     |
     +--> local Frontline responses
     |
     +--> DBv / DBt / DBp / DBl
             |
             +--> teams.dat
             +--> players.dat
             +--> teamplayerlinks.dat
```

The mock/proxy environment is a **core part** of the project.

## Current mock

The current public mock is the **DLS21 8.13 LAB V2 / CONTROL MOCK**.

It currently contains support for:

- local `NEWUSER`
- local `SIGNIN`
- minimal functional config
- local `CAREERINIT`
- local `CAREERENDMATCH`
- dynamic Dream Team/profile structures
- local stadium/profile structures
- `DBv / DBt / DBp / DBl` database bootstrap
- structural validation of the three DAT databases
- PID/TID cross-database validation
- generated in-memory LAB fallback database
- offline music configuration
- blocking of unknown Frontline operations
- optional diagnostic shadow probe

See [mock/README.md](mock/README.md).

## Database mapping

```text
DBt -> teams.dat
DBp -> players.dat
DBl -> teamplayerlinks.dat
DBv -> common database version
```

The mock sends Base64 of the `.dat` bytes as stored on disk. The native engine is expected to decode and write them.

## Important research findings

### Runtime PlayerRecord

```text
+0xF0 = integer overall (OVR)
+0xF4 = high-precision rating
+0xF8 = card tier / rarity
```

### Card rarity classifier

`FUN_0035fe88`:

```c
int GetPlayerCardTier(int score, bool maxed)
{
    if (score <= 7599) return 0;
    if (score <= 8299) return 1;
    if (maxed) return 3;
    return 2;
}
```

Observed class mapping:

```text
0 = Common / gray-silver
1 = Rare / blue
2 = Legendary / gold
3 = Maxed / special dark
```

The tier stored at:

```text
PlayerRecord +0xF8
```

is later copied to:

```text
PlayerCard +0x4C8
```

## Current research blocker

The immediate target is the auxiliary per-player record:

```text
record size = 0x46 bytes
```

Known fields:

```text
+0x00  Player ID                       [PROVEN]
+0x02  baseline high-precision rating  [PROVEN]
+0x04  UNKNOWN                         [NEXT TARGET]
```

The rarity classifier receives:

```text
rarity_score =
    uint16(aux + 0x02)
  + uint16(aux + 0x04)
```

The next researcher should trace every read/write/population path for `aux +0x04`.

See [CONTINUE_HERE.md](CONTINUE_HERE.md).

## Start here

- [STATUS.md](STATUS.md) — current project state
- [CONTINUE_HERE.md](CONTINUE_HERE.md) — exact handoff point
- [docs/RARITY_SYSTEM.md](docs/RARITY_SYSTEM.md) — card-tier logic
- [docs/PLAYERS_DAT_FORMAT.md](docs/PLAYERS_DAT_FORMAT.md) — reconstructed player record notes
- [docs/GHIDRA_FINDINGS.md](docs/GHIDRA_FINDINGS.md) — native functions already identified
- [docs/APK_PATCHING.md](docs/APK_PATCHING.md) — reproduce the LAB / USER-CA APK
- [mock/README.md](mock/README.md) — real mock documentation
- [proxy/MITMPROXY_SETUP.md](proxy/MITMPROXY_SETUP.md) — proxy setup
- [proxy/TROUBLESHOOTING.md](proxy/TROUBLESHOOTING.md) — troubleshooting

## Evidence labels

Please preserve these labels in future contributions:

- **PROVEN** — closed by native assembly/data flow or repeatable runtime behavior.
- **IN PROGRESS** — strong evidence exists, but the loop is not fully closed.
- **HYPOTHESIS** — possible interpretation that still needs proof.

## Proprietary / sensitive files

Do not commit:

- original or modified APKs
- signing private keys
- keystore passwords
- mitmproxy private CA keys
- tokens
- credentials
- personal session/account captures
- private diagnostic captures

This repository documents the research and original tooling. Modified laboratory builds should always be clearly labeled as modified.

## Reproducing the LAB / USER-CA APK

The original DLS21 APK is **not distributed by this repository**.

Researchers who already have their own compatible DLS21 v8.13 APK can generate the LAB build used by this preservation project:

```bash
python tools/make_lab.py DLS21_813_original.apk
```

On Windows, a convenience launcher is also included:

```bat
tools\make_lab_windows.bat "C:\path\to\DLS21_813_original.apk"
```

The builder:

- verifies package `com.firsttouchgames.dls7`, v8.13 / versionCode 38;
- enables `android:debuggable`;
- trusts the Android user CA store for `api.ftpub.net`;
- rebuilds and zipaligns the APK;
- signs it with a local research key;
- checks SHA-256 of `classes*.dex` and `libDLS21.so` before/after the rebuild.

Default output:

```text
DLS21_813_USERCA_LAB_signed.apk
```

See [docs/APK_PATCHING.md](docs/APK_PATCHING.md) for the full process.

## How to run the mock

Example:

```bat
set DLS21_DB_DIR=C:\DLS21\database

mitmdump -s mock\dls_mock.py ^
  --listen-host 0.0.0.0 ^
  --listen-port 8080 ^
  --set connection_strategy=lazy
```

Then configure the Android device Wi-Fi proxy to:

```text
Host: <PC LAN IP>
Port: 8080
```

## ❤️ Support the project

A significant amount of time has gone into reverse engineering, testing, documenting and preserving Dream League Soccer 2021.

If this research has helped you and you would like to support the project, donations are completely optional.

### 🇧🇷 Brazil — Pix

Pix is Brazil's instant payment system.

**Random Pix key:**

```text
10c43492-762d-4e9a-9356-6462989e32d3
```

### 🇺🇸 International — USD

International donations in US dollars can be sent through the Banco Inter international banking channel below.

**Intermediary Bank:** JP Morgan Chase N.A.  
**SWIFT:** `CHASUS33`  
**ABA / Routing:** `021000021`  
**Account:** `360556937`

**Beneficiary Bank:** Banco Inter S.A.  
**SWIFT:** `ITEMBRSP`

**Beneficiary:** Lucas Emanuel dos Santos Oliveira  
**IBAN:** `BR3300416968000010231844590C1`

**Intermediary bank address:** 270 Park Avenue, New York, NY 10017, United States  
**Beneficiary bank address:** 1219 Barbacena Ave, Belo Horizonte, MG, 30190-924, Brazil

### 🇪🇺 International — EUR

International donations in euros can be sent through the Banco Inter international banking channel below.

**Intermediary Bank:** J.P. Morgan AG  
**SWIFT:** `CHASDEFX`

**Beneficiary Bank:** Banco Inter S.A.  
**SWIFT:** `ITEMBRSP`

**Beneficiary:** Lucas Emanuel dos Santos Oliveira  
**IBAN:** `BR3300416968000010231844590C1`

**Intermediary bank address:** Taunustor 1, Frankfurt, Germany  
**Beneficiary bank address:** 1219 Barbacena Ave, Belo Horizonte, MG, 30190-924, Brazil

Donations do not provide exclusive files, private builds or additional access.

## Contributing

The most valuable contribution right now is:

```text
Identify auxiliary player record +0x04
```

Issues are included for the main open research tracks.

## Disclaimer

Dream League Soccer and related proprietary assets are property of their respective rights holders.

This community research repository is intended for preservation, interoperability, technical study and archival documentation.
