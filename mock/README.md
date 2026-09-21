# DLS21 8.13 Mock

This is the current **LAB V2 / CONTROL MOCK** used in the DLS21 preservation research.

## What it currently implements

- Local `NEWUSER`
- Local `SIGNIN`
- Minimal functional config
- Local `CAREERINIT`
- Local `CAREERENDMATCH`
- Dynamic profile/roster construction
- `DBv / DBt / DBp / DBl` database bootstrap
- Structural validation of `players.dat`, `teams.dat` and `teamplayerlinks.dat`
- Cross-database PID/TID validation
- Optional generated LAB fallback database
- Optional offline music configuration
- Unknown operations blocked locally
- Optional diagnostic shadow probe to the historical backend

## Database mapping

```text
DBt -> teams.dat
DBp -> players.dat
DBl -> teamplayerlinks.dat
DBv -> common database version
```

The mock sends Base64 of the `.dat` bytes as stored on disk. The game engine is expected to decode/write them.

## Database location

Recommended:

```bat
set DLS21_DB_DIR=C:\DLS21\database
```

The directory should contain:

```text
players.dat
teams.dat
teamplayerlinks.dat
```

The script also searches relative locations such as the script directory and current working directory.

## Run

```bat
mitmdump -s mock\dls_mock.py ^
  --listen-host 0.0.0.0 ^
  --listen-port 8080 ^
  --set connection_strategy=lazy
```

## Important cache note

The database is cached in memory by the mock.

After changing a `.dat` file, restart `mitmdump` before testing again.

## Shadow probe

The diagnostic real-backend shadow mode is **disabled by default**:

```python
SHADOW_REAL_BACKEND = False
```

When disabled, it does not contact the historical backend.

If a researcher deliberately enables it, the implementation is designed so that the real response is captured for diagnostics and is not passed back to the game.

## Generated LAB database

If no valid external database trio is found and the fallback option remains enabled, the mock can generate a minimal in-memory LAB database.

This fallback is **not an original DLS21 database** and must never be presented as one.

## Public-repository cleanup

The public copy removes machine-specific paths such as:

```text
C:\Users\<name>\...
```

Use `DLS21_DB_DIR` instead.

## Requirements

- Python 3
- mitmproxy / mitmdump

## Security

Do not commit:

- mitmproxy private CA keys
- APK signing private keys / keystores
- passwords
- tokens
- captured personal account/session data
