# Research Status

Last handoff: September 2026.

## Primary target

```text
DLS21 v8.13
versionCode 38
package com.firsttouchgames.dls7
```

## Proven runtime fields

| Offset | Meaning | Status |
|---|---|---|
| `PlayerRecord +0xF0` | Integer OVR | PROVEN |
| `PlayerRecord +0xF4` | High-precision rating | PROVEN |
| `PlayerRecord +0xF8` | Card tier / rarity | PROVEN |
| `PlayerCard +0x4C8` | Card tier copied from PlayerRecord | PROVEN |

## Card-tier classifier

Function:

```text
FUN_0035fe88
```

Behavior:

```text
score <= 7599       -> tier 0
7600..8299          -> tier 1
score >= 8300       -> tier 2
score >= 8300 maxed -> tier 3
```

Observed visual classes:

```text
0 = Common / gray-silver
1 = Rare / blue
2 = Legendary / gold
3 = Maxed / special dark
```

## Auxiliary player record

Record stride:

```text
0x46 bytes
```

Known:

```text
+0x00 = Player ID                      [PROVEN]
+0x02 = baseline high-precision rating [PROVEN]
+0x04 = UNKNOWN                        [OPEN]
```

Rarity input:

```text
uint16(aux + 0x02) + uint16(aux + 0x04)
```

## Important native functions

```text
FUN_0035d84c  player runtime construction/update
FUN_0035fd94  overall/high-precision rating
FUN_0035fe88  card tier classifier
FUN_00471694  find/copy 0x46 auxiliary record
FUN_00471604  copy auxiliary record array
FUN_00472290  development/progress calculation
FUN_00472384  access another field in same record family
FUN_00475bd0  large player/config global copy
```

## Local mock

Current public mock:

```text
mock/dls_mock.py
```

Main supported flows include:

```text
NEWUSER
SIGNIN
CAREERINIT
CAREERENDMATCH
DBv/DBt/DBp/DBl bootstrap
```

## Core DAT files

```text
players.dat
teams.dat
teamplayerlinks.dat
```

Tiny bootstrap/test files must not be confused with complete original server databases.

## Current blocker

```text
auxiliary player record +0x04
```

See `CONTINUE_HERE.md`.
