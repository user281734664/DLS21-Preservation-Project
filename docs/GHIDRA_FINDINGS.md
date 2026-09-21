# Ghidra Findings

## `FUN_0035d84c`

Player runtime construction/update path.

Known behavior includes:

- stat/runtime population
- overall calculation
- auxiliary per-player record lookup
- rarity calculation
- storage of tier at `PlayerRecord +0xF8`

## `FUN_0035fd94`

Overall/high-precision rating calculation.

```text
PlayerRecord +0xF0 = integer OVR
PlayerRecord +0xF4 = high-precision rating
```

## `FUN_0035fe88`

Card rarity/tier classifier:

```text
<=7599       -> 0
7600..8299   -> 1
>=8300       -> 2
>=8300 maxed -> 3
```

## `FUN_00471694`

Finds/copies a `0x46`-byte auxiliary per-player record.

Known fields:

```text
+0x00 Player ID
+0x02 baseline high-precision rating
+0x04 UNKNOWN
```

## Other useful functions

- `FUN_00471604` — copies the auxiliary-record list.
- `FUN_00472290` — development/progress calculation.
- `FUN_00472384` — accesses another field in the same record family.
- `FUN_00475bd0` — large player/config global copy.

## Next target

Trace all reads/writes/population paths involving:

```text
auxiliary record +0x04
```

Interior-field xrefs may be incomplete, so use pointer arithmetic, record stride and `ldrh/strh` patterns.
