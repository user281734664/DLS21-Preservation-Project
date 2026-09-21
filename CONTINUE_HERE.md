# Continue Here

This is the exact technical handoff point.

## Current target

Identify the semantic meaning, origin and numeric scale of:

```text
auxiliary player record +0x04
```

The record size is:

```text
0x46 bytes
```

Known beginning:

```text
+0x00  uint16  Player ID                      [PROVEN]
+0x02  uint16  baseline high-precision rating [PROVEN]
+0x04  uint16  UNKNOWN                        [NEXT TARGET]
```

## Why +0x04 matters

Inside the player runtime path:

```text
rarity_score =
    *(uint16 *)(aux + 0x02)
  + *(uint16 *)(aux + 0x04)

tier =
    FUN_0035fe88(rarity_score, maxed)
```

The result is stored at:

```text
PlayerRecord +0xF8
```

and copied to:

```text
PlayerCard +0x4C8
```

## Confirmed thresholds

```text
<= 7599       -> 0
7600..8299    -> 1
>= 8300       -> 2
>= 8300 maxed -> 3
```

## Next reverse-engineering steps

1. Find every routine iterating the `0x46`-stride auxiliary player array.
2. Inspect every `ldrh` / `strh` touching record offset `+0x04`.
3. Trace the array population/deserialization path.
4. Determine whether `+0x04` is:
   - loaded from stored data,
   - calculated,
   - synchronized,
   - or derived from another player field.
5. Compare real values against known players.
6. Only then assign a semantic name.

## Do not assume

Do not name `+0x04` as:

```text
potential
rarity bonus
offset
development
```

until native evidence proves it.

## Useful functions

```text
FUN_0035d84c
FUN_0035fd94
FUN_0035fe88
FUN_00471694
FUN_00471604
FUN_00472290
FUN_00472384
FUN_00475bd0
```

## Research discipline

Do not modify real/reconstructed DAT fields simply to test an unsupported guess.

Close the data flow first, then test controlled reconstructed data.
