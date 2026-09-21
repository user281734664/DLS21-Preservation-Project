# Player Card Rarity / Tier System

## PROVEN classifier

Native function:

```text
FUN_0035fe88
```

Equivalent behavior:

```c
int GetPlayerCardTier(int score, bool maxed)
{
    if (score <= 7599)
        return 0;

    if (score <= 8299)
        return 1;

    if (maxed)
        return 3;

    return 2;
}
```

## Tier mapping

```text
PlayerRecord +0xF8
        |
        v
PlayerCard +0x4C8
```

Observed mapping:

| Tier | Visual |
|---:|---|
| 0 | Common / gray-silver |
| 1 | Rare / blue-cyan |
| 2 | Legendary / gold |
| 3 | Maxed / special dark |

## Input score

The classifier does not receive visible integer OVR directly.

It receives:

```text
uint16(aux + 0x02) + uint16(aux + 0x04)
```

Known:

```text
aux +0x02 = baseline high-precision rating
aux +0x04 = unresolved
```

## Maxed

The maxed flag can become true when development progress reaches `1.0f`, or integer OVR reaches 100.

## Open problem

Understanding `aux +0x04` is required before fully explaining the visible rarity boundaries.
