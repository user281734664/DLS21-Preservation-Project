# Continue Here

Current target: identify the meaning/origin/scale of auxiliary player record `+0x04` in the `0x46`-byte per-player record.

Known:

```text
+0x00 Player ID [PROVEN]
+0x02 baseline high-precision rating [PROVEN]
+0x04 UNKNOWN [NEXT TARGET]
```

Rarity score = `uint16(aux+0x02) + uint16(aux+0x04)`.
