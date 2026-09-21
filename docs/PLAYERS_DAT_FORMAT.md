# players.dat Notes

> Reconstructed working format; not claimed byte-for-byte identical to an untouched original server database unless explicitly proven.

## Container

Known reconstruction work uses a zlib-compressed payload.

## Working record size

```text
0xB4 bytes / 180 bytes
```

## Important reconstructed fields

```text
+0x00  first name     UTF-16 fixed field
+0x20  last name      UTF-16 fixed field
+0x50  nickname       UTF-16 fixed field

+0x70  player ID
+0x72  nationality
+0x7C  height
+0x80  position
+0x88  foot

+0x8A  acceleration
+0x8C  speed
+0x8E  stamina
+0x90  strength
+0x92  tackling
+0x94  control
+0x96  shooting
+0x98  passing
+0x9A  goalkeeper reactions
+0x9C  goalkeeper handling
```

## Structural warning

Do not mix offsets between:

1. `players.dat` record
2. auxiliary `0x46` record
3. runtime `PlayerRecord`
4. `PlayerCard` UI object
