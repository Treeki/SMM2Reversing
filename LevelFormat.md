This information relates to version 1.0.0 of _Super Mario Maker 2_. Not guaranteed to be correct; a lot of these fields are just educated guesses based off observations from the files included in the game.

## Encryption

Special thanks to simontime for writing a decryptor, which is available on GitHub here: [simontime/SMM2CourseDecryptor](https://github.com/simontime/SMM2CourseDecryptor)

See that repository for working decryption code. The configuration block it uses is as follows:

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8[16] | AES IV |
| 10 | u32[4] | Randomiser state (for key generation) |
| 20 | u8[16] | Some sort of MAC |

## File Layout

Size 0x5C000. This describes the fixed-size .bcd files that contain each course in the game's romfs, following Yaz0 decompression and SARC extraction.

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u32 | Assumed version number -- must be 1 in v1.0.0 |
| 04 | u16 | Assumed version number -- must be 0x10 in v1.0.0 |
| 06 | *padding* | 2 empty bytes |
| 08 | u32 | CRC32 of the decrypted level file from offset 0x10 to 0x5BFD0 (non-inclusive) |
| 0C | char[4] | Magic `SCDL` (`53 53 44 4C`) |
| 10 | LevelHeader | level header (encrypted) |
| 210 | LevelArea | main level area (encrypted) |
| 2E0F0 | LevelArea | sub level area (encrypted) |
| 5BFD0 | CryptoCfg | information for the level file's encryption |

## Level Header

Size 0x200. Stores metadata about the level itself. Some of this is still unknown.

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | Unknown setting; defaults to 2 |
| 01 | u8 | Unknown setting; defaults to 2 |
| 02 | u16 | Might be a position in terms of game tiles * 10 |
| 04 | u16 | Time limit; defaults to 300 |
| 06 | u16 | Target amount required for clear condition |
| 08 | u16 | Creation year |
| 0A | u8 | Creation month |
| 0B | u8 | Creation day |
| 0C | u8 | Creation hour |
| 0D | u8 | Creation minute |
| 0E | u8 | Unknown byte |
| 0F | u8 | Clear condition type (more below) |
| 10 | u32 | Clear condition object |
| 14 | u32 | Unknown |
| 18 | u32 | Unknown |
| 1C | u32 | Always seems to be zeroes |
| 20 | u32 | Always seems to be 0xFFFFFFFF |
| 24 | u32 | Initialised to a random value when a level is created |
| .. | .. | .. zero in all files .. |
| F0 | u8 | Unknown, usually FF but sometimes set to other things |
| F1 | char[3] | Game style, null-terminated: `M1`, `M3`, `MW`, `WU`, `3W` |
| .. | .. | .. zero up to 0x114 (exclusive) .. |
| .. | .. | .. mostly zero (see below) up to 0x200 (exclusive) |

There's a bunch of data in that last block, but only in certain levels. I can't spot any consistent pattern to it. Where present, it starts at 0x114, except for quest_071 (Dirty Donuts), where it starts at 0x198. Perhaps this will become apparent at some point...

## Clear Conditions

These appear to be controlled by three values in the level header: the condition type (field at 0xF), condition object (field at 0x10) and target amount (field at 0x6).

The following combinations are seen in the game's files:

| Type | Object | Outcome |
|------|--------|---------|
| 1 | `F55B3863` | Must collect X coins |
| 1 | `EF026A7F` | Must have X Toads |
| 1 | `4B115542` | Must defeat X Spinies |
| 1 | `C2A80228` | Must handstand on X trees |
| 1 | `4B980B7F` | Must defeat X Bowsers |
| 1 | `103BBA8C` | Must defeat X Cheeps |
| 1 | `E25C5F60` | Must defeat X Dry Bones |
| 1 | `387C22CA` | Must defeat X Bloopers |
| 1 | `E47C2BE8` | Must defeat X Piranha Creepers |
| 1 | `7A128199` | Must defeat X Lava Bubbles |
| 1 | `6DAA9A3F` | Must defeat X Pom Poms |
| 1 | `7F07ACBF` | Must defeat X Goombas |
| 2 | `46219146` | Must be carrying the stone |
| 2 | `DE56FFB5` | Must be on a Koopa Car |
| 2 | `DE0ABFC6` | Must wear a Spiny Shell |
| 2 | `97F8A309` | Must wear a Dry Bones Shell |
| 2 | `4C8772A3` | Must be on a Lakitu's Cloud |
| 3 | `08327AE6` | Do not touch the ground |
| 3 | `97F4CF7A` | Do not use Swinging Claws |
| 3 | `3AF23BDE` | Do not leave the water |

I have a hunch that the 'Object' is some sort of hash of a name because Nintendo likes using those for things. Must investigate!

## Level Area

Positioning in this game considers each tile to be 16x16. Some positions in the format specify values within this space, others address individual tiles instead, and others specify values multiplied by 10 (considering each tile to be 160x160). A veritable mess.

Coordinates and dimensions specified below will use the former unless specified otherwise. Y coordinates originate at the bottom, so higher values are further up.

This structure is of size 0x2DEE0.

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | ranges from 00 to 09 |
| 01 | u8 | values seen: 00, 01, 02, 03, 04 |
| 02 | u8 | values seen: 00, 01 |
| 03 | u8 | 00 in main areas of all supplied levels, 01 in some sub areas |
| 04 | u8 | ranges from 00 to 0C in main areas, 00 to A1 in sub areas |
| 05 | u8 | values seen: 00, 01, 02 |
| 06 | u8 | values seen: 00, 01, 02, 03 |
| 07 | u8 | values seen: 00, 01, 02, 04, 06, 08, 09, 0C in main areas; 00, 01, 05, 0D, 10, 1C, 95, A1 in sub areas |
| 08 | u32 | usable width |
| 0C | u32 | usable height |
| 10 | u32 | seems to be always zero |
| 14 | u32 | zero everywhere except for sub-areas in Ancient Seesaw Fortress (0x230), Bing Bang Boom (0xE0), Fire Koopa Clown Carnage (0x1C0) |
| 18 | u32 | some kinda bitfield, values 0, 2, 3 spotted |
| 1C | u32 | object count |
| 20 | u32 | free-standing sound effect count |
| 24 | u32 | snake block count |
| 28 | u32 | clear pipe count |
| 2C | u32 | piranha creeper count |
| 30 | u32 | expanding block count |
| 34 | u32 | track block count |
| 38 | u32 | unused, always zero |
| 3C | u32 | tile count |
| 40 | u32 | rail count |
| 44 | u32 | icicle count |
| 48 | Object[2600] | objects |
| 14548 | SoundEffect[300] | free-standing sound effects (not attached to any object) |
| 149F8 | Snake[5] | snake block paths |
| 15CCC | ClearPipe[200] | clear pipes (3D World style) |
| 240EC | Creeper[10] | piranha creepers (3D World style) |
| 24434 | ExpandingBlock[10] | expanding blocks (3D World style) |
| 245EC | TrackBlock[10] | track blocks (3D World style) |
| 247A4 | Tile[4000] | simple terrain tiles |
| 28624 | Rail[1500] | rails (path tracks) as individual objects |
| 2CC74 | Icicle[300] | icicles |
| 2D124 | .. | .. 0xDBC unmapped bytes (maybe unused? need to check if any files have data here) |

## Objects/Parts

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u32 | X position * 10 (each tile is 160x160) |
| 04 | u32 | Y position * 10 (each tile is 160x160) |
| 08 | u16 | unused? |
| 0A | u8 | object width (in tiles) |
| 0B | u8 | object height (in tiles) |
| 0C | u32 | object flags |
| 10 | u32 | child object flags |
| 14 | u32 | extended data |
| 18 | u16 | object type |
| 1A | u16 | child object type (or 0xFFFF if no child) |
| 1C | u16 | link ID (or 0xFFFF if none) |
| 1E | u16 | sound effect (or 0xFFFF if none) |

As in Mario Maker 1, objects can contain children (e.g. enemies containing keys or powerups which appear when the enemy is killed, or blocks containing a variety of items).

The extended data field is usually zero, but is used by the following objects:

- `EditTsuta` (see quest_008)
- `EditFireBar` (see quest_020)
- `EditBubble` (see quest_023)
- `EditSnakeBlock`: references an ID from the Snake Block section of the file
- `EditNobinobiPakkun`: references an ID from the Piranha Creeper section of the file
- `EditBikkuriBlock`: references an ID from the Expanding Block section of the file
- `EditOrbitBlock`: references an ID from the Track Block section of the file

There may be more; these are just the examples that showed up in the courses in romfs.

## Freestanding Sound Effects

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | effect type |
| 01 | u8 | X position (in tiles) |
| 02 | u8 | Y position (in tiles) |
| 03 | *padding* | empty byte |

## Snake Block Tracks

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | ID |
| 01 | u8 | node count |
| 02 | u8 | unknown, always 1 - may signal "this slot is in use"? |
| 03 | *padding* | empty byte |
| 04 | SnakeNode[120] | nodes |

### Snake Block Nodes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u16 | index? starts at 0, goes up by 1 each node |
| 02 | u16 | seen values: 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 16 |
| 04 | u16 | seen values: 0x100 |
| 06 | u16 | unused? |

Weirdness in quest_051: the only snake block object refers to ID 2, and the only track structure has ID 1 and is in the second slot, not the first as you'd expect. Something odd is up there...

## Clear Pipes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | ID |
| 01 | u8 | node count |
| 02 | u8 | unknown, always 1 - may signal "this slot is in use"? |
| 03 | *padding* | empty byte |
| 04 | ClearPipeNode[36] | nodes |

### Clear Pipe Nodes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | unknown, ranges from 0 to 11 |
| 01 | u8 | index? starts at 0, goes up by 1 each node |
| 02 | u8 | unknown - wide spread, may be some kind of coordinate |
| 03 | u8 | unknown - wide spread, may be some kind of coordinate |
| 04 | u8 | seems to be always 2 |
| 05 | u8 | values seen: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 15, 16, 18, 21, 23, 26, 27, 35 |
| 06 | u8 | seems to be always 1 |
| 07 | u8 | values seen: 0, 1, 2, 3 |

## Piranha Creeper Tracks

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | unknown, always 1 - may signal "this slot is in use"? |
| 01 | u8 | ID |
| 02 | u8 | node count |
| 03 | *padding* | empty byte |
| 04 | CreeperNode[20] | nodes |

### Piranha Creeper Nodes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | seems to be always 1 |
| 01 | u8 | values seen: 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 |
| 02 | u8 | seems to be always 0 |
| 03 | u8 | seems to be always 0 |

## Expanding Block Tracks

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | unknown, always 1 - may signal "this slot is in use"? |
| 01 | u8 | ID |
| 02 | u8 | node count |
| 03 | *padding* | empty byte |
| 04 | ExpandingBlockNode[10] | nodes |

### Expanding Block Nodes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | seems to be always 1 |
| 01 | u8 | values seen: 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 |
| 02 | u8 | seems to be always 0 |
| 03 | u8 | seems to be always 0 |

## Track Block Tracks

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | unknown, always 1 - may signal "this slot is in use"? |
| 01 | u8 | ID |
| 02 | u8 | node count |
| 03 | *padding* | empty byte |
| 04 | TrackBlockNode[10] | nodes |

### Track Block Nodes

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | seems to be always 1 |
| 01 | u8 | values seen: 1, 2, 4, 5, 9, 11, 12, 13, 14, 15, 16 |
| 02 | u8 | seems to be always 0 |
| 03 | u8 | seems to be always 0 |

## Tiles

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | X position in tiles |
| 01 | u8 | Y position in tiles |
| 02 | u16 | tile ID |

## Rails

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u16 | seems to be always zero |
| 02 | u8 | always 0 or 1 |
| 03 | u8 | X position in tiles |
| 04 | u8 | Y position in tiles |
| 05 | u8 | unknown, in range 0-14 |
| 06 | u16 | unknown |
| 08 | u16 | unknown |
| 0A | u16 | unknown |

## Icicles

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | X position in tiles |
| 01 | u8 | Y position in tiles |
| 02 | u8 | always 0 or 1 |
| 03 | *padding* | empty byte |
