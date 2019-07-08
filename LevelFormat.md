This information relates to version 1.0.0 of _Super Mario Maker 2_. Not guaranteed to be correct; a lot of these fields are just educated guesses based off observations from the files included in the game.

## Encryption

Special thanks to simontime for writing a decryptor, which is available on GitHub here: [simontime/SMM2CourseDecryptor](https://github.com/simontime/SMM2CourseDecryptor)

See that repository for working decryption code. The configuration block it uses is as follows:

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8[16] | AES IV |
| 10 | u32[4] | Randomiser state (for key generation) |
| 20 | u8[16] | AES-CMAC digest |

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
| 00 | u8 | Y position of start (in tiles) |
| 01 | u8 | Y position of goal (in tiles) |
| 02 | u16 | X position of goal (in tiles * 10) |
| 04 | u16 | Time limit; defaults to 300 |
| 06 | u16 | Target amount required for clear condition |
| 08 | u16 | Creation year |
| 0A | u8 | Creation month |
| 0B | u8 | Creation day |
| 0C | u8 | Creation hour |
| 0D | u8 | Creation minute |
| 0E | u8 | Unknown byte |
| 0F | u8 | Clear condition type (more below) |
| 10 | u32 | Clear condition object (CRC32 of more below) |
| 14 | u32 | Unknown |
| 18 | u32 | Unknown |
| 1C | u32 | Always seems to be zeroes |
| 20 | u32 | Always seems to be 0xFFFFFFFF |
| 24 | u32 | Initialised to a random value when a level is created |
| .. | .. | .. zero in all files .. |
| F0 | u8 | Unknown, usually FF but sometimes set to other things |
| F1 | char[3] | Game style, null-terminated: `M1`, `M3`, `MW`, `WU`, `3W` |
| F4 | wchar16[33] | Course name, null-terminated, UCS-2 |
| 136 | wchar16[76] | Course description, null-terminated, UCS-2 |
| .. | .. | .. zero up to 0x200 (exclusive) |

## Clear Conditions

These appear to be controlled by three values in the level header: the condition type (field at 0xF), condition object (field at 0x10) and target amount (field at 0x6).

The following combinations are seen in the game's files:

| Type | String | Hash | Outcome |
|------|--------|------|---------|
| | None | `DFA2AFF1` | *unchecked* |
| 1 | EnemyKuribo | `7F07ACBF` | Must defeat X Goombas |
| | EnemyKakibo | `C77685E8` | *unchecked* |
| | EnemyNokonoko | `CCE12A46` | *unchecked* |
| | EnemyMet | `C7DAD20F` | *unchecked* |
| 1 | EnemyTogezo | `4B115542` | Must defeat X Spinies |
| | EnemyPakkun | `DF6717DE` | *unchecked* |
| | EnemyFirePakkun | `E50302F7` | *unchecked* |
| | EnemyBlackPakkun | `CE9A707B` | *unchecked* |
| 1 | EnemyNobinobiPakkun | `E47C2BE8` | Must defeat X Piranha Creepers |
| 1 | EnemyKaron | `E25C5F60` | Must defeat X Dry Bones |
| | EnemyFishBone | `563755F2` | *unchecked* |
| | EnemyPoo | `A3AEC34A` | *unchecked* |
| | EnemyChoropoo | `5A085610` | *unchecked* |
| | EnemyBros | `634A6671` | *unchecked* |
| | EnemyMegaBros | `A09BB51F` | *unchecked* |
| | EnemyJugem | `794C6EB3` | *unchecked* |
| 1 | EnemyGesso | `387C22CA` | Must defeat X Bloopers |
| 1 | EnemyPukupuku | `103BBA8C` | Must defeat X Cheeps |
| | EnemyTogemet | `FE75363E` | *unchecked* |
| | EnemyArihei | `4C44DA92` | *unchecked* |
| 1 | EnemyBubble | `7A128199` | Must defeat X Lava Bubbles |
| | EnemyWanwan | `CE2E5A15` | *unchecked* |
| | EnemyHanachan | `CF81610A` | *unchecked* |
| | EnemyBombhei | `48D111E0` | *unchecked* |
| | EnemyDossun | `7F88648A` | *unchecked* |
| | EnemyTeresa | `501C7C00` | *unchecked* |
| | EnemyTeren | `756120EE` | *unchecked* |
| | EnemyMagnumKiller | `FFE76309` | *unchecked* |
| | EnemyKameck | `F571D608` | *unchecked* |
| | EnemySun | `66C2B75E` | *unchecked* |
| | EnemyPyonchu | `F0F35CBA` | *unchecked* |
| | EnemyHacchin | `E3F62C75` | *unchecked* |
| | EnemyDonketsu | `4067AB4E` | *unchecked* |
| | EnemyUganFish | `3F50B513` | *unchecked* |
| | EnemyFugumannen | `3F4124E8` | *unchecked* |
| | EnemyHopper | `467AFB58` | *unchecked* |
| 1 | EnemyKoopa | `4B980B7F` | Must defeat X Bowsers |
| | EnemyKoopaJr | `CA315249` | *unchecked* |
| | EnemyBunbun | `3C164EB1` | *unchecked* |
| 1 | EnemyPunpun | `6DAA9A3F` | Must defeat X Pom Poms |
| | EnemyKiller | `405DCE65` | *unchecked* |
| 2 | ItemSuperKinoko | `ED1023EA` | Must be Super Mario |
| | ItemOneUpKinoko | `62B74A93` | *unchecked* |
| | ItemFireFlower | `2A8E77BB` | *unchecked* |
| | ItemSuperStar | `C73BE7EC` | *unchecked* |
| | ItemDekaKinoko | `7C8612D5` | *unchecked* |
| | ItemLeaf | `35A5AF47` | *unchecked* |
| | ItemFeather | `BB926013` | *unchecked* |
| 2 | ItemPropeller | `3A2F3996` | Must be Propeller Mario |
| | ItemSuperBell | `7DDB5D7F` | *unchecked* |
| | ItemSuperHammer | `B7402052` | *unchecked* |
| | ItemSuperBallFlower | `6A1CE415` | *unchecked* |
| | ObjectPowBlock | `66477BE4` | *unchecked* |
| | ObjectPowBlockRed | `48B4157B` | *unchecked* |
| | ObjectPSwitch | `63F3D532` | *unchecked* |
| | ObjectWoodBox | `E6F2EEBE` | *unchecked* |
| | ObjectJumpStep | `553A9590` | *unchecked* |
| | AdditionalItemShoe | `1A098D50` | *unchecked* |
| 2 | AdditionalItemYoshi | `FAE86A49` | Must be on Yoshi |
| | AdditionalItemHelmetMet | `B4FA3D4B` | *unchecked* |
| 2 | AdditionalItemHelmetTogezo | `DE0ABFC6` | Must wear a Spiny Shell |
| | AdditionalItemKoopaClown | `D9893249` | *unchecked* |
| 2 | AdditionalItemJugemCloud | `4C8772A3` | Must be on a Lakitu's Cloud |
| 2 | AdditionalItemKoopaCar | `DE56FFB5` | Must be on a Koopa Car |
| 2 | AdditionalItemKaronShoe | `97F8A309` | Must wear a Dry Bones Shell |
| 1 | Coin | `F55B3863` | Must collect X coins |
| | Coin10 | `C78F5040` | *unchecked* |
| | Coin30 | `F5B932C2` | *unchecked* |
| | Coin50 | `A3E39544` | *unchecked* |
| 3 | Damage | `1664515A` | Do not take damage |
| 3 | Land | `08327AE6` | Do not touch the ground |
| | ShellNokonoko | `3EAB9AA1` | *unchecked* |
| 3 | Crane | `97F4CF7A` | Do not use Swinging Claws |
| 3 | Water | `3AF23BDE` | Do not leave the water |
| 1 | BellTree | `C2A80228` | Must handstand on X trees |
| 1 | QuestChaseKinopio | `EF026A7F` | Must have X Toads |
| 2 | QuestMaterialStone | `46219146` | Must be carrying the stone |

The examples listed with a type and description are those seen in the files on romfs; others are guessed based on a list found in the binary. The objects are referenced by storing the CRC32 of their name.

## Level Area

Positioning in this game considers each tile to be 16x16. Some positions in the format specify values within this space, others address individual tiles instead, and others specify values multiplied by 10 (considering each tile to be 160x160). A veritable mess.

Coordinates and dimensions specified below will use the former unless specified otherwise. Y coordinates originate at the bottom, so higher values are further up.

This structure is of size 0x2DEE0.

| Offset | Type | Description |
|--------|------|-------------|
| 00 | u8 | course theme: 0 = ground, 1 = underground, 2 = castle, 3 = airship, 4 = underwater, 5 = ghost house, 6 = snow, 7 = desert, 8 = sky, 9 = forest |
| 01 | u8 | autoscroll type (00..04) |
| 02 | u8 | values seen: 00, 01 - editor seems to sometimes sets it to 1 for horizontal levels and 0 for vertical...? not sure what the criteria are |
| 03 | u8 | level orientation: 00 = horizontal, 01 = vertical |
| 04 | u8 | maximum height of water/lava |
| 05 | u8 | water/lava mode: 0 = static, 1 = continuous rise, 2 = rise/lower |
| 06 | u8 | water/lava movement speed: 0 = static, 1 = slow, 2 = medium, 3 = fast |
| 07 | u8 | minimum height of water/lava |
| 08 | u32 | right boundary (always 0x300 for vertical areas) |
| 0C | u32 | top boundary (always 0x1B0 for horizontal areas) |
| 10 | u32 | left boundary (always 0) |
| 14 | u32 | bottom boundary (always 0, except for certain vertical sub-areas) |
| 18 | u32 | some kinda bitfield :: &2 means night mode, &1 is unknown |
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

Default flags: 0x06000040

Examples observed:

- 2 : Wings (tested on Coin)
- 4 : Music block (tested on Note Block)
- 4 : Goombrat (tested on Goomba)
- 4 : Red shell (tested on Koopa)
- 4 : Red Cheep (tested on Cheep-Cheep)
- 4 : Shell only (tested on Buzzy Beetle)
- 4 : Blue (tested on Spike Top)
- 4 : Blooper Nanny (tested on Blooper)
- 4 : Shoots fireballs (tested on Piranha Plant)
- 4 : Deactivate burner
- 8 : Firebar rotates anti-clockwise
- 8 : Conveyor belt faces right
- 8 : Burner faces right
- 0x10 : Burner faces down
- 0x18 : Burner faces left
- 0x20 : Pipe faces left
- 0x40 : Pipe faces up (also set on most other objects)
- 0x60 : Pipe faces down
- 0x400 : Make object larger (tested on Goomba)
- 0x4000 : Red Yoshi (tested on Yoshi Egg)
- 0x8000 : Para (tested on Coin)
- 0x40000 : Mushroom addition (tested on Fire Flower)
- 0x40000 : Conveyor belt goes fast
- 0x40000 : Yellow platform (tested on Mushroom Platform)
- 0x80000 : Green platform (tested on Mushroom Platform)
- 0x40000 : 30 Coin (tested on 10 Coin)
- 0x80000 : 50 Coin (tested on 10 Coin)
- 0x40000 : Door is P-switch controlled
- 0x80000 : Door is key controlled
- 0x100000 : Slope goes down-right (steep)
- 0x200000 : Slope goes up-right (gentle - unnecessary?)
- 0x300000 : Slope goes down-right (gentle)
- 0x100000, 0x200000, 0x300000 ... 0xA00000 : Warp pipe ID (10 max, connects to corresponding pipe in other area)
- 0x000000, 0x200000 ... 0x700000 : Door ID (8 max, 0 connects to 1, 2 connects to 3, 4 connects to 5, 6 connects to 7)
- 0 : Spike pillar faces down
- 0x400000 : Spike pillar faces left
- 0x800000 : Spike pillar faces up
- 0xC00000 : Spike pillar faces right
- 0 : One-way Wall faces right
- 0x400000 : One-way Wall faces down
- 0x800000 : One-way Wall faces left
- 0xC00000 : One-way Wall faces up
- 0x100000 : Conveyor belt slope goes up-right (steep)
- 0x200000 : Conveyor belt slope goes down-right (steep)
- 0x400000 : Conveyor belt is switch-controlled
- 0 : Firebar is 1 tile long
- 0x400000 : Firebar is 2 tiles long
- 0x800000 : Firebar is 3 tiles long
- 0xC00000 : Firebar is 4 tiles long
- 0x1000000 : Firebar is 5 tiles long
- 0x1400000 : Firebar is 6 tiles long
- 0x1800000 : Firebar is 7 tiles long
- 0x1C00000 : Firebar is 8 tiles long
- 0 : Cannon faces up-left
- 0x400000 : Cannon faces up
- 0x800000 : Cannon faces up-right
- 0xC00000 : Cannon faces right
- 0x1000000 : Cannon faces left

Checkpoint flags:

- 0x6400000 : Rotated 90 degrees clockwise
- 0x6800000 : Rotated 180 degrees
- 0x6C00000 : Rotated 270 degrees

Pipes:

- 0x40000 : Red Pipe
- 0x80000 : Blue Pipe
- 0xC0000 : Yellow Pipe

- 0x06000000 : Facing Right
- 0x06000060 : Facing Down
- 0x06000020 : Facing Left

Thwomps:

- 0x06000058 : Normal Thwomp
- 0x06000040 : Left Thwomp
- 0x06000050 : Right Thwomp

Arrow Signs:

- 0x06000040 : Facing right
- 0x06400040 : Facing down-right
- 0x06800040 : Facing down
- 0x06C00040 : Facing down-left
- 0x07000040 : Facing left
- 0x07400040 : Facing up-left
- 0x07800040 : Facing up
- 0x07C00040 : Facing up-right

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
