Much of SMM2 is controlled by a state machine system. Conveniently, Nintendo has left plain-text names for all the states in the executable. Making use of them is a bit more of a pain - the state structures are all created dynamically.

Dumping the data from memory isn't really feasible; these are only created when needed, so you would have to trigger every single one and dump them afterwards.

Doing it by hand is prohibitive; there's hundreds of them. A reasonable middle ground is static analysis!

An initial attempt at this is provided in the `ExtractedStateList.md` file in this repository. The Ghidra script used for this is in the scripts subdirectory.
