For the sake of documentation, here's some info on how to get GDB and Yuzu working so that you can dump the game's memory and do other interesting things.

For this setup I used Yuzu on Windows 10 and Ubuntu on WSL.

Install devkitPro as specified on https://devkitpro.org/wiki/devkitPro_pacman into the WSL environment:

    sudo ln -s /proc/self/mounts /etc/mtab
	sudo dpkg -i devkitpro-pacman.deb
	dkp-pacman -Syu
	dkp-pacman -S devkitA64

Run yuzu and enable the GDB stub under Configuration > General > Debug.

Run `/opt/devkitpro/devkitA64/bin/aarch64-none-elf/gdb` inside WSL, and enter `target remote :24689` to connect.

I couldn't figure out how to get a memory map out of the very limited gdb support in yuzu, but you can do some painstaking binary searching to figure out where memory starts and ends -- for my setup with SMM v1.0.0, this was from `0x8000000` to `0xB325000`. The MOD0 header for Mario Maker's main binary begins at `0x8005000`.

    (gdb) dump memory memdump8000000.bin 0x8000000 0xB325000

