# Jailbreak Kernel Patches

### Features

- Jailbreak
- Sandbox escape
- Debug settings
- Enable UART
- Disable system update messages
- Delete system updates
- Fake self support
- Fake pkg support
- RPC server
- RPC client in C#

I use the standard fake pkg keys, created by flatz.

### General Notes
**Only for 4.55 Jailbroken PlayStation 4 consoles!**

The main jkpatch payload utilizes a port of CTurt's payload sdk. Change the [Makefile](payload/Makefile) to have `LIBPS4` point to the ps4-payload-sdk directory on your machine. I could have it referenced from the home directory but meh...
```makefile
# change this to point to your ps4-payload-sdk directory
LIBPS4	:=	/home/John/ps4-payload-sdk/libPS4
```

If you decide to edit the `resolve` code in the kernel payload, make sure you do not mess with...
```c
void resolve(uint64_t kernbase);
```
... as it is called from `crt0.s`. And changing this will produce errors.

See other branches for other kernel support. I will support latest publically exploited firmware on main branch.

### RPC Quickstart

See either [Example.cs](librpc/Example.cs) or look at the [RPC documentation](librpc/jkpatch.pdf).

You can read/write memory, call functions, read/write kernel memory, and even load elfs.

[Here](https://www.youtube.com/watch?v=ieQPY4feBZo) is a cool example of an elf loaded into COD Ghosts (forge mod made by me!) You can download the source code to the forge mod [here](http://www.mediafire.com/file/v2m6513km68vmpd/forge.zip). Have fun!

### Coming Soon
- General code clean up and refactoring

Thank you to flatz, idc, zecoxao, hitodama, osdev.org, and anyone else I forgot!

Join the PS4 Cheater discord chat! Help grow the game modding community... https://discord.gg/WXgmWFh

Twitter: [@cloverleafswag3](https://twitter.com/cloverleafswag3) psxhax: [g991](https://www.psxhax.com/members/g991.473299/)

**golden <3**