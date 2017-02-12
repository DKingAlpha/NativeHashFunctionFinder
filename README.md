========================================================================
    NATIVE HASH FUNCTION FINDER : Console Application Project Overview
========================================================================

AppWizard has created this ConsoleApplication1 application for you.

(Yup it did!)

This program scans an actively running copy of GTAV.exe for known hashes
and produces output like this:

Includes https://github.com/gdabah/distorm library.

> Powerful Disassembler Library For x86/AMD64

**Currently supports b944.2 only**

If it isn't working, try unloading your stupid mods first.

```
Scanning process for PLAYER::GET_PLAYER_PED hash 0xc834a7c58deb59b4
 
0x1f48c5f0000: 0004
Found hash at address: 0x 1f49ab20428
Pointer to Native Function is at: 0x 1f49ab203e8
Native Function Address: 0x 7ff7464a39f4
00007ff7464a39f4 (05) e9e82e9a02               JMP 0x7ff748e468e1
00007ff748e468e1 (05) 48895c24f8               MOV [RSP-0x8], RBX
00007ff748e468e6 (05) 488d6424f8               LEA RSP, [RSP-0x8]
00007ff748e468eb (04) 4883ec20                 SUB RSP, 0x20
00007ff748e468ef (04) 488b4110                 MOV RAX, [RCX+0x10]
```

