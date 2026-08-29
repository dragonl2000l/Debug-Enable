#!/usr/bin/env python3
"""
ac5_earlyhook.py - run the Another Age debug menu where its output is used

Ghidra traced the real chain:

    0x0010065C  addiu $v0, $s7, 8304     ; $v0 = 0x00302070
    0x00100664  lw    $v1, 32($v0)       ; read STAGE from 0x00302090
    0x0010066C  sw    $v1, -22684($gp)   ; -> 0x004D91D4

and the map loader at 0x0019E428 reads 0x004D91D4, adding 4600 or 4800 to
make the archive index. So the game ALREADY propagates the debug menu's
variable into the map load. The menu was simply running too late: hooked at
0x00100788, roughly 300 bytes after the copy had happened.

This moves the hook to 0x00100654, the call immediately before the copy. The
displaced call to 0x001A7888 is preserved - the wrapper makes it first, then
runs the menu, so nothing is lost. $v0/$v1/$s0 are all recomputed after the
hook point, and $s4/$s7 are callee-saved, so the menu clobbering scratch
registers is safe.

No scratch word, no loader hook, no override. The menu writes 0x00302090 and
six instructions later the game copies it onward by itself.

    python3 ac5_earlyhook.py IMAGE.bin
    python3 ac5_earlyhook.py IMAGE.bin --apply
    python3 ac5_earlyhook.py IMAGE.bin --revert
    python3 ac5_earlyhook.py IMAGE.bin --repair    # from any earlier patch
"""

import argparse
import os
import sys

REGIONS = {
    "hook site": (
        0x000B2E54,
        bytes((0x22, 0x9E, 0x06, 0x0C)),                  # jal 0x001A7888
        bytes((0x58, 0x1C, 0x04, 0x0C))),                 # jal 0x00107160
    "wrapper": (
        0x000B9960,
        bytes((0xC0, 0xFE, 0xBD, 0x27, 0x40, 0x3A, 0x04, 0x24,
               0x20, 0x01, 0xBE, 0xFF, 0xC0, 0x3F, 0x05, 0x24,
               0x10, 0x01, 0xB7, 0xFF, 0x00, 0x01, 0xB6, 0xFF,
               0x4D, 0x00, 0x1E, 0x3C, 0xF0, 0x00, 0xB5, 0xFF,
               0x4D, 0x00, 0x17, 0x3C)),
        bytes((0xF0, 0xFF, 0xBD, 0x27,    # addiu $sp, $sp, -16
               0x00, 0x00, 0xBF, 0xFF,    # sd    $ra, 0($sp)
               0x22, 0x9E, 0x06, 0x0C,    # jal   0x001A7888  (displaced call)
               0x00, 0x00, 0x00, 0x00,    # nop
               0x7A, 0x1B, 0x04, 0x0C,    # jal   0x00106DE8  (debug menu)
               0x00, 0x00, 0x00, 0x00,    # nop
               0x00, 0x00, 0xBF, 0xDF,    # ld    $ra, 0($sp)
               0x08, 0x00, 0xE0, 0x03,    # jr    $ra
               0x10, 0x00, 0xBD, 0x27))), # addiu $sp, $sp, 16
}

# every address any earlier build of mine touched, with its stock bytes
REPAIR = {
    0x000B2E54: bytes((0x22, 0x9E, 0x06, 0x0C)),
    0x000B2F88: bytes((0x18, 0x1B, 0x04, 0x0C)),
    0x000B9FC8: bytes((0xA8, 0x98, 0x65, 0x24, 0xFC, 0x6B, 0x0B, 0x0C,
                       0x2D, 0x20, 0xA0, 0x03)),
    0x000B9960: bytes((
        0xC0, 0xFE, 0xBD, 0x27, 0x40, 0x3A, 0x04, 0x24, 0x20, 0x01, 0xBE, 0xFF,
        0xC0, 0x3F, 0x05, 0x24, 0x10, 0x01, 0xB7, 0xFF, 0x00, 0x01, 0xB6, 0xFF,
        0x4D, 0x00, 0x1E, 0x3C, 0xF0, 0x00, 0xB5, 0xFF, 0x4D, 0x00, 0x17, 0x3C,
        0xE0, 0x00, 0xB4, 0xFF, 0x4D, 0x00, 0x16, 0x3C, 0xD0, 0x00, 0xB3, 0xFF,
        0x4D, 0x00, 0x15, 0x3C, 0xC0, 0x00, 0xB2, 0xFF, 0x4D, 0x00, 0x14, 0x3C,
        0xB0, 0x00, 0xB1, 0xFF, 0x2F, 0x00, 0x12, 0x3C, 0xA0, 0x00, 0xB0, 0xFF,
        0x2D, 0x88, 0x00, 0x00, 0x30, 0x01, 0xBF, 0xFF, 0x28, 0xAF, 0x0A, 0x0C,
        0x06, 0x00, 0x10, 0x24, 0x4D, 0x00, 0x13, 0x3C, 0xFF, 0x00, 0x02, 0x3C,
        0x00, 0x08, 0x08, 0x24)),
}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--revert", action="store_true")
    ap.add_argument("--repair", action="store_true")
    args = ap.parse_args()

    if os.path.getsize(args.image) % 2048:
        print("refusing: not a 2048-byte-sector image")
        return 1

    if args.repair:
        with open(args.image, "r+b") as fh:
            for off, stock in REPAIR.items():
                fh.seek(off)
                fh.write(stock)
            fh.flush()
            os.fsync(fh.fileno())
        print("repaired: every region any earlier build touched is back to stock")
        return 0

    mode = "r+b" if (args.apply or args.revert) else "rb"
    with open(args.image, mode) as fh:
        state = {}
        for name, (off, orig, new) in REGIONS.items():
            fh.seek(off)
            cur = fh.read(len(orig))
            state[name] = ("stock" if cur == orig else
                           "patched" if cur == new else "UNKNOWN")
            print("%-10s 0x%08X  %-26s %s"
                  % (name, off, " ".join("%02X" % b for b in cur[:8]) + "..",
                     state[name]))

        if not (args.apply or args.revert):
            print("\nnothing written. --apply to install, --repair to clean up")
            return 0
        if "UNKNOWN" in state.values():
            print("\nrefusing: unrecognised state. run --repair first")
            return 1

        for name, (off, orig, new) in REGIONS.items():
            fh.seek(off)
            fh.write(orig if args.revert else new)
        fh.flush()
        os.fsync(fh.fileno())
        for name, (off, orig, new) in REGIONS.items():
            fh.seek(off)
            if fh.read(len(orig)) != (orig if args.revert else new):
                print("WRITE FAILED in %s" % name)
                return 1
        print("\n%s, verified" % ("reverted" if args.revert else
              "installed: menu now runs before the game copies your stage onward"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
