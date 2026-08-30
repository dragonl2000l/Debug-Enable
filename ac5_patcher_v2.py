#!/usr/bin/env python3
"""
ac5_patcher.py - install/uninstall patches for Armored Core 2: Another Age
                 (PS2 prototype, SLUS-20249)

Run with just the image path for an interactive menu, or drive it directly:

    python3 ac5_patcher.py IMAGE.bin                 # menu
    python3 ac5_patcher.py IMAGE.bin --list
    python3 ac5_patcher.py IMAGE.bin --install stageselect
    python3 ac5_patcher.py IMAGE.bin --uninstall stageselect

Each patch is a set of byte regions with a known stock value and a known
patched value. Install and uninstall both verify before and after writing, so
a partially-applied or foreign state is refused rather than compounded.
"""

import argparse
import os
import sys

# ---------------------------------------------------------------------------

PATCHES = {
    "stageselect": {
        "name": "Debug stage-select menu",
        "desc": ("Restores the developer STAGE / DEBUG MODE screen at the end of "
                 "a mission, hooked where the game copies your selection into "
                 "the map loader's index. LEFT/RIGHT cycle DEBUG MODE 0-7, the "
                 "stage buttons move STAGE over 0-199, Circle accepts, holding "
                 "Square for three seconds backs out."),
        "regions": [
            # hook site: jal 0x001A7888 -> jal 0x00107160 (our wrapper),
            # placed immediately before main copies 0x00302090 -> 0x004D91D4
            (0x000B2E54,
             bytes((0x22, 0x9E, 0x06, 0x0C)),
             bytes((0x58, 0x1C, 0x04, 0x0C))),
            # wrapper, written over the dead MODE SELECT function. It makes the
            # displaced call first so nothing is lost, then runs the menu.
            (0x000B9960,
             bytes((0xC0, 0xFE, 0xBD, 0x27, 0x40, 0x3A, 0x04, 0x24,
                    0x20, 0x01, 0xBE, 0xFF, 0xC0, 0x3F, 0x05, 0x24,
                    0x10, 0x01, 0xB7, 0xFF, 0x00, 0x01, 0xB6, 0xFF,
                    0x4D, 0x00, 0x1E, 0x3C, 0xF0, 0x00, 0xB5, 0xFF,
                    0x4D, 0x00, 0x17, 0x3C)),
             bytes((0xF0, 0xFF, 0xBD, 0x27,    # addiu $sp, $sp, -16
                    0x00, 0x00, 0xBF, 0xFF,    # sd    $ra, 0($sp)
                    0x22, 0x9E, 0x06, 0x0C,    # jal   0x001A7888   displaced
                    0x00, 0x00, 0x00, 0x00,    # nop
                    0x7A, 0x1B, 0x04, 0x0C,    # jal   0x00106DE8   debug menu
                    0x00, 0x00, 0x00, 0x00,    # nop
                    0x00, 0x00, 0xBF, 0xDF,    # ld    $ra, 0($sp)
                    0x08, 0x00, 0xE0, 0x03,    # jr    $ra
                    0x10, 0x00, 0xBD, 0x27))), # addiu $sp, $sp, 16
        ],
    },
    "debrief": {
        "name": "Debrief screen on mission failure",
        "desc": ("In AC2 the debrief ran win or lose. In Another Age it is "
                 "gated at 0x00100B74 on the mission-result byte "
                 "(0x002FD496) being 3. Nopping that branch lets the debrief "
                 "run on any result, so the seven currency lines - reward, "
                 "bonus, damage, special deduction, ammo, net and balance - "
                 "are settled after a failed mission too. Whether the net "
                 "actually debits you depends on what the settlement routine "
                 "computes with a non-3 result; that part is untested."),
        "regions": [
            # bne $v1, $v0, 0x00100324  ->  nop
            # $s3 is zeroed in the delay slot on both paths, so removing the
            # branch changes nothing except that it always falls through to
            # the unconditional branch to the debrief at 0x00100B7C.
            (0x000B3374,
             bytes((0xEB, 0xFD, 0x62, 0x14)),
             bytes((0x00, 0x00, 0x00, 0x00))),
        ],
    },
}

# Patches that are understood but not yet located precisely enough to ship.
# Listed so the menu tells you where things stand instead of staying silent.
PENDING = {}

# ---------------------------------------------------------------------------


def read_region(fh, off, n):
    fh.seek(off)
    return fh.read(n)


def status(fh, patch):
    """stock / installed / MIXED / UNKNOWN"""
    seen = set()
    for off, orig, new in patch["regions"]:
        cur = read_region(fh, off, len(orig))
        seen.add("stock" if cur == orig else
                 "installed" if cur == new else "UNKNOWN")
    if len(seen) == 1:
        return seen.pop()
    return "UNKNOWN" if "UNKNOWN" in seen else "MIXED"


def write_patch(path, patch, install):
    with open(path, "r+b") as fh:
        st = status(fh, patch)
        want = "stock" if install else "installed"
        if st == ("installed" if install else "stock"):
            print("already %s" % ("installed" if install else "uninstalled"))
            return True
        if st != want:
            print("refusing: regions are '%s', expected '%s'" % (st, want))
            return False
        for off, orig, new in patch["regions"]:
            fh.seek(off)
            fh.write(new if install else orig)
        fh.flush()
        os.fsync(fh.fileno())
        for off, orig, new in patch["regions"]:
            if read_region(fh, off, len(orig)) != (new if install else orig):
                print("WRITE FAILED at 0x%08X" % off)
                return False
    print("%s, verified" % ("installed" if install else "uninstalled"))
    return True


def show(path):
    print("\nimage: %s" % path)
    with open(path, "rb") as fh:
        for i, (key, p) in enumerate(PATCHES.items(), 1):
            print("\n  [%d] %-28s %s" % (i, p["name"], status(fh, p).upper()))
            print("      %s" % p["desc"])
    for key, p in PENDING.items():
        print("\n  [-] %-28s NOT AVAILABLE" % p["name"])
        print("      %s" % p["why"])
    print()


def menu(path):
    keys = list(PATCHES)
    while True:
        show(path)
        choice = input("number to toggle, or q to quit: ").strip().lower()
        if choice in ("q", "quit", ""):
            return 0
        if not choice.isdigit() or not (1 <= int(choice) <= len(keys)):
            print("not a valid choice")
            continue
        key = keys[int(choice) - 1]
        with open(path, "rb") as fh:
            st = status(fh, PATCHES[key])
        if st == "stock":
            write_patch(path, PATCHES[key], True)
        elif st == "installed":
            write_patch(path, PATCHES[key], False)
        else:
            print("regions are '%s' - refusing to touch them" % st)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--install", metavar="NAME")
    ap.add_argument("--uninstall", metavar="NAME")
    args = ap.parse_args()

    if not os.path.exists(args.image):
        print("no such file: %s" % args.image)
        return 1
    if os.path.getsize(args.image) % 2048:
        print("refusing: not a 2048-byte-sector image")
        return 1

    if args.install or args.uninstall:
        key = args.install or args.uninstall
        if key not in PATCHES:
            print("unknown patch '%s'. available: %s"
                  % (key, ", ".join(PATCHES)))
            return 1
        return 0 if write_patch(args.image, PATCHES[key],
                                bool(args.install)) else 1
    if args.list:
        show(args.image)
        return 0
    return menu(args.image)


if __name__ == "__main__":
    sys.exit(main())
