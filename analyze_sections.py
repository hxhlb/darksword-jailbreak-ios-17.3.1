#!/usr/bin/env python3
"""Find which Mach-O section contains the target strings."""
import struct, zipfile, os

ipa_path = os.path.join(os.path.dirname(__file__), "Dopamine.ipa")

with zipfile.ZipFile(ipa_path, 'r') as z:
    for name in z.namelist():
        if name.endswith('/Dopamine') and '/Dopamine.app/' in name and '__MACOSX' not in name:
            data = z.read(name)
            break

# Parse Mach-O header (64-bit LE)
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = \
    struct.unpack('<IIIIIIII', data[:32])

print(f"Mach-O 64-bit: magic=0x{magic:x} cpu=0x{cputype:x} sub=0x{cpusub:x}")
print(f"  ncmds={ncmds} sizeofcmds={sizeofcmds}")

cpuname = "arm64"
if cputype == 0x0100000c:
    if cpusub & 0xff == 0x02:
        cpuname = "arm64e"
print(f"  Architecture: {cpuname}")

# Target strings
targets = [
    (b'iOS 15.0 - 16.5.1 (arm64e)', "arm64e version string"),
    (b'iOS 15.0 - 15.8.6 / 16.0 - 16.6.1 (arm64)', "arm64 version string"),
]

# Parse load commands to find sections
offset = 32  # after header
segments = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[offset:offset+8])

    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[offset+8:offset+24].split(b'\x00')[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[offset+24:offset+56])
        maxprot, initprot, nsects, flags_seg = struct.unpack('<IIII', data[offset+56:offset+72])
        print(f"\nSegment: {segname}")
        print(f"  fileoff=0x{fileoff:x} filesize=0x{filesize:x} (end=0x{fileoff+filesize:x})")
        print(f"  vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x}")

        # Parse sections
        for s in range(nsects):
            sec_off = offset + 72 + s * 80
            sectname = data[sec_off:sec_off+16].split(b'\x00')[0].decode()
            sect_segname = data[sec_off+16:sec_off+32].split(b'\x00')[0].decode()
            sec_addr, sec_size, sec_offset = struct.unpack('<QQI', data[sec_off+32:sec_off+52])
            print(f"  Section: {sect_segname}.{sectname}")
            print(f"    offset=0x{sec_offset:x} size=0x{sec_size:x} (end=0x{sec_offset+sec_size:x})")

            # Check if any target string falls in this section
            for needle, desc in targets:
                idx = data.find(needle)
                if idx != -1 and sec_offset <= idx < sec_offset + sec_size:
                    print(f"    *** FOUND '{desc}' at file offset 0x{idx:x} (in this section!) ***")

        segments.append((segname, fileoff, filesize))

    offset += cmdsize

# Summary: find section for each string
print("\n=== STRING LOCATION SUMMARY ===")
for needle, desc in targets:
    idx = data.find(needle)
    if idx == -1:
        print(f"  {desc}: NOT FOUND")
        continue
    found_in = None
    for segname, fileoff, filesize in segments:
        if fileoff <= idx < fileoff + filesize:
            found_in = segname
            break
    print(f"  {desc}: offset 0x{idx:x} => segment {found_in or 'UNKNOWN'}")
