#!/usr/bin/env python3
"""Analyze Dopamine binary for string patch safety."""
import struct, zipfile, sys, os

ipa_path = os.path.join(os.path.dirname(__file__), "Dopamine.ipa")

with zipfile.ZipFile(ipa_path, 'r') as z:
    for name in z.namelist():
        if name.endswith('/Dopamine') and '/Dopamine.app/' in name and '__MACOSX' not in name:
            data = z.read(name)
            print(f"Found: {name}")
            break

s1 = b'iOS 15.0 - 16.5.1 (arm64e)'
s2 = b'iOS 15.0 - 15.8.6 / 16.0 - 16.6.1 (arm64)'

print(f"Binary size: {len(data)} bytes")
print(f"\nString 1: {s1!r} ({len(s1)} bytes)")
count1 = data.count(s1)
print(f"  Occurrences: {count1}")
idx = -1
for i in range(count1):
    idx = data.find(s1, idx + 1)
    print(f"  #{i+1} at offset 0x{idx:x} ({idx})")

print(f"\nString 2: {s2!r} ({len(s2)} bytes)")
count2 = data.count(s2)
print(f"  Occurrences: {count2}")
idx = -1
for i in range(count2):
    idx = data.find(s2, idx + 1)
    print(f"  #{i+1} at offset 0x{idx:x} ({idx})")

# Check FAT or single
magic = struct.unpack('>I', data[:4])[0]
print(f"\nMagic: 0x{magic:08x}")

if magic in (0xcafebabe, 0xbebafeca):
    print("==> FAT (Universal) binary")
    nfat = struct.unpack('>I', data[4:8])[0]
    print(f"  Slices: {nfat}")
    slices = []
    for i in range(nfat):
        off = 8 + i * 20
        cpu, sub, foff, fsize, align = struct.unpack('>5I', data[off:off+20])
        cpuname = "arm64" if cpu == 0x100000c else f"0x{cpu:x}"
        if cpu == 0x100000c and sub == 0x02:
            cpuname = "arm64e"
        elif cpu == 0x100000c and sub == 0x00:
            cpuname = "arm64"
        print(f"  Slice {i}: {cpuname} (cpu=0x{cpu:x} sub=0x{sub:x}) offset=0x{foff:x} size=0x{fsize:x} ({fsize} bytes)")
        slices.append((cpuname, foff, fsize))

    # Check which slice each string occurrence falls in
    print("\n--- String location analysis ---")
    for label, needle in [("S1 arm64e-ver", s1), ("S2 arm64-ver", s2)]:
        idx = -1
        while True:
            idx = data.find(needle, idx + 1)
            if idx == -1:
                break
            for sname, soff, ssize in slices:
                if soff <= idx < soff + ssize:
                    rel = idx - soff
                    print(f"  {label}: offset 0x{idx:x} => in {sname} slice (relative 0x{rel:x})")
                    break
            else:
                print(f"  {label}: offset 0x{idx:x} => OUTSIDE any slice!!")

elif magic in (0xfeedface, 0xfeedfacf):
    print("==> Single-arch Mach-O")
    cputype = struct.unpack('<I', data[4:8])[0]
    cpusub = struct.unpack('<I', data[8:12])[0]
    print(f"  CPU: 0x{cputype:x} sub: 0x{cpusub:x}")
else:
    print(f"Unknown magic: 0x{magic:08x}")

# Also look for partial matches that might indicate dangerous overlaps
print("\n--- Checking for partial byte overlaps near critical sections ---")
# Look for "iOS 1" pattern to see if it appears in unexpected places
simple = b'iOS 1'
all_idx = []
idx = -1
while True:
    idx = data.find(simple, idx + 1)
    if idx == -1:
        break
    all_idx.append(idx)
print(f"Pattern 'iOS 1' found {len(all_idx)} times:")
for i in all_idx[:20]:
    ctx = data[i:i+60]
    text = ctx.replace(b'\x00', b'|').decode('ascii', errors='replace')
    print(f"  0x{i:x}: {text[:60]}")
