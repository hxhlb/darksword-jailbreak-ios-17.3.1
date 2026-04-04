#!/usr/bin/env python3
"""
sign_app.py v2 — Sign iOS .app bundle with Apple developer certificate.
Correct CodeDirectory v20400 layout with proper offset calculations.

Usage: python3 sign_app.py <app_dir> <cert.pem> <key.pem> <mobileprov>
"""

import hashlib
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile

# Apple Code Signature magic numbers
CSMAGIC_REQUIREMENTS  = 0xfade0c01
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSMAGIC_EMBEDDED_SIG  = 0xfade0cc0
CSMAGIC_BLOBWRAPPER   = 0xfade0b01
CSMAGIC_ENTITLEMENTS  = 0xfade7171

CS_HASHTYPE_SHA256 = 2
CS_HASHTYPE_SHA1   = 1
CS_PAGE_SIZE       = 4096

sha1   = lambda d: hashlib.sha1(d).digest()
sha256 = lambda d: hashlib.sha256(d).digest()
be32   = lambda v: struct.pack('>I', v)
be64   = lambda v: struct.pack('>Q', v)
beb    = lambda v: struct.pack('>B', v)

# Keep old aliases for compat
def pack_be32(v): return be32(v)

def make_blob(magic, payload):
    """Wrap payload in CS blob: magic(4) + length(4) + payload"""
    return be32(magic) + be32(8 + len(payload)) + payload

def make_requirements():
    """Minimal empty requirements blob."""
    return make_blob(CSMAGIC_REQUIREMENTS, be32(0))

def make_entitlements(ent_plist_path):
    """CMS entitlements blob from plist."""
    with open(ent_plist_path, 'rb') as f:
        data = f.read()
    return make_blob(CSMAGIC_ENTITLEMENTS, data)

def make_code_directory(binary_data, bundle_id, team_id, ent_hash, req_hash,
                        hash_type=CS_HASHTYPE_SHA256):
    """
    Build CodeDirectory v20400 blob with CORRECT offset layout.

    All offset fields (hashOffset, identOffset, teamOffset) are measured from
    the start of the CD *payload* (cd[0] = version field, NOT from blob magic/len).

    hashOffset points to codeslot[0] (first code page hash).
    Special slots [-n_special .. -1] are stored immediately before hashOffset.
    """
    if hash_type == CS_HASHTYPE_SHA256:
        hsz = 32
        hfn = sha256
    else:
        hsz = 20
        hfn = sha1

    ncode   = (len(binary_data) + CS_PAGE_SIZE - 1) // CS_PAGE_SIZE
    nspec   = 5  # slots -5=ents, -4=app, -3=codeResources, -2=reqs, -1=info

    ident_bytes = bundle_id.encode('utf-8') + b'\x00'
    team_bytes  = team_id.encode('utf-8')   + b'\x00'

    # v20400 fixed header is 80 bytes (fields version..execSegFlags)
    HDR = 80

    # Offsets measured from start of CD payload (cd[0])
    ident_off = HDR
    team_off  = ident_off + len(ident_bytes)
    spec_off  = team_off  + len(team_bytes)
    hash_off  = spec_off  + nspec * hsz   # codeslot[0] starts HERE

    # Build special slot hashes (indices 0..nspec-1 = slots -nspec..-1)
    specials  = [b'\x00' * hsz] * nspec
    if ent_hash and len(ent_hash) >= hsz:
        specials[0] = ent_hash[:hsz]   # slot -5 = entitlements
    if req_hash and len(req_hash) >= hsz:
        specials[3] = req_hash[:hsz]   # slot -2 = requirements
    spec_data = b''.join(specials)

    # Build code page hashes
    code_hashes = b''
    for i in range(ncode):
        page = binary_data[i*CS_PAGE_SIZE : min((i+1)*CS_PAGE_SIZE, len(binary_data))]
        code_hashes += hfn(page)

    # Assemble CD payload header (80 bytes)
    cd  = be32(0x20400)          # [0]  version
    cd += be32(0)                # [4]  flags
    cd += be32(hash_off)         # [8]  hashOffset → codeslot[0]
    cd += be32(ident_off)        # [12] identOffset
    cd += be32(nspec)            # [16] nSpecialSlots
    cd += be32(ncode)            # [20] nCodeSlots
    cd += be32(len(binary_data)) # [24] codeLimit
    cd += beb(hsz)               # [28] hashSize
    cd += beb(hash_type)         # [29] hashType
    cd += beb(0)                 # [30] platform
    cd += beb(12)                # [31] pageSize (log2 4096=12)
    cd += be32(0)                # [32] spare2
    # v20100
    cd += be32(0)                # [36] scatterOffset
    # v20200
    cd += be32(team_off)         # [40] teamOffset
    cd += be32(0)                # [44] spare3
    # v20300
    cd += be64(len(binary_data)) # [48] codeLimit64
    cd += be64(0)                # [56] execSegBase
    cd += be64(0)                # [64] execSegLimit
    # v20400
    cd += be64(0)                # [72] execSegFlags
    # Total = 80 bytes ✓

    assert len(cd) == HDR, f"CD header size is {len(cd)}, expected {HDR}"

    payload = cd + ident_bytes + team_bytes + spec_data + code_hashes
    return make_blob(CSMAGIC_CODEDIRECTORY, payload)


def make_cms_signature(cd_blob, cert_pem, key_pem):
    """Create CMS/PKCS#7 detached signature over CodeDirectory blob."""
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(cd_blob)
        cd_file = f.name

    sig_file = cd_file + '.sig'
    try:
        # iOS requires signed attributes — do NOT use -noattr
        cmd = [
            'openssl', 'cms', '-sign',
            '-signer', cert_pem,
            '-inkey', key_pem,
            '-binary', '-in', cd_file,
            '-outform', 'DER',
            '-out', sig_file,
            '-md', 'sha256',
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  OpenSSL CMS failed: {result.stderr.strip()}")
            return None
        with open(sig_file, 'rb') as f:
            sig = f.read()
        return make_blob(CSMAGIC_BLOBWRAPPER, sig)
    finally:
        for p in [cd_file, sig_file]:
            if os.path.exists(p):
                os.unlink(p)

def make_superblob(blobs):
    """Create EmbeddedSignature SuperBlob. blobs = [(slot_type, blob_bytes), ...]"""
    n = len(blobs)
    header_size = 12 + n * 8   # magic(4)+len(4)+count(4) + n*(type(4)+off(4))

    index     = b''
    body      = b''
    offset    = header_size

    for slot_type, blob_data in blobs:
        index += be32(slot_type) + be32(offset)
        body  += blob_data
        offset += len(blob_data)

    total = header_size + len(body)
    return be32(CSMAGIC_EMBEDDED_SIG) + be32(total) + be32(n) + index + body


def inject_signature(binary_path, signature, output_path=None):
    """Inject code signature into Mach-O binary by updating/adding LC_CODE_SIGNATURE."""
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Parse Mach-O header
    """Inject code signature into Mach-O binary (in-place if output_path is None)."""
    if output_path is None:
        output_path = binary_path
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())

    magic = struct.unpack('<I', data[0:4])[0]
    if magic != 0xfeedfacf:
        print(f"  Unknown Mach-O magic: 0x{magic:08x}")
        return False

    ncmds      = struct.unpack('<I', data[16:20])[0]
    sizeofcmds = struct.unpack('<I', data[20:24])[0]

    lc_cs_off    = None
    li_off       = None
    li_fileoff   = 0

    off = 32
    for _ in range(ncmds):
        cmd = struct.unpack('<I', data[off:off+4])[0]
        csz = struct.unpack('<I', data[off+4:off+8])[0]
        if cmd == 0x1d:  # LC_CODE_SIGNATURE
            lc_cs_off = off
        if cmd == 0x19:  # LC_SEGMENT_64
            sn = data[off+8:off+24].rstrip(b'\x00')
            if sn == b'__LINKEDIT':
                li_off      = off
                li_fileoff  = struct.unpack('<Q', data[off+40:off+48])[0]
        off += csz

    if lc_cs_off is None:
        # Insert new LC_CODE_SIGNATURE in padding space
        lc_end = 32 + sizeofcmds
        if data[lc_end:lc_end+16] == b'\x00' * 16:
            struct.pack_into('<IIII', data, lc_end, 0x1d, 16, 0, 0)
            struct.pack_into('<I', data, 16, ncmds + 1)
            struct.pack_into('<I', data, 20, sizeofcmds + 16)
            lc_cs_off = lc_end
            print(f"  Inserted LC_CODE_SIGNATURE at 0x{lc_end:x}")
        else:
            print("  ERROR: No space for LC_CODE_SIGNATURE")
            return False

    # Truncate old signature if present
    old_sig_off = struct.unpack('<I', data[lc_cs_off+8:lc_cs_off+12])[0]
    if old_sig_off and old_sig_off < len(data):
        del data[old_sig_off:]

    # Pad to 16-byte alignment
    while len(data) % 16:
        data.append(0)

    new_sig_off = len(data)
    data.extend(signature)

    # Update LC_CODE_SIGNATURE
    struct.pack_into('<I', data, lc_cs_off + 8,  new_sig_off)
    struct.pack_into('<I', data, lc_cs_off + 12, len(signature))
    print(f"  LC_CODE_SIGNATURE: off=0x{new_sig_off:x} size=0x{len(signature):x}")

    # Update __LINKEDIT
    if li_off:
        new_sz = new_sig_off + len(signature) - li_fileoff
        struct.pack_into('<Q', data, li_off + 32, (new_sz + 0x3fff) & ~0x3fff)
        struct.pack_into('<Q', data, li_off + 48, new_sz)
        print(f"  __LINKEDIT: fileoff=0x{li_fileoff:x} size=0x{new_sz:x}")

    with open(output_path, 'wb') as f:
        f.write(data)
    return True


def make_code_resources(app_dir, binary_name=None):
    """Generate _CodeSignature/CodeResources plist."""
    files  = {}
    files2 = {}

    for root, dirs, fnames in os.walk(app_dir):
        dirs[:] = [d for d in dirs if d != '_CodeSignature']
        for fname in fnames:
            full = os.path.join(root, fname)
            rel  = os.path.relpath(full, app_dir)

            if binary_name and rel == binary_name:
                continue
                
            with open(full, 'rb') as f:
                fdata = f.read()
            
            h256 = sha256(fdata)
            h1 = sha1(fdata)
            
            fdata = open(full, 'rb').read()
            h1    = sha1(fdata)
            h256  = sha256(fdata)
            files[rel]  = h1
            files2[rel] = {'hash': h1, 'hash2': h256}

    resource_dict = {
        'files':  files,
        'files2': files2,
        'rules': {
            '^.*': True,
            '^Info\\.plist$':              {'omit': True, 'weight': 20},
            '^embedded\\.mobileprovision$': {'weight': 20},
        },
        'rules2': {
            '^.*': True,
            '^Info\\.plist$':              {'omit': True, 'weight': 20},
            '^PkgInfo$':                   {'omit': True, 'weight': 20},
            '^embedded\\.mobileprovision$': {'weight': 20},
        },
    }

    cs_dir = os.path.join(app_dir, '_CodeSignature')
    os.makedirs(cs_dir, exist_ok=True)
    cr_path = os.path.join(cs_dir, 'CodeResources')
    with open(cr_path, 'wb') as f:
        plistlib.dump(resource_dict, f)
    print(f"  CodeResources: {len(files)} files sealed")
    return cr_path



def main():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <app_dir> <cert.pem> <key.pem> <mobileprov>")
        sys.exit(1)

    app_dir   = sys.argv[1]
    cert_pem  = sys.argv[2]
    key_pem   = sys.argv[3]
    mp_path   = sys.argv[4]

    # Info.plist
    with open(os.path.join(app_dir, 'Info.plist'), 'rb') as f:
        info = plistlib.load(f)
    binary_name = info.get('CFBundleExecutable', 'DarkSword')
    bundle_id   = info.get('CFBundleIdentifier', 'unknown')
    binary_path = os.path.join(app_dir, binary_name)

    print(f"=== Signing {binary_name} [{bundle_id}] ===")

    # Team ID from cert
    r = subprocess.run(['openssl', 'x509', '-in', cert_pem, '-noout', '-subject'],
                       capture_output=True, text=True)
    team_id = 'V945SAD4LF'
    for part in r.stdout.replace('/', ',').split(','):
        part = part.strip()
        if part.startswith('OU') and '=' in part:
            c = part.split('=', 1)[1].strip()
            if len(c) == 10:
                team_id = c; break
    print(f"  Team: {team_id}")

    # 1. Embed mobileprovision
    print("[1] Embed mobileprovision")
    shutil.copy2(mp_path, os.path.join(app_dir, 'embedded.mobileprovision'))

    # 2. Entitlements from mobileprovision
    print("[2] Extract entitlements")
    mp_data = open(mp_path, 'rb').read()
    s = mp_data.find(b'<?xml'); e = mp_data.find(b'</plist>') + 8
    ents = plistlib.loads(mp_data[s:e]).get('Entitlements', {})
    ents['application-identifier'] = f"{team_id}.{bundle_id}"
    ents['com.apple.developer.team-identifier'] = team_id
    ent_tmp = os.path.join(app_dir, '_ents.plist')
    with open(ent_tmp, 'wb') as f:
        plistlib.dump(ents, f)
    print(f"  {len(ents)} entitlements")

    # 3. CodeResources
    print("[3] CodeResources")
    make_code_resources(app_dir, binary_name)

    # 4. Blobs
    print("[4] CodeDirectory")
    binary_data = open(binary_path, 'rb').read()
    req_blob = make_requirements()
    ent_blob = make_entitlements(ent_tmp)

    cd256 = make_code_directory(binary_data, bundle_id, team_id,
                                sha256(ent_blob), sha256(req_blob), CS_HASHTYPE_SHA256)
    cd1   = make_code_directory(binary_data, bundle_id, team_id,
                                sha1(ent_blob),   sha1(req_blob),   CS_HASHTYPE_SHA1)
    print(f"  CD256={len(cd256)}b  CD1={len(cd1)}b")

    # 5. CMS
    print("[5] CMS signature")
    cms = make_cms_signature(cd256, cert_pem, key_pem)
    if not cms:
        print("  CMS failed — aborting")
        sys.exit(1)
    print(f"  CMS={len(cms)}b")

    # 6. SuperBlob
    sb = make_superblob([
        (0,       cd256),   # CSSLOT_CODEDIRECTORY
        (2,       req_blob),# CSSLOT_REQUIREMENTS
        (5,       ent_blob),# CSSLOT_ENTITLEMENTS
        (0x1000,  cd1),     # CSSLOT_ALTERNATE_CODEDIRECTORY (SHA1)
        (0x10000, cms),     # CSSLOT_CMS_SIGNATURE
    ])
    print(f"  SuperBlob={len(sb)}b")

    # 7. Inject
    print("[6] Inject signature")
    if not inject_signature(binary_path, sb):
        sys.exit(1)
    os.chmod(binary_path, 0o755)
    print(f"  Binary: {os.path.getsize(binary_path)}b")
    print("=== Signing complete ===")


if __name__ == '__main__':
    main()
