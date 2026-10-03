from tableextraction import bounds, offsets, sizes, paths, key_tbl
from encrypt import decrypt, encrypt

import hashlib
import os
from readconfig import steam_path

GAME = steam_path
OUT  = "../unpacked"

def unpack_single_bin(binNumber):
    with open(os.path.join(GAME, f"data{binNumber:03d}.bin"), "rb") as f:
        for s in range(bounds[binNumber], bounds[binNumber+1]):
            f.seek(offsets[s])
            plain = decrypt(f.read(sizes[s]), key_tbl)
            out = os.path.join(OUT, paths[s].replace("/", os.sep))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as o:
                o.write(plain)

def UNPACK_MBTL(binNumber=-1):
    if binNumber == -1:
        for a in range(21):
           unpack_single_bin(a)

def pack_folder_to_bin(binNumber):
    buf = bytearray()

    for s in range(bounds[binNumber], bounds[binNumber + 1] ):
        out_path = os.path.join(OUT, paths[s].replace("/", os.sep))
        with open(out_path, "rb") as g:
            enc = encrypt(g.read(), key_tbl)
        buf[offsets[s]:offsets[s] + len(enc)] = enc
        
    open(f"data{binNumber:03d}_rebuilt.bin", "wb").write(buf)    
    return buf

def VERIFY_UNPACK(binNumber) -> bool:
    src = os.path.join(GAME, f"data{binNumber:03d}.bin")
    buf  = pack_folder_to_bin(binNumber)
    return hashlib.sha256(buf).hexdigest() == hashlib.sha256(open(src, "rb").read()).hexdigest() 
