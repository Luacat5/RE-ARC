from tableextraction import bounds, offsets, sizes, paths, key_tbl
from encrypt import decrypt, encrypt

import hashlib
import os


GAME = r"C:\Program Files (x86)\Steam\steamapps\common\MELTY BLOOD TYPE LUMINA"
OUT  = "../unpacked"

def UNPACK_MBTL(binNumber=-1):
    if binNumber == -1:
        for a in range(21):
            with open(os.path.join(GAME, f"data{a:03d}.bin"), "rb") as f:
                for s in range(bounds[a], bounds[a+1]):
                    f.seek(offsets[s])
                    plain = decrypt(f.read(sizes[s]), key_tbl)
                    out = os.path.join(OUT, paths[s].replace("/", os.sep))
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with open(out, "wb") as o:
                        o.write(plain)
    else:
        with open(os.path.join(GAME, f"data{binNumber:03d}.bin"), "rb") as f:
            for s in range(bounds[binNumber], bounds[binNumber+1]):
                f.seek(offsets[s])
                plain = decrypt(f.read(sizes[s]), key_tbl)
                out = os.path.join(OUT, paths[s].replace("/", os.sep))
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as o:
                    o.write(plain)
                  
def VERIFY_UNPACK(binNumber) -> bool:
    src = os.path.join(GAME, f"data{binNumber:03d}.bin")
    size = os.path.getsize(src)
    buf = bytearray(size)

    for s in range(bounds[binNumber], bounds[binNumber + 1] ):
        out_path = os.path.join(OUT, paths[s].replace("/", os.sep))
        with open(out_path, "rb") as g:
            enc = encrypt(g.read(), key_tbl)
        buf[offsets[s]:offsets[s] + len(enc)] = enc

    open(f"data{binNumber:03d}_rebuilt.bin", "wb").write(buf)    
    return hashlib.sha256(buf).hexdigest() == hashlib.sha256(open(src, "rb").read()).hexdigest() 

                    
if __name__ == "__main__":
    # unpack roundtrip test
    binNum = 13 # one of  the smaller bins

    UNPACK_MBTL(binNum)
    success = VERIFY_UNPACK(binNum)
    print(success)

    if success:
        print(f"Round trip succeed for bin: data{binNum:03d}.bin!")
    else:
        print(f"Failed Round trip test for data{binNum:03d}.bin... ")
    
    print(f"Please delete data{binNum:03d}_rebuilt.bin")