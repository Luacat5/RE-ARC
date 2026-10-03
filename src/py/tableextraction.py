""""
Can we get much higher?
(so high)
"""

import struct, pefile

pe = pefile.PE("C:\\Program Files (x86)\\Steam\\steamapps\\common\\MELTY BLOOD TYPE LUMINA\\mbtl.exe")
BASE = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()


# helper functions that run on the file image
def u32(va):  return struct.unpack_from("<I", img, va - BASE)[0]
def cstr(va): return img[(va-BASE):img.index(b"\0", va - BASE)].decode("utf-8", "replace")

# each value found in Ghirda decomp for MBTL.exe version 1.4.5
bounds_va = 0x8CDCF0
paths_va = 0x8B8270
size_va = 0x8A23E8
offsets_va = 0x8CDDB8
key_tbl_va = 0x8B7E70 - BASE

bounds  = [u32(bounds_va + 4*i) for i in range(22)]
count   = bounds[21]    
paths   = [cstr(u32(paths_va + 4*i)) for i in range(count)]
sizes   = [u32(size_va + 4*i) for i in range(count)]
offsets = [u32(offsets_va + 4*i) for i in range(count)]
key_tbl = img[key_tbl_va : key_tbl_va + 0x400]
