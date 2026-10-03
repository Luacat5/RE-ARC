""""
Can we get much higher?
(so high)
"""

from image import Image
from readconfig import steam_path
from os import path

pe = Image(path.join(steam_path, "MBTL.exe"))

# each value found in Ghirda decomp for MBTL.exe version 1.4.5
bounds_va = 0x8CDCF0
paths_va = 0x8B8270
size_va = 0x8A23E8
offsets_va = 0x8CDDB8
# key_tbl_va = 0x8B7E70

key_tbl_va = pe.find(b'\xd0\x50\x25\x99\x94\x0b\x20\x61\x54\xca\x25\xcc\xe6\xde\xd2\x4e\xf5\xaa')

bounds  = [pe.u32(bounds_va + 4*i) for i in range(22)]
count   = bounds[21]    
paths   = [pe.cstr(pe.u32(paths_va + 4*i)) for i in range(count)]
sizes   = [pe.u32(size_va + 4*i) for i in range(count)]
offsets = [pe.u32(offsets_va + 4*i) for i in range(count)]
key_tbl = pe.img[(key_tbl_va - pe.base)  : (key_tbl_va - pe.base) + 0x400]
