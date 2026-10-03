import struct, pefile


# convert to VA: RVA - base

class Image:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()   # indexed by RVA

    def is_va(self, v):
        return self.base <= v < self.base + len(self.img)

    def u32(self, va):
        return struct.unpack_from("<I", self.img, va - self.base)[0]

    def cstr(self, va):
        rva = va - self.base 
        return self.img[rva:self.img.index(b"\0", rva)].decode("utf-8", "replace")

    def find(self, pattern):          # returns a VA, or None
        i = self.img.find(pattern)
        return None if i < 0 else i + self.base
    