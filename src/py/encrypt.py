# in the future I will use something faster, python is far too slow for operations like this.

def decrypt(buf: bytes, table: bytes) -> bytes:
    b = bytearray(buf)
    if len(b) < 2: return bytes(b)
    
    b[0] ^= 0xA5 # unscrambling
    b[1] ^= 0x18 
    
    key = b[0] ^ 0xAC # this is encrypt key
    ctr = ((b[1] ^ key) ^ 0x76381) & 0xFFFFFFFF # encrypt counter?
    
    for i in range(len(b) - 1, 1, -1):          # last byte down to index 2
        b[i] ^= table[(ctr & 0x3FF) ^ key]
        # Use the counter modulo 1024 to get the position in the table to use.
        # here 0x3FF = 1023 (thus giving 0 to 1023)
        # xor  the position with the "key" assigned from the first byte of the data.
        
        ctr = (ctr + 1) & 0xFFFFFFFF
        # increment the counter (Claude added an AND to keep it a 32 bit number)
        
    return bytes(b)


def encrypt(plain: bytes, table: bytes) -> bytes:
    b = bytearray(plain)
    if len(b) < 2: return bytes(b)
    
    key = b[0] ^ 0xAC                       
    ctr = ((b[1] ^ key) ^ 0x76381) & 0xFFFFFFFF
    
    # xOR undoes itself: (a ^ k) ^ k = a
    for i in range(len(b) - 1, 1, -1):
        b[i] ^= table[(ctr & 0x3FF) ^ key]
        # use counter % 1024 and xor with key
        # applying xOR to this bit again redoes the encryption
        ctr = (ctr + 1) & 0xFFFFFFFF
        #increment counter 
        
    b[0] ^= 0xA5 # scrambling
    b[1] ^= 0x18              
    
    return bytes(b)