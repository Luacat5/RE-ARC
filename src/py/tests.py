import tableextraction
from image import Image
from unpack import unpack_single_bin, VERIFY_UNPACK

def test1():
    print(tableextraction.key_tbl_va, tableextraction.key_tbl)
    if (tableextraction.key_tbl[len(tableextraction.key_tbl) - 1] != 0x14):
        print("Test Failed!")
    else:
        print("Test Passed!")

def test2():
    # unpack roundtrip test
    binNum = 0 # one of  the smaller bins

    unpack_single_bin(binNum)
    success = VERIFY_UNPACK(binNum)
    print(success)

    if success:
        print(f"Round trip succeed for bin: data{binNum:03d}.bin!")
    else:
        print(f"Failed Round trip test for data{binNum:03d}.bin... ")
    
    print(f"Please delete data{binNum:03d}_rebuilt.bin")
    
if __name__ == "__main__":
    test2()