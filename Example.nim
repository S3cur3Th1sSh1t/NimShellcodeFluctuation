import winim
import Fluctuation

echo "Trying to hook Sleep"

if (hookSleep()):
    echo "Hooked Sleep successfully!"
    
    type
      PocArray = array[12, byte]
    let names: PocArray = [byte 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA]
    g_fluctuationData.shellcodeAddr = unsafeAddr names[0]
    echo "Shellcode address:"
    echo repr(g_fluctuationData.shellcodeAddr)
    g_fluctuationData.shellcodeSize = size_t(len(names))
    echo "Shellcode Size:"
    echo repr(g_fluctuationData.shellcodeSize)
    # Recommend to use a random key for each round here instead of a static one
    when defined(amd64):
        g_fluctuationData.encodeKey = 0xDEADB33f
    when defined(i386):
        g_fluctuationData.encodeKey = 0xDEAD
    
    g_fluctuationData.currentlyEncrypted = false
    g_fluctuationData.protect = PAGE_READWRITE
    g_fluctuate = FluctuateToRW
    
    echo "Calling Sleep"
    Sleep(2500)
    echo "Everything went fine and as expected"
else:
    echo "Failed to hook Sleep"
    quit(1)