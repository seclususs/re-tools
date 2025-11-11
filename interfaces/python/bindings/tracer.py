import ctypes
from utils.lib_loader import _lib

# Definisi tipe
RT_Handle = ctypes.c_void_p
u64 = ctypes.c_uint64
u8 = ctypes.c_ubyte
p_u8 = ctypes.POINTER(u8)

# Setup prototype fungsi C
if _lib:
    # RT_Handle rt_attachProses(int pid);
    _lib.rt_attachProses.argtypes = [ctypes.c_int]
    _lib.rt_attachProses.restype = RT_Handle

    # void rt_detachProses(RT_Handle handle);
    _lib.rt_detachProses.argtypes = [RT_Handle]
    _lib.rt_detachProses.restype = None

    # int rt_bacaMemory(RT_Handle handle, u64 addr, u8* out_buffer, int size);
    _lib.rt_bacaMemory.argtypes = [RT_Handle, u64, p_u8, ctypes.c_int]
    _lib.rt_bacaMemory.restype = ctypes.c_int

    # int rt_tulisMemory(RT_Handle handle, u64 addr, const u8* data, int size);
    _lib.rt_tulisMemory.argtypes = [RT_Handle, u64, p_u8, ctypes.c_int]
    _lib.rt_tulisMemory.restype = ctypes.c_int
    
    # int rt_setBreakpoint(RT_Handle handle, u64 addr);
    _lib.rt_setBreakpoint.argtypes = [RT_Handle, u64]
    _lib.rt_setBreakpoint.restype = ctypes.c_int

    # int rt_singleStep(RT_Handle handle);
    _lib.rt_singleStep.argtypes = [RT_Handle]
    _lib.rt_singleStep.restype = ctypes.c_int

    # int rt_traceSyscall(int pid);
    _lib.rt_traceSyscall.argtypes = [ctypes.c_int]
    _lib.rt_traceSyscall.restype = ctypes.c_int

# Wrapper Python
class Debugger:
    def __init__(self, pid: int):
        if not _lib:
            raise RuntimeError("Library re-tools core tidak termuat")
        self.handle = _lib.rt_attachProses(pid)
        if not self.handle:
            raise RuntimeError(f"Gagal attach ke PID {pid}")
        self.pid = pid

    def __del__(self):
        self.detachProses()

    def detachProses(self):
        if self.handle and _lib:
            _lib.rt_detachProses(self.handle)
            self.handle = None

    def bacaMemory(self, addr: int, size: int) -> bytes:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        
        buffer = (u8 * size)()
        bytes_read = _lib.rt_bacaMemory(self.handle, addr, buffer, size)
        
        if bytes_read < 0:
            raise RuntimeError(f"Gagal baca memori di alamat 0x{addr:x}")
        
        return bytes(buffer)[:bytes_read]

    def tulisMemory(self, addr: int, data: bytes) -> int:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")

        size = len(data)
        buffer = (u8 * size).from_buffer_copy(data)
        
        bytes_written = _lib.rt_tulisMemory(self.handle, addr, buffer, size)
        
        if bytes_written < 0:
            raise RuntimeError(f"Gagal tulis memori di alamat 0x{addr:x}")
        
        return bytes_written

    def setBreakpoint(self, addr: int):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if _lib.rt_setBreakpoint(self.handle, addr) != 0:
            raise RuntimeError(f"Gagal set breakpoint di 0x{addr:x}")
        print(f"Breakpoint disetel di 0x{addr:x}")

    def singleStep(self):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if _lib.rt_singleStep(self.handle) != 0:
            raise RuntimeError("Gagal single step")
        print("Single step sukses")

# Fungsi standalone untuk syscall trace
def traceSyscall(pid: int):
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    print(f"Mulai melacak syscall untuk PID {pid}.")
    _lib.rt_traceSyscall(pid)
    print("Trace selesai.")