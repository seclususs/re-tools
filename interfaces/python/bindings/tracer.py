import ctypes
from utils.lib_loader import _lib

# Definisi tipe
RT_Handle = ctypes.c_void_p
u64 = ctypes.c_uint64
u8 = ctypes.c_ubyte
p_u8 = ctypes.POINTER(u8)
c_int = ctypes.c_int

# Tipe Data C-ABI
class C_Registers(ctypes.Structure):
    _fields_ = [
        ("rax", u64), ("rbx", u64), ("rcx", u64), ("rdx", u64),
        ("rsi", u64), ("rdi", u64), ("rbp", u64), ("rsp", u64),
        ("r8", u64), ("r9", u64), ("r10", u64), ("r11", u64),
        ("r12", u64), ("r13", u64), ("r14", u64), ("r15", u64),
        ("rip", u64),
        ("eflags", u64),
    ]

# Enum C-ABI untuk tipe event debugger
EVENT_UNKNOWN = 0
EVENT_BREAKPOINT = 1
EVENT_SINGLE_STEP = 2
EVENT_PROSES_EXIT = 3

_EVENT_MAP = {
    EVENT_UNKNOWN: "UNKNOWN",
    EVENT_BREAKPOINT: "BREAKPOINT",
    EVENT_SINGLE_STEP: "SINGLE_STEP",
    EVENT_PROSES_EXIT: "PROSES_EXIT",
}

class C_DebugEvent(ctypes.Structure):
    """ Struct C-ABI untuk hasil event debugger """
    _fields_ = [
        ("tipe", c_int), # DebugEventTipe (enum)
        ("pid_thread", c_int),
        ("info_alamat", u64), # Alamat breakpoint/exception
    ]
    
    def to_dict(self):
        tipe_str = _EVENT_MAP.get(self.tipe, "ERROR")
        info = self.info_alamat
        if tipe_str == "PROSES_EXIT":
            info_str = f"Exit code {info}"
        else:
            info_str = hex(info)
            
        return {
            "tipe": tipe_str,
            "thread_id": self.pid_thread,
            "info_alamat": self.info_alamat,
            "info_str": info_str
        }

# Setup prototype fungsi C
if _lib:

    # RT_Handle rt_attachProses(int pid);
    _lib.rt_attachProses.argtypes = [c_int]
    _lib.rt_attachProses.restype = RT_Handle

    # void rt_detachProses(RT_Handle handle);
    _lib.rt_detachProses.argtypes = [RT_Handle]
    _lib.rt_detachProses.restype = None

    # int rt_bacaMemory(RT_Handle handle, u64 addr, u8* out_buffer, int size);
    _lib.rt_bacaMemory.argtypes = [RT_Handle, u64, p_u8, c_int]
    _lib.rt_bacaMemory.restype = c_int

    # int rt_tulisMemory(RT_Handle handle, u64 addr, const u8* data, int size);
    _lib.rt_tulisMemory.argtypes = [RT_Handle, u64, p_u8, c_int]
    _lib.rt_tulisMemory.restype = c_int

    # int rt_setBreakpoint(RT_Handle handle, u64 addr);
    _lib.rt_setBreakpoint.argtypes = [RT_Handle, u64]
    _lib.rt_setBreakpoint.restype = c_int

    # int rt_singleStep(RT_Handle handle);
    _lib.rt_singleStep.argtypes = [RT_Handle]
    _lib.rt_singleStep.restype = c_int

    # int rt_traceSyscall(int pid);
    _lib.rt_traceSyscall.argtypes = [c_int]
    _lib.rt_traceSyscall.restype = c_int
    
    # int rt_getRegisters(RT_Handle handle, C_Registers* out_registers);
    _lib.rt_getRegisters.argtypes = [RT_Handle, ctypes.POINTER(C_Registers)]
    _lib.rt_getRegisters.restype = c_int
    
    # int rt_setRegisters(RT_Handle handle, const C_Registers* registers);
    _lib.rt_setRegisters.argtypes = [RT_Handle, ctypes.POINTER(C_Registers)]
    _lib.rt_setRegisters.restype = c_int
    
    # int rt_continueProses(RT_Handle handle);
    _lib.rt_continueProses.argtypes = [RT_Handle]
    _lib.rt_continueProses.restype = c_int
    
    # int rt_tungguEvent(RT_Handle handle, C_DebugEvent* event_out);
    _lib.rt_tungguEvent.argtypes = [RT_Handle, ctypes.POINTER(C_DebugEvent)]
    _lib.rt_tungguEvent.restype = c_int

# Wrapper Python
class Debugger:
    def __init__(self, pid: int):
        if not _lib:
            raise RuntimeError("Library re-tools core tidak termuat")
        self.handle = _lib.rt_attachProses(pid)
        if not self.handle:
            raise RuntimeError(f"Gagal attach ke PID {pid}")
        self.pid = pid
        self._register_names = [f[0] for f in C_Registers._fields_]

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
        print("Single step primitif sukses")

    def getRegisters(self) -> dict:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        
        c_regs = C_Registers()
        if _lib.rt_getRegisters(self.handle, ctypes.byref(c_regs)) != 0:
            raise RuntimeError("Gagal mengambil register")
            
        # Konversi C_Registers ke dict
        regs_dict = {}
        for field_name in self._register_names:
            regs_dict[field_name] = getattr(c_regs, field_name)
        return regs_dict
        
    def setRegisters(self, regs_dict: dict):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
            
        c_regs = C_Registers()
        # Isi c_regs dari dict
        for field_name in self._register_names:
            if field_name in regs_dict:
                setattr(c_regs, field_name, regs_dict[field_name])
                
        if _lib.rt_setRegisters(self.handle, ctypes.byref(c_regs)) != 0:
            raise RuntimeError("Gagal menyetel register")

    def continueProses(self):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if _lib.rt_continueProses(self.handle) != 0:
            raise RuntimeError("Gagal continue proses")
            
    def tungguEvent(self) -> dict:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
            
        c_event = C_DebugEvent()
        if _lib.rt_tungguEvent(self.handle, ctypes.byref(c_event)) != 0:
            raise RuntimeError("Gagal menunggu event (proses mungkin sudah exit?)")
        
        return c_event.to_dict()

# Fungsi standalone untuk syscall trace
def traceSyscall(pid: int):
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    print(f"Mulai melacak syscall untuk PID {pid}.")
    _lib.rt_traceSyscall(pid)
    print("Trace selesai.")