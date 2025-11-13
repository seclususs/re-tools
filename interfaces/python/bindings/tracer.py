import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None


class Debugger:
    def __init__(self, pid: int):
        if not re_tools:
            raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
        self.handle = re_tools.rt_attachProses(pid)
        if not self.handle:
            raise RuntimeError(f"Gagal attach ke PID {pid} (via re_tools)")
        self.pid = pid
        self._register_names = [] 

    def __del__(self):
        self.detachProses()

    def detachProses(self):
        if self.handle and re_tools:
            re_tools.rt_detachProses(self.handle)
            self.handle = None

    def bacaMemory(self, addr: int, size: int) -> bytes:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        data = re_tools.rt_bacaMemory(self.handle, addr, size)
        if data is None:
            raise RuntimeError(f"Gagal baca memori di alamat 0x{addr:x}")
        return data

    def tulisMemory(self, addr: int, data: bytes) -> int:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        bytes_written = re_tools.rt_tulisMemory(self.handle, addr, data)
        if bytes_written < 0:
            raise RuntimeError(f"Gagal tulis memori di alamat 0x{addr:x}")
        return bytes_written

    def setBreakpoint(self, addr: int):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if re_tools.rt_setBreakpoint(self.handle, addr) != 0:
            raise RuntimeError(f"Gagal set breakpoint di 0x{addr:x}")
        print(f"Breakpoint disetel di 0x{addr:x}")

    def singleStep(self):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if re_tools.rt_singleStep(self.handle) != 0:
            raise RuntimeError("Gagal single step")
        print("Single step primitif sukses")

    def getRegisters(self) -> dict:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        regs_dict = re_tools.rt_getRegisters(self.handle)
        if not regs_dict:
            raise RuntimeError("Gagal mengambil register")
        if not self._register_names:
            self._register_names = list(regs_dict.keys())
        return regs_dict
        
    def setRegisters(self, regs_dict: dict):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if re_tools.rt_setRegisters(self.handle, regs_dict) != 0:
            raise RuntimeError("Gagal menyetel register")

    def continueProses(self):
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        if re_tools.rt_continueProses(self.handle) != 0:
            raise RuntimeError("Gagal continue proses")
            
    def tungguEvent(self) -> dict:
        if not self.handle:
            raise RuntimeError("Sudah di-detach")
        event_dict = re_tools.rt_tungguEvent(self.handle)
        if not event_dict:
            raise RuntimeError("Gagal menunggu event (proses mungkin sudah exit?)")
        return event_dict

def traceSyscall(pid: int):
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
    print(f"Mulai melacak syscall untuk PID {pid}.")
    re_tools.rt_traceSyscall(pid)
    print("Trace selesai.")