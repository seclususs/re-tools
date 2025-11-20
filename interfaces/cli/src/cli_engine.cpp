#include "cli_engine.h"
#include "cli_utils.h"
#include <iostream>
#include <sstream>

CliEngine::CliEngine() : tracing_active(false), active_handle(nullptr) {}

CliEngine::~CliEngine() {
    stop_background_trace();
}

json CliEngine::parse_and_free_json(char* json_ptr) {
    if (!json_ptr) {
        char* err = rt_get_last_error_message();
        std::string err_msg = err ? err : "Unknown Error";
        if(err) c_freeString(err);
        return json::object();
    }
    try {
        std::string str(json_ptr);
        c_freeString(json_ptr);
        if (str.empty()) return json::object();
        return json::parse(str);
    } catch (...) {
        return json::object();
    }
}

json CliEngine::get_header_info(const std::string& binary_path) {
    return parse_and_free_json(c_parseHeader_json(binary_path.c_str()));
}

json CliEngine::get_header_info_raw(const std::string& binary_path, int arch_id, uint64_t base_addr) {
    return parse_and_free_json(c_parseHeaderRaw_json(binary_path.c_str(), arch_id, base_addr));
}

json CliEngine::get_sections(const std::string& binary_path) {
    return parse_and_free_json(c_parseSeksi_json(binary_path.c_str()));
}

json CliEngine::get_symbols(const std::string& binary_path) {
    return parse_and_free_json(c_parseSimbol_json(binary_path.c_str()));
}

json CliEngine::get_imports(const std::string& binary_path) {
    return parse_and_free_json(c_parseImpor_json(binary_path.c_str()));
}

json CliEngine::get_exports(const std::string& binary_path) {
    return parse_and_free_json(c_parseEkspor_json(binary_path.c_str()));
}

json CliEngine::get_elf_dynamic(const std::string& binary_path) {
    return parse_and_free_json(c_parseElfDyn_json(binary_path.c_str()));
}

json CliEngine::extract_strings(const std::string& binary_path, int min_len) {
    return parse_and_free_json(c_scanString_rs(binary_path.c_str(), min_len));
}

json CliEngine::calc_entropy(const std::string& binary_path, int block_size) {
    return parse_and_free_json(c_calcEntropy_json(binary_path.c_str(), block_size));
}

json CliEngine::scan_yara(const std::string& binary_path, const std::string& rules) {
    return parse_and_free_json(c_scanYara_rs(binary_path.c_str(), rules.c_str()));
}

json CliEngine::scan_packer(const std::string& binary_path, double threshold) {
    return parse_and_free_json(c_scanPacker(binary_path.c_str(), threshold));
}

json CliEngine::scan_crypto(const std::string& binary_path) {
    return parse_and_free_json(c_scanKripto_json(binary_path.c_str()));
}

json CliEngine::scan_libs(const std::string& binary_path, const std::string& signatures) {
    return parse_and_free_json(c_scanLib(binary_path.c_str(), signatures.c_str()));
}

std::vector<uint64_t> CliEngine::get_data_xrefs(const std::string& binary_path, uint64_t va_data) {
    json j = parse_and_free_json(c_scanAksesData_json(binary_path.c_str(), va_data));
    if (j.is_array()) return j.get<std::vector<uint64_t>>();
    return {};
}

std::vector<uint64_t> CliEngine::get_func_callers(const std::string& binary_path, uint64_t va_func) {
    json j = parse_and_free_json(c_scanPenelepon_json(binary_path.c_str(), va_func));
    if (j.is_array()) return j.get<std::vector<uint64_t>>();
    return {};
}

json CliEngine::lift_instruction(const std::vector<uint8_t>& code, uint64_t va, int arch_id) {
    char* res = c_liftInstruksi(code.data(), code.size(), 0, va, (ArsitekturDisasm)arch_id);
    return parse_and_free_json(res);
}

json CliEngine::optimize_ir(const std::string& binary_path) {
    return parse_and_free_json(c_calcOptimasi(binary_path.c_str()));
}

std::string CliEngine::generate_cfg(const std::string& binary_path) {
    char* res = c_createCFG(binary_path.c_str());
    if (!res) return "";
    std::string s(res);
    c_freeString(res);
    return s;
}

std::string CliEngine::decompile_func(const std::string& binary_path, uint64_t va) {
    char* res = c_createPseudocode(binary_path.c_str(), va);
    if (!res) return "";
    std::string s(res);
    c_freeString(res);
    return s;
}

json CliEngine::analyze_liveness(const std::string& binary_path) {
    return parse_and_free_json(c_getLivenessAnalysis_json(binary_path.c_str()));
}

json CliEngine::analyze_reaching_defs(const std::string& binary_path) {
    return parse_and_free_json(c_getReachingDefs_json(binary_path.c_str()));
}

json CliEngine::analyze_def_use(const std::string& binary_path) {
    return parse_and_free_json(c_getDefUseChains_json(binary_path.c_str()));
}

json CliEngine::analyze_vsa(const std::string& binary_path) {
    return parse_and_free_json(c_getValueSetAnalysis_json(binary_path.c_str()));
}

json CliEngine::analyze_types(const std::string& binary_path) {
    return parse_and_free_json(c_getTipeInference_json(binary_path.c_str()));
}

json CliEngine::check_memory_access(const std::string& binary_path) {
    return parse_and_free_json(c_getMemoryAccessCheck_json(binary_path.c_str()));
}

std::vector<uint8_t> CliEngine::read_bytes_raw(const std::string& binary_path, uint64_t offset, size_t size) {
    std::vector<char> buffer(size * 3 + 1);
    int res = c_readBytes_hex(binary_path.c_str(), (int)offset, (int)size, buffer.data(), buffer.size());
    std::vector<uint8_t> data;
    if (res == 0) {
        std::string hex_str(buffer.data());
        std::istringstream iss(hex_str);
        std::string byte_str;
        while (iss >> byte_str) {
            try {
                data.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            } catch (...) {}
        }
    }
    return data;
}

bool CliEngine::write_bytes(const std::string& binary_path, uint64_t offset, const std::vector<uint8_t>& data) {
    return c_writeBytes(binary_path.c_str(), (int)offset, data.data(), (int)data.size()) == 1;
}

json CliEngine::search_pattern(const std::string& binary_path, const std::vector<uint8_t>& pattern) {
    return parse_and_free_json(c_scanPolaBytes_json(binary_path.c_str(), pattern.data(), pattern.size()));
}

void CliEngine::start_background_trace(int pid, std::function<void(const C_Registers&, const C_DebugEvent&)> on_update) {
    if (tracing_active) return;
    tracing_active = true;
    trace_thread = std::thread([this, pid, on_update]() {
        RT_Handle handle = rt_attachProses(pid);
        if (!handle) {
            tracing_active = false;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(trace_mutex);
            active_handle = handle;
        }
        C_DebugEvent event;
        while (tracing_active) {
            int res = rt_stepInstruksi(handle);
            if (res != 0) break;
            if (rt_waitEvent(handle, &event) == 0) {}
            C_Registers regs;
            if (rt_readRegister(handle, &regs) == 0) {
                on_update(regs, event);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        {
            std::lock_guard<std::mutex> lock(trace_mutex);
            active_handle = nullptr;
        }
        rt_detachProses(handle);
    });
    trace_thread.detach();
}

void CliEngine::stop_background_trace() {
    tracing_active = false;
    if (trace_thread.joinable()) {
        trace_thread.join();
    }
}

bool CliEngine::is_tracing() const {
    return tracing_active;
}

void CliEngine::set_breakpoint_sw(uint64_t va) {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) rt_insertTitikHentiSw(active_handle, va);
}

void CliEngine::remove_breakpoint_sw(uint64_t va) {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) rt_removeTitikHentiSw(active_handle, va);
}

void CliEngine::set_breakpoint_hw(uint64_t va, int slot) {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) rt_insertTitikHentiHw(active_handle, va, slot);
}

void CliEngine::remove_breakpoint_hw(int slot) {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) rt_removeTitikHentiHw(active_handle, slot);
}

json CliEngine::get_threads() {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) return parse_and_free_json(rt_listThread_json(active_handle));
    return json::array();
}

json CliEngine::get_memory_regions() {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) return parse_and_free_json(rt_readRegionMemori_json(active_handle));
    return json::array();
}

void CliEngine::set_syscall_trace(bool active) {
    std::lock_guard<std::mutex> lock(trace_mutex);
    if (active_handle) rt_setTraceSyscall(active_handle, active);
}

json CliEngine::resolve_dynamic_jumps(const std::string& binary_path, int pid, int max_steps) {
    return parse_and_free_json(rt_resolveDynamic(binary_path.c_str(), pid, max_steps));
}