#ifndef RETOOLS_CLI_ENGINE_H
#define RETOOLS_CLI_ENGINE_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>

#include "retools_static.h"
#include "retools_dynamic.h"
#include "retools_advanced.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

class CliEngine {
public:
    CliEngine();
    ~CliEngine();
    json get_header_info(const std::string& binary_path);
    json get_header_info_raw(const std::string& binary_path, int arch_id, uint64_t base_addr);
    json get_sections(const std::string& binary_path);
    json get_symbols(const std::string& binary_path);
    json get_imports(const std::string& binary_path);
    json get_exports(const std::string& binary_path);
    json get_elf_dynamic(const std::string& binary_path);
    json extract_strings(const std::string& binary_path, int min_len);
    json calc_entropy(const std::string& binary_path, int block_size);
    json scan_yara(const std::string& binary_path, const std::string& rules);
    json scan_packer(const std::string& binary_path, double threshold);
    json scan_crypto(const std::string& binary_path);
    json scan_libs(const std::string& binary_path, const std::string& signatures);
    std::vector<uint64_t> get_data_xrefs(const std::string& binary_path, uint64_t va_data);
    std::vector<uint64_t> get_func_callers(const std::string& binary_path, uint64_t va_func);
    json lift_instruction(const std::vector<uint8_t>& code, uint64_t va, int arch_id);
    json optimize_ir(const std::string& binary_path);
    std::string generate_cfg(const std::string& binary_path);
    std::string decompile_func(const std::string& binary_path, uint64_t va);
    json analyze_liveness(const std::string& binary_path);
    json analyze_reaching_defs(const std::string& binary_path);
    json analyze_def_use(const std::string& binary_path);
    json analyze_vsa(const std::string& binary_path);
    json analyze_types(const std::string& binary_path);
    json check_memory_access(const std::string& binary_path);
    std::vector<uint8_t> read_bytes_raw(const std::string& binary_path, uint64_t offset, size_t size);
    bool write_bytes(const std::string& binary_path, uint64_t offset, const std::vector<uint8_t>& data);
    json search_pattern(const std::string& binary_path, const std::vector<uint8_t>& pattern);
    void start_background_trace(int pid, std::function<void(const C_Registers&, const C_DebugEvent&)> on_update);
    void stop_background_trace();
    bool is_tracing() const;
    void set_breakpoint_sw(uint64_t va);
    void remove_breakpoint_sw(uint64_t va);
    void set_breakpoint_hw(uint64_t va, int slot);
    void remove_breakpoint_hw(int slot);
    json get_threads();
    json get_memory_regions();
    void set_syscall_trace(bool active);
    json resolve_dynamic_jumps(const std::string& binary_path, int pid, int max_steps);

private:
    json parse_and_free_json(char* json_ptr);
    std::atomic<bool> tracing_active;
    std::thread trace_thread;
    std::mutex trace_mutex;
    RT_Handle active_handle;
};

#endif