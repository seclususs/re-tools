#include "cli_repl.h"
#include "cli_utils.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/event.hpp>
#include <sstream>
#include <iomanip>
#include <cstdio> 

using namespace ftxui;

Element create_panel(std::string title, Element content) {
    return window(
        text(" " + title + " ") | bold | color(Color::Cyan),
        content | vscroll_indicator | yframe | flex
    ) | flex;
}

std::string fmt_addr(uint64_t addr) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << addr;
    return ss.str();
}

CliRepl::CliRepl(CliEngine& engine) : engine(engine) {}

void CliRepl::run() {
    std::string binary_path = "";
    std::string pid_input_str = "";
    std::string status_msg = "Idle - Ready to load target.";
    json cached_header;
    json cached_entropy;
    json cached_strings;
    json cached_vuln_scan;
    std::string cached_decompilation = "// Load binary and click 'Decompile Entry' to analyze.";
    C_Registers current_regs = {0};
    int tab_selected = 0;
    uint64_t hex_offset = 0;
    std::vector<std::string> menu_entries = {
        " 1. Overview         ", 
        " 2. Static Analysis  ", 
        " 3. Hex Editor       ", 
        " 4. Decompiler       ", 
        " 5. Security Audit   ", 
        " 6. Live Debugger    ", 
        " 7. Quit             "
    };
    auto menu = Menu(&menu_entries, &tab_selected);
    InputOption path_opt;
    path_opt.on_enter = [&] { status_msg = "Target path updated."; };
    Component input_path = Input(&binary_path, "Enter target binary path...", path_opt);
    Component btn_load = Button("LOAD TARGET", [&] {
        if (binary_path.empty()) { status_msg = "Error: Path cannot be empty."; return; }
        try {
            cached_header = engine.get_header_info(binary_path);
            cached_entropy = engine.calc_entropy(binary_path, 64);
            status_msg = "Target loaded successfully.";
        } catch(...) { status_msg = "Failed to parse target binary."; }
    });
    Component btn_scan_static = Button("Run Deep Static Scan", [&] {
        if (binary_path.empty()) return;
        cached_strings = engine.extract_strings(binary_path, 4);
        status_msg = "Static analysis complete.";
    });
    Component btn_decompile = Button("Decompile Entry Point", [&] {
        if (binary_path.empty()) { status_msg = "Load binary first."; return; }
        uint64_t entry_va = 0;
        if (cached_header.contains("entry_point")) {
            entry_va = cached_header["entry_point"].get<uint64_t>();
        }
        if (entry_va == 0) {
            status_msg = "Error: No entry point found in header.";
            cached_decompilation = "// Error: Could not determine entry point address.";
            return;
        }
        status_msg = "Decompiling function at " + fmt_addr(entry_va) + "...";
        try {
            std::string code = engine.decompile_func(binary_path, entry_va);
            if (code.empty()) {
                cached_decompilation = "// Decompilation failed or returned empty result.";
            } else {
                cached_decompilation = code;
                status_msg = "Decompilation successful.";
            }
        } catch (...) {
            cached_decompilation = "// Exception during decompilation process.";
            status_msg = "Decompilation crashed.";
        }
    });
    Component btn_audit = Button("Start Security Audit", [&] {
        if (binary_path.empty()) return;
        cached_vuln_scan = engine.analyze_vsa(binary_path);
        status_msg = "Security audit complete. Checking results...";
    });
    Component input_pid = Input(&pid_input_str, "Process ID (PID)");
    Component btn_attach = Button("Attach Debugger", [&] {
        try {
            int pid = std::stoi(pid_input_str);
            engine.start_background_trace(pid, [&](const C_Registers& r, const C_DebugEvent&) {
                current_regs = r;
            });
            status_msg = "Debugger attached to PID " + pid_input_str;
        } catch(...) { status_msg = "Invalid PID format."; }
    });
    Component btn_detach = Button("Detach / Stop", [&] {
        engine.stop_background_trace();
        status_msg = "Debugger detached.";
    });
    auto layout = Container::Vertical({
        Container::Horizontal({ input_path, btn_load }),
        Container::Horizontal({
            menu | border,
            Container::Tab({
                Renderer([]{ return text(""); }),
                btn_scan_static,
                Renderer([]{ return text(""); }),
                btn_decompile,
                btn_audit,
                Container::Vertical({ input_pid, Container::Horizontal({ btn_attach, btn_detach }) }),
                Renderer([]{ return text(""); })
            }, &tab_selected) | flex
        }) 
    });
    auto renderer = Renderer(layout, [&] {
        auto title_bar = hbox({
            text(" ReTools CLI ") | bold | color(Color::White) | bgcolor(Color::Blue),
            text(" Reverse Engineering Suite ") | color(Color::GrayLight),
            filler(),
            text(" STATUS: " + status_msg + " ") | color(Color::Black) | bgcolor(Color::Cyan)
        });
        Element content_view;
        if (tab_selected == 0) {
            Elements info_list;
            if (!cached_header.empty()) {
                info_list.push_back(hbox({text("File Type    : ") | bold, text(cached_header.value("format", "Unknown"))}));
                info_list.push_back(hbox({text("CPU Arch     : ") | bold, text(cached_header.value("arch", "Unknown"))}));
                info_list.push_back(hbox({text("Word Size    : ") | bold, text(std::to_string(cached_header.value("bits", 0)) + "-bit")}));
                info_list.push_back(hbox({text("Entry Point  : ") | bold, text(fmt_addr(cached_header.value("entry_point", 0ULL))) | color(Color::Yellow)}));
                info_list.push_back(hbox({text("File Size    : ") | bold, text(std::to_string(cached_header.value("file_size", 0)) + " bytes")}));
            } else {
                info_list.push_back(text("Waiting for target binary...") | dim);
            }
            Elements entropy_bars;
            if (cached_entropy.is_array()) {
                for (const auto& val : cached_entropy) {
                    float v = val.get<float>();
                    Color c = (v > 7.2) ? Color::Red : (v > 6.0) ? Color::Yellow : Color::Green;
                    entropy_bars.push_back(text("█") | color(c));
                }
            } else {
                entropy_bars.push_back(text("No entropy data.") | dim);
            }
            content_view = vbox({
                create_panel("Target Metadata", vbox(std::move(info_list))),
                create_panel("Entropy Map", hflow(std::move(entropy_bars))) 
            });
        }
        else if (tab_selected == 1) {
            Elements list_str;
            if (cached_strings.is_array()) {
                int count = 0;
                for (auto& s : cached_strings) {
                    if (count++ > 100) break;
                    std::string str_content = "";
                    if (s.is_string()) {
                        str_content = s.get<std::string>();
                    } else if (s.is_object() && s.contains("content")) {
                        str_content = s.value("content", "[Empty/Invalid String]");
                    } else {
                        str_content = s.dump();
                    }
                    list_str.push_back(paragraph(str_content));
                    list_str.push_back(separator() | dim); 
                }
                if (cached_strings.size() > 100) {
                    list_str.push_back(text("... output truncated (" + std::to_string(cached_strings.size() - 100) + " more) ...") | color(Color::Yellow));
                }
            } else {
                list_str.push_back(text("Run scan to see strings & imports.") | dim);
            }
            content_view = vbox({
                btn_scan_static->Render(),
                separator(),
                create_panel("Extracted Strings", vbox(std::move(list_str)))
            });
        }
        else if (tab_selected == 2) {
            if (binary_path.empty()) {
                content_view = text("Please load a target first.") | center;
            } else {
                auto bytes = engine.read_bytes_raw(binary_path, hex_offset, 128);
                Elements rows;
                rows.push_back(text("Offset    00 01 02 03 04 05 06 07  ASCII") | bold | color(Color::Cyan));
                rows.push_back(separator());
                for (size_t i = 0; i < bytes.size(); i += 8) {
                    std::string hex_part, ascii_part;
                    char buf[32];
                    snprintf(buf, 32, "%08llX  ", (unsigned long long)(hex_offset + i));
                    hex_part += buf;
                    for (size_t j = 0; j < 8; ++j) {
                        if (i + j < bytes.size()) {
                            uint8_t b = bytes[i+j];
                            snprintf(buf, 5, "%02X ", b);
                            hex_part += buf;
                            ascii_part += (b >= 32 && b <= 126) ? (char)b : '.';
                        } else { hex_part += "   "; }
                    }
                    rows.push_back(hbox({ text(hex_part) | color(Color::GrayLight), text(" " + ascii_part) | color(Color::Yellow) }));
                }
                content_view = vbox({
                    text("Controls: Arrow Keys (Scroll)") | center | dim,
                    separator(),
                    create_panel("Hex View", vbox(std::move(rows)))
                });
            }
        }
        else if (tab_selected == 3) {
             content_view = vbox({
                 btn_decompile->Render(),
                 separator(),
                 create_panel("Pseudocode Generator", paragraph(cached_decompilation))
             });
        }
        else if (tab_selected == 4) {
             std::string report = "Ready to scan.";
             if (!cached_vuln_scan.empty()) report = cached_vuln_scan.dump(2);
             content_view = vbox({
                 btn_audit->Render(),
                 separator(),
                 create_panel("Vulnerability Report", paragraph(report))
             });
        }
        else if (tab_selected == 5) {
            auto reg_box = [&](std::string name, uint64_t val) {
                return vbox({
                    text(name) | bold | center | color(Color::RedLight),
                    separator(),
                    text(fmt_addr(val)) | center | color(Color::White)
                }) | border | flex;
            };
            content_view = vbox({
                hbox({ input_pid->Render(), btn_attach->Render(), btn_detach->Render() }),
                separator(),
                create_panel("CPU Registers", 
                    vbox({
                        hbox({ reg_box("RIP", current_regs.rip), reg_box("RAX", current_regs.rax), reg_box("RBX", current_regs.rbx) }),
                        hbox({ reg_box("RCX", current_regs.rcx), reg_box("RDX", current_regs.rdx), reg_box("RSP", current_regs.rsp) }),
                        hbox({ reg_box("RBP", current_regs.rbp), reg_box("RSI", current_regs.rsi), reg_box("RDI", current_regs.rdi) })
                    })
                )
            });
        }
        else {
            content_view = vbox({
                text(""),
                text(" Confirm Exit ") | bold | bgcolor(Color::Red) | center,
                text(""),
                text("Press ENTER to quit application.") | center,
                text("")
            }) | center;
        }
        return vbox({
            title_bar,
            hbox({
                text(" SOURCE ") | bold | center,
                input_path->Render() | flex,
                btn_load->Render()
            }) | border,
            hbox({
                vbox({
                    text(" TOOLKIT ") | center | bold | color(Color::Magenta),
                    separator(),
                    menu->Render()
                }) | border | size(WIDTH, EQUAL, 25), 
                content_view | flex | border
            }) | flex
        });
    });
    auto screen = ScreenInteractive::Fullscreen();
    auto component = CatchEvent(renderer, [&](Event event) {
        if (tab_selected == 6 && event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        if (tab_selected == 2) { 
            if (event == Event::ArrowDown) { hex_offset += 8; return true; }
            if (event == Event::ArrowUp && hex_offset >= 8) { hex_offset -= 8; return true; }
            if (event == Event::PageDown) { hex_offset += 128; return true; }
            if (event == Event::PageUp && hex_offset >= 128) { hex_offset -= 128; return true; }
        }
        return false;
    });
    std::thread refresher([&] {
        while(true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            if (engine.is_tracing()) screen.Post(Event::Custom);
        }
    });
    refresher.detach();
    screen.Loop(component);
}