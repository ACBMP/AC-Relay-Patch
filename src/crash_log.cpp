#include "crash_log.h"
#include "logger.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace ac_relay::crash_log
{
    namespace
    {
        constexpr std::uintptr_t kGhidraImageBase = 0x00400000; // ACBMP.exe as Ghidra shows it
        constexpr int kMaxReports = 8;
        constexpr int kStackScanDwords = 512;
        constexpr int kMaxStackHits = 24;

        std::atomic<int> s_reports{0};
        PVOID s_handler = nullptr;
        std::uintptr_t s_exe_base = 0;

        // [base, base + SizeOfImage) of the module containing addr, or false
        bool module_of(std::uintptr_t addr, std::uintptr_t& base, std::uintptr_t& size, char* name, std::size_t name_len)
        {
            HMODULE mod = nullptr;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCSTR>(addr), &mod) ||
                !mod)
                return false;
            base = reinterpret_cast<std::uintptr_t>(mod);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            size = nt->OptionalHeader.SizeOfImage;
            char path[MAX_PATH] = {};
            GetModuleFileNameA(mod, path, MAX_PATH);
            const char* slash = std::strrchr(path, '\\');
            std::snprintf(name, name_len, "%s", slash ? slash + 1 : path);
            return true;
        }

        std::string describe(std::uintptr_t addr)
        {
            char name[MAX_PATH] = {};
            std::uintptr_t base = 0, size = 0;
            char out[MAX_PATH + 96];
            if (!module_of(addr, base, size, name, sizeof(name)))
            {
                std::snprintf(out, sizeof(out), "0x%08zx (no module)", static_cast<std::size_t>(addr));
                return out;
            }
            if (base == s_exe_base)
                std::snprintf(out, sizeof(out), "%s+0x%zx (Ghidra VA 0x%08zx)", name, static_cast<std::size_t>(addr - base),
                              static_cast<std::size_t>(addr - base + kGhidraImageBase));
            else
                std::snprintf(out, sizeof(out), "%s+0x%zx", name, static_cast<std::size_t>(addr - base));
            return out;
        }

        bool is_fatal(DWORD code)
        {
            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION:
            case EXCEPTION_STACK_OVERFLOW:
            case EXCEPTION_ILLEGAL_INSTRUCTION:
            case EXCEPTION_PRIV_INSTRUCTION:
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            case EXCEPTION_IN_PAGE_ERROR:
            case 0xC0000409: // STATUS_STACK_BUFFER_OVERRUN (also __fastfail)
            case 0xC0000374: // STATUS_HEAP_CORRUPTION
                return true;
            default:
                return false;
            }
        }

        // Return-address candidates: stack values pointing into executable
        // image memory (cheap, no unwinding; enough to see who called whom).
        // POD only: MSVC rejects __try next to objects with destructors (C2712).
        int collect_stack_seh(std::uintptr_t esp, std::uintptr_t* out, int* offsets, int max)
        {
            int hits = 0;
            __try
            {
                const auto* p = reinterpret_cast<const std::uintptr_t*>(esp);
                for (int i = 0; i < kStackScanDwords && hits < max; ++i)
                {
                    const std::uintptr_t v = p[i];
                    if (v < 0x10000)
                        continue;
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<LPCVOID>(v), &mbi, sizeof(mbi)) || mbi.Type != MEM_IMAGE ||
                        !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                        continue;
                    out[hits] = v;
                    offsets[hits] = i * 4;
                    ++hits;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            return hits;
        }

        std::string scan_stack(std::uintptr_t esp)
        {
            std::uintptr_t addrs[kMaxStackHits];
            int offsets[kMaxStackHits];
            const int n = collect_stack_seh(esp, addrs, offsets, kMaxStackHits);
            std::string out;
            for (int i = 0; i < n; ++i)
            {
                char line[MAX_PATH + 128];
                std::snprintf(line, sizeof(line), "\n    [esp+0x%03x] %s", offsets[i], describe(addrs[i]).c_str());
                out += line;
            }
            return out;
        }

        LONG CALLBACK on_exception(EXCEPTION_POINTERS* ep)
        {
            if (!ep || !ep->ExceptionRecord || !is_fatal(ep->ExceptionRecord->ExceptionCode))
                return EXCEPTION_CONTINUE_SEARCH;
            if (s_reports.fetch_add(1) >= kMaxReports)
                return EXCEPTION_CONTINUE_SEARCH;

            const EXCEPTION_RECORD* er = ep->ExceptionRecord;
            const CONTEXT* c = ep->ContextRecord;
            const auto at = reinterpret_cast<std::uintptr_t>(er->ExceptionAddress);

            char head[512];
            std::snprintf(head, sizeof(head), "EXCEPTION 0x%08lx at %s (thread %lu)",
                          static_cast<unsigned long>(er->ExceptionCode), describe(at).c_str(),
                          static_cast<unsigned long>(GetCurrentThreadId()));
            std::string msg = head;
            if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
            {
                const auto kind = er->ExceptionInformation[0];
                std::snprintf(head, sizeof(head), ": %s 0x%08zx",
                              kind == 0 ? "read of" : kind == 1 ? "write to" : kind == 8 ? "execute at" : "access to",
                              static_cast<std::size_t>(er->ExceptionInformation[1]));
                msg += head;
            }
            if (c)
            {
                std::snprintf(head, sizeof(head),
                              "\n    eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx ebp=%08lx esp=%08lx",
                              c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->Esp);
                msg += head;
                msg += "\n  code addresses on the stack:";
                msg += scan_stack(c->Esp);
            }
            msg += "\n  (first-chance: the game or the patch may still handle it; a crash right after means it didn't)";
            logger::error(msg);
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    auto install() -> void
    {
        if (s_handler)
            return;
        s_exe_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        // first in line, so it still sees the exception if the game's own
        // filter or a debugger-less crash path never returns to us
        s_handler = AddVectoredExceptionHandler(1, on_exception);
        logger::info(s_handler ? "crash logging installed" : "crash logging could not be installed");
    }
}
