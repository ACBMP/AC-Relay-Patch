#include "crash_log.h"
#include "logger.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <intrin.h>
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

        // ---- silent exits -------------------------------------------------
        // The game's CRT (VS2008, static) ends a /GS cookie failure, an invalid
        // CRT parameter and abort() by calling kernel32!UnhandledExceptionFilter
        // directly (no exception is raised, so the vectored handler never sees
        // it), and a pure virtual call by _amsg_exit -> ExitProcess. The game's
        // own minidump filter is unset first on those paths. Hooking ACBMP.exe's
        // imports for these makes every such death show up in the log.

        using UefFn = LONG(WINAPI*)(EXCEPTION_POINTERS*);
        using SetUefFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
        using ExitProcessFn = void(WINAPI*)(UINT);
        using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);

        UefFn s_uef_original = nullptr;
        SetUefFn s_set_uef_original = nullptr;
        ExitProcessFn s_exit_process_original = nullptr;
        TerminateProcessFn s_terminate_process_original = nullptr;
        LPTOP_LEVEL_EXCEPTION_FILTER s_game_filter = nullptr;
        std::atomic<bool> s_exit_logged{false};

        const char* exit_reason(DWORD code)
        {
            switch (code)
            {
            case 0xC0000409:
                return "/GS stack cookie overrun (stack buffer overflow)";
            case 0xC0000417:
                return "invalid CRT parameter (e.g. strcpy_s overflow)";
            case 0x40000015:
                return "abort() (unhandled C++ exception, terminate, ...)";
            case 0xE06D7363:
                return "unhandled C++ exception";
            case EXCEPTION_ACCESS_VIOLATION:
                return "access violation";
            default:
                return "see code";
            }
        }

        void log_exit(const char* what, std::uintptr_t caller, std::uintptr_t esp, const EXCEPTION_POINTERS* ep)
        {
            if (s_reports.fetch_add(1) >= kMaxReports)
                return;
            char head[512];
            std::string msg;
            if (ep && ep->ExceptionRecord)
            {
                const DWORD code = ep->ExceptionRecord->ExceptionCode;
                std::snprintf(head, sizeof(head), "PROCESS DYING: %s, code 0x%08lx = %s, at %s (thread %lu)", what,
                              static_cast<unsigned long>(code), exit_reason(code),
                              describe(reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress)).c_str(),
                              static_cast<unsigned long>(GetCurrentThreadId()));
                msg = head;
                if (ep->ContextRecord && ep->ContextRecord->Esp)
                    esp = ep->ContextRecord->Esp;
            }
            else
            {
                std::snprintf(head, sizeof(head), "PROCESS EXITING: %s (thread %lu)", what,
                              static_cast<unsigned long>(GetCurrentThreadId()));
                msg = head;
            }
            msg += "\n  called from " + describe(caller);
            msg += "\n  code addresses on the stack:";
            msg += scan_stack(esp);
            logger::error(msg);
        }

        LONG WINAPI hk_unhandled_exception_filter(EXCEPTION_POINTERS* ep)
        {
            log_exit("UnhandledExceptionFilter", reinterpret_cast<std::uintptr_t>(_ReturnAddress()),
                     reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()), ep);
            return s_uef_original(ep);
        }

        // Wraps the game's own top-level filter (its minidump writer): this is
        // where a normal unhandled exception of any code ends up.
        LONG WINAPI our_top_level_filter(EXCEPTION_POINTERS* ep)
        {
            log_exit("unhandled exception", ep && ep->ExceptionRecord
                                                ? reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress)
                                                : 0,
                     reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()), ep);
            return s_game_filter ? s_game_filter(ep) : EXCEPTION_CONTINUE_SEARCH;
        }

        LPTOP_LEVEL_EXCEPTION_FILTER WINAPI hk_set_unhandled_exception_filter(LPTOP_LEVEL_EXCEPTION_FILTER filter)
        {
            // NULL is what abort/gsfailure/watson pass before reporting: keep
            // that, those paths are covered by hk_unhandled_exception_filter.
            if (!filter)
                return s_set_uef_original(nullptr);
            const LPTOP_LEVEL_EXCEPTION_FILTER previous = s_game_filter;
            s_game_filter = filter;
            s_set_uef_original(our_top_level_filter);
            return previous;
        }

        void WINAPI hk_exit_process(UINT code)
        {
            if (!s_exit_logged.exchange(true))
            {
                char what[64];
                std::snprintf(what, sizeof(what), "ExitProcess(%u)%s", code,
                              code == 255 ? " -- 255 = CRT runtime error, e.g. pure virtual call" : "");
                log_exit(what, reinterpret_cast<std::uintptr_t>(_ReturnAddress()),
                         reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()), nullptr);
            }
            s_exit_process_original(code);
        }

        BOOL WINAPI hk_terminate_process(HANDLE process, UINT code)
        {
            if ((process == GetCurrentProcess() || GetProcessId(process) == GetCurrentProcessId()) &&
                !s_exit_logged.exchange(true))
            {
                char what[64];
                std::snprintf(what, sizeof(what), "TerminateProcess(self, 0x%x)", code);
                log_exit(what, reinterpret_cast<std::uintptr_t>(_ReturnAddress()),
                         reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()), nullptr);
            }
            return s_terminate_process_original(process, code);
        }

        // Points ACBMP.exe's import of kernel32!name at hook; returns the old target.
        void* patch_import(const char* name, void* hook)
        {
            const auto base = s_exe_base;
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!dir.VirtualAddress)
                return nullptr;
            for (auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); imp->Name; ++imp)
            {
                if (_stricmp(reinterpret_cast<const char*>(base + imp->Name), "kernel32.dll") != 0 ||
                    !imp->OriginalFirstThunk)
                    continue;
                auto* names = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + imp->OriginalFirstThunk);
                auto* slots = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
                for (; names->u1.AddressOfData; ++names, ++slots)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal))
                        continue;
                    const auto* by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
                    if (std::strcmp(reinterpret_cast<const char*>(by_name->Name), name) != 0)
                        continue;
                    DWORD old = 0;
                    if (!VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), PAGE_READWRITE, &old))
                        return nullptr;
                    void* previous = reinterpret_cast<void*>(slots->u1.Function);
                    slots->u1.Function = reinterpret_cast<std::uintptr_t>(hook);
                    VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), old, &old);
                    return previous;
                }
            }
            return nullptr;
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

        // Set the originals before the import slots point at the hooks.
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        s_uef_original = reinterpret_cast<UefFn>(GetProcAddress(k32, "UnhandledExceptionFilter"));
        s_set_uef_original = reinterpret_cast<SetUefFn>(GetProcAddress(k32, "SetUnhandledExceptionFilter"));
        s_exit_process_original = reinterpret_cast<ExitProcessFn>(GetProcAddress(k32, "ExitProcess"));
        s_terminate_process_original = reinterpret_cast<TerminateProcessFn>(GetProcAddress(k32, "TerminateProcess"));
        int patched = 0;
        if (s_uef_original && patch_import("UnhandledExceptionFilter", reinterpret_cast<void*>(hk_unhandled_exception_filter)))
            ++patched;
        if (s_set_uef_original &&
            patch_import("SetUnhandledExceptionFilter", reinterpret_cast<void*>(hk_set_unhandled_exception_filter)))
            ++patched;
        if (s_exit_process_original && patch_import("ExitProcess", reinterpret_cast<void*>(hk_exit_process)))
            ++patched;
        if (s_terminate_process_original &&
            patch_import("TerminateProcess", reinterpret_cast<void*>(hk_terminate_process)))
            ++patched;

        logger::info(s_handler ? std::format("crash logging installed (exit paths hooked: {}/4)", patched)
                               : std::string("crash logging could not be installed"));
    }
}
