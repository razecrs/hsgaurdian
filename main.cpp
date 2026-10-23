#include <windows.h>
#include <cstring>
#include <TlHelp32.h>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <print>
#include <memory>
#define WIN_LEAN_AND_MEAN


// A RAII handle wrapper  to prove handle leaks across our project
struct HandleDeleter {
    void operator()(HANDLE h) const noexcept{
        if(h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};

using ScopedHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

struct Process{
    DWORD id;
    std::wstring name;
};
class ProcessScanner{
    public:
        [[nodiscard]] static std::vector<Process> list_all(){
            std::vector<Process> processes;
            ScopedHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};

        if(!snapshot || snapshot.get() == INVALID_HANDLE_VALUE) return processes;
        PROCESSENTRY32W entry{ .dwSize = sizeof(PROCESSENTRY32W) };

        if(Process32FirstW(snapshot.get(), &entry)){
            do{
                processes.emplace_back(entry.th32ProcessID, entry.szExeFile);
            }while(Process32NextW(snapshot.get(), &entry));
        }
        return processes;
        }
    [[nodiscard]] static std::optional<Process> find_by_name(std::wstring_view target_name){
        ScopedHandle snapshot{ CreateToolhelp32Snapshot(TH3CS_SNAPPROCESS, 0)};

        if(!snapshot || snapshot.get() == INVALID_HANDLE_VALUE) return std::nullopt;
        PROCESSENTRY32W entry{ .dwSize = sizeof(PROCESSENTRY32W) };

        if(Process32FirstW(snapshot.get(), &entry)){
            do{
                if(target_name == entry.szExeFile){
                    return Process{entry.th32ProcessID, entry.szExeFile};
                }
            }while(Process32NextW(snapshot.get(), &entry));
        }
        return std::nullopt;
        }

    };
}
int main()
{
    constexpr std::wstring_view target  = L"HillClimbRacing.exe"; // we are hardcoding cause we are using this app for testing

    if(auto proc = ProcessScanner::find_by_name(target)){
        std::println("Found the nigga  -> Pid: {} | Name: {}", proc-id, target);
    }else {
        std::println(stderr, "Didnt find the process bro");
    }
    std::println("==========raze=======apollo========eyad======hsr=======");
    auto all_niggas = ProcessScanner::list_all();
    std::println("Listing FIRST 5 nigga processes out of {} total niggas: ", all_niggas.size()); // oh my fucking god cpp is ugly
    for(size_t i = 0; i < std::min<size_t>(5, all_niggas.size()); ++i){
        std::println("NIGGA_HOUSE:{:<6}| Nigga: {}", all_niggas[i].id, all_niggas[i].name.c_str());
    }
    return all_niggas;
}
