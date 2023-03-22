#include <Windows.h>
#include <iostream>
#include <string>
#include <string_view>
#include <psapi.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <chrono>
#include <thread>
#include <bitset>
#include <winsock.h>
#include <TlHelp32.h>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;
using namespace std::this_thread; // sleep_for, sleep_until
using namespace std::chrono; // nanoseconds, system_clock, seconds

size_t READ_TYPE;

enum READ_TYPE {
    BYTES,INTEGER
}RT;


bool IsUserAdmin()
{
    HANDLE tokenHandle;
    DWORD bufferSize = 0;
    PTOKEN_GROUPS groupInfo = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroupSid = nullptr;
    BOOL isMember = FALSE;

    // Open a handle to the access token of the current process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        std::cerr << "Failed to open process token" << std::endl;
        return false;
    }

    // Get the size of the token's group information
    if (!GetTokenInformation(tokenHandle, TokenGroups, nullptr, 0, &bufferSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        std::cerr << "Failed to query token information" << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    // Allocate memory for the token's group information
    groupInfo = (PTOKEN_GROUPS)LocalAlloc(LPTR, bufferSize);
    if (!groupInfo)
    {
        std::cerr << "Failed to allocate memory for token groups" << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    // Get the token's group information
    if (!GetTokenInformation(tokenHandle, TokenGroups, groupInfo, bufferSize, &bufferSize))
    {
        std::cerr << "Failed to query token information" << std::endl;
        CloseHandle(tokenHandle);
        LocalFree(groupInfo);
        return false;
    }

    // Create a SID for the Administrators group
    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroupSid))
    {
        std::cerr << "Failed to create SID for Administrators group" << std::endl;
        CloseHandle(tokenHandle);
        LocalFree(groupInfo);
        return false;
    }

    // Check if the user belongs to the Administrators group
    for (DWORD i = 0; i < groupInfo->GroupCount; ++i)
    {
        if (EqualSid(adminGroupSid, groupInfo->Groups[i].Sid))
        {
            isMember = TRUE;
            break;
        }
    }

    // Clean up
    FreeSid(adminGroupSid);
    CloseHandle(tokenHandle);
    LocalFree(groupInfo);

    return isMember;
}


int processSnapShot()
{
    // Create a snapshot of the system processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create process snapshot!" << std::endl;
        return 1;
    }

    // Enumerate the processes and print their names and IDs
    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(pe32);

    if (!Process32First(hSnapshot, &pe32))
    {
        std::cerr << "Failed to get first process!" << std::endl;
        CloseHandle(hSnapshot);
        return 1;
    }

    do {
        std::wstring wstr(pe32.szExeFile);
        std::string str(wstr.begin(), wstr.end());
        std::cout << "Process Name: " << str << std::endl;
        std::cout << "Process ID: " << pe32.th32ProcessID << std::endl;
        std::cout << std::endl;
    } while (Process32Next(hSnapshot, &pe32));

    // Close the process snapshot handle
    CloseHandle(hSnapshot);

    return 0;
   
}

void readProcessMemory(HANDLE processHandle)
{

    // Define the memory range to read
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    SIZE_T vals{ 0 };

    PROCESS_MEMORY_COUNTERS_EX pmc_ex;
    PROCESS_MEMORY_COUNTERS pmc;

    // initialize the structure
    ZeroMemory(&pmc, sizeof(PROCESS_MEMORY_COUNTERS));
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);

    ZeroMemory(&pmc_ex, sizeof(PROCESS_MEMORY_COUNTERS_EX));
    pmc_ex.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX);

    if (!GetProcessMemoryInfo(processHandle, (PROCESS_MEMORY_COUNTERS*)&pmc_ex, sizeof(pmc_ex)))
    {
        std::cerr << endl << "Failed to get process memory information. Error code: " << GetLastError() << std::endl;
        return;
    }
    SIZE_T virtualMemUsedByProcess = pmc_ex.PrivateUsage;
    double memUsageInMB = static_cast<double>(virtualMemUsedByProcess) / (1024 * 1024);
    std::cout << endl << "Process Memory Usage: " << memUsageInMB << " MB" << std::endl;

    int targetValue = 98679567;
    int totalMemoryRead{ 0 };

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPVOID baseAddress = nullptr;
    LPVOID maxAddress = nullptr;
    LPVOID currentAddress = sysInfo.lpMinimumApplicationAddress;

    SIZE_T bytesRead = 0;
    SIZE_T bytesReturned{ 0 };

    while (currentAddress < sysInfo.lpMaximumApplicationAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        bytesReturned = VirtualQuery(currentAddress, &mbi, sizeof(mbi));
        if (bytesReturned == 0)
        {
            // Failed to query memory information
            std::cerr << "VirtualQuery failed with error code " << GetLastError() << std::endl;
            break;
        }

        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS)
        {
            // This memory region is committed and accessible, so we can read it
            char* buffer = new char[mbi.RegionSize];

            if (ReadProcessMemory(GetCurrentProcess(), currentAddress, buffer, mbi.RegionSize, &bytesRead) == 0)
            {
                // Failed to read process memory
                std::cerr << "ReadProcessMemory failed with error code " << GetLastError() << std::endl;
                delete[] buffer;
                break;
            }

            totalMemoryRead += bytesRead;

            // Scan for integers in the memory region
            for (size_t i = 0; i < bytesRead; i += sizeof(int))
            {
                int* intValue = reinterpret_cast<int*>(&buffer[i]);
                if (*intValue == targetValue)
                {
                    std::cout << "Found target value at address " << currentAddress << std::endl;
                }
                vals++;
            }

            // Free the buffer memory
            delete[] buffer;
        }

        // Move to the next memory region
        currentAddress = static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    cout << endl <<"Values:" << vals << " SIZE:" << totalMemoryRead/(pow(1024,2));
}

int main()
{

    if (!IsUserAdmin())
    {
        cout << endl << "No admin privilages";
        return 1;
    }

    processSnapShot();

    HANDLE processHandle;
    DWORD processId, bytesRead;

    //cout << endl << "0=Binary Search";
    cout << endl << "Integer Search";
    cout << endl << "Input process id:";

    cin >> processId;

    // Open a handle to the process
    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    cout << endl << processHandle << endl << processId;

    readProcessMemory(processHandle);

    // Close the process handle
    CloseHandle(processHandle);

    return 0;
}

