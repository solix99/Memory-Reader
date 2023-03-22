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
    SIZE_T bytesRead, vals{ 0 };

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

    int targetValue = 123451245;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPVOID baseAddress = nullptr;
    LPVOID maxAddress = nullptr;

    while (baseAddress < sysInfo.lpMaximumApplicationAddress)
    {
        // Query the memory region
        if (VirtualQueryEx(processHandle, baseAddress, &mbi, sizeof(mbi)) == 0)
        {
            std::cerr<<endl << "VirtualQueryEx failed with error code " << GetLastError() << std::endl;
            break;
        }

        // Check if the memory region is accessible
        if (mbi.Protect == PAGE_NOACCESS)
        {
            SIZE_T regionSize = mbi.RegionSize;
            LPVOID regionAddress = VirtualAlloc(nullptr, regionSize, MEM_COMMIT, PAGE_READWRITE);
            if (!regionAddress)
            {
                std::cerr << endl << "VirtualAlloc failed with error code " << GetLastError() << std::endl;
                break;
            }

            char* buffer = new char[mbi.RegionSize];
            if (ReadProcessMemory(processHandle, baseAddress, buffer, mbi.RegionSize, &bytesRead) == 0)
            {
                std::cerr << "ReadProcessMemory failed with error code " << GetLastError() << std::endl;
                delete[] buffer;

                // Move to the next memory region
                baseAddress = static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            // Update mbi to point to the newly allocated memory
            mbi.BaseAddress = regionAddress;
            mbi.Protect = PAGE_READWRITE;
            mbi.RegionSize = regionSize;
        }

        // Read the memory region
        char* buffer = nullptr;
        SIZE_T bufferSize = 0;
        if (mbi.RegionSize > 1024 * 1024)
        {
            // Allocate a buffer for large memory regions
            bufferSize = 1024 * 1024;
        }
        else
        {
            bufferSize = mbi.RegionSize;
        }
        buffer = new char[bufferSize];


        if (ReadProcessMemory(processHandle, baseAddress, buffer, mbi.RegionSize, &bytesRead) == 0)
        {
            std::cerr << endl << "ReadProcessMemory failed with error code " << GetLastError() << std::endl;
            delete[] buffer;
            break;
        }
        // Scan for integers in the memory region
        for (size_t i = 0; i < mbi.RegionSize; i += sizeof(int))
        {
            int* intValue = reinterpret_cast<int*>(&buffer[i]);
            if (*intValue == targetValue)
            {
                std::cout << endl << "Found target value at address " << baseAddress << std::endl;

            }
            //cout << endl << *intValue;
            ++vals;
        }
        // Free the allocated memory, if necessary
        if (mbi.Protect == PAGE_READWRITE)
        {
            VirtualFree(mbi.BaseAddress, 0, MEM_RELEASE);
        }

        delete[] buffer;
        baseAddress = static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    cout << endl << vals;
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

