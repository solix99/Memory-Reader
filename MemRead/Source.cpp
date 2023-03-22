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

#pragma comment(lib, "Ws2_32.lib")

using namespace std;
using namespace std::this_thread; // sleep_for, sleep_until
using namespace std::chrono; // nanoseconds, system_clock, seconds

size_t READ_TYPE;

enum READ_TYPE {
    BYTES,INTEGER
}RT;


ostream& operator <<(ostream& out,string_view str)
{
    return out;
}


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

            // Copy the inaccessible region to the newly allocated memory
            if (!ReadProcessMemory(processHandle, baseAddress, regionAddress, regionSize, &bytesRead))
            {
                std::cerr << endl << "ReadProcessMemory failed with error code " << GetLastError() << std::endl;
                VirtualFree(regionAddress, 0, MEM_RELEASE);
                break;
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



        /*

        LPVOID baseAddress = sysInfo.lpMinimumApplicationAddress;
        LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;
        while (baseAddress < maxAddress)
        {
            MEMORY_BASIC_INFORMATION memInfo;
            if (VirtualQueryEx(processHandle, baseAddress, &memInfo, sizeof(memInfo)) == 0)
            {
                std::cerr << "Failed to query memory information. Error code: " << GetLastError() << std::endl;
                // Failed to query the memory information, so break the loop
                break;
            }

            // Only read memory blocks that are readable and not guard pages
            if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_GUARD) == 0 && (memInfo.Protect & PAGE_NOACCESS) == 0)
            {
                //Read in bytes
                if (READ_TYPE == BYTES)
                {

                }
                //Read in integer
                if (READ_TYPE == INTEGER)
                {
                    // Check if the memory block is aligned to the size of an integer
                    if (reinterpret_cast<uintptr_t>(memInfo.BaseAddress) % sizeof(int) != 0)
                    {
                        // Move to the next memory block
                        baseAddress = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(memInfo.BaseAddress) + memInfo.RegionSize);
                        continue;
                    }

                    LPVOID buffer = VirtualAlloc(NULL, memInfo.RegionSize, MEM_COMMIT, PAGE_READWRITE);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(processHandle, baseAddress, buffer, memInfo.RegionSize, &bytesRead) == 0)
                    {
                        // Failed to read the memory block, so free the buffer and break the loop
                        std::cerr << "Failed to read memory. Error code: " << GetLastError() << std::endl;
                        VirtualFree(buffer, 0, MEM_RELEASE);
                        break;
                    }

                    // Search for integer values in the memory block
                    int* ptr = reinterpret_cast<int*>(buffer);
                    for (int i = 0; i < (bytesRead / sizeof(int)); ++i, ++ptr)
                    {
                        int value = *ptr;
                        if (value == 123451245)
                        {
                            cout << endl << "Found";
                        }
                        vals++;
                    }

                    // Free the buffer
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
            }

            // Move to the next memory block
            baseAddress = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(baseAddress) + memInfo.RegionSize);
            baseAddress = (LPBYTE)baseAddress + pmc.PageFaultCount;
        }
        cout << endl << "Values Read:" << vals;
        */
int main()
{

    if (!IsUserAdmin())
    {
        cout << endl << "No admin privilages";
        return 1;
    }

    cout << endl << "0=Binary Search";
    cout << endl << "1=Integer Search";

    HWND targetWindow;
    HANDLE processHandle;
    HWND windowHandle;
    DWORD processId, bytesRead;
    char buffer[256];

    // Find the window by enumerating all windows
    targetWindow = NULL;
    EnumWindows([](HWND hWnd, LPARAM lParam) -> BOOL 
        {
        HWND* pTargetWindow = reinterpret_cast<HWND*>(lParam);
        wchar_t title[256];
        if (GetWindowTextW(hWnd, title, 256) > 0) 
        {
            if (wcsstr(title, L"test1") != nullptr) 
            {
                *pTargetWindow = hWnd;
                return FALSE;
            }
        }
        return TRUE;
        }, reinterpret_cast<LPARAM>(&targetWindow));

    if (targetWindow == NULL) 
    {
        std::cerr << "Could not find target window" << std::endl;
        return 1;
    }

    cin >> READ_TYPE;


    // Get the process ID of the target program
    GetWindowThreadProcessId(targetWindow, &processId);

    // Open a handle to the process
    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    cout << endl << processHandle << endl << processId;

    readProcessMemory(processHandle);

    // Close the process handle
    CloseHandle(processHandle);

    return 0;
}

