#include <windows.h>
#include <Iphlpapi.h>
#include <stdio.h>
#include <TlHelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

void NetworkTest();
void FilesystemTest();
void ProcessListTest();
CHAR *GatewayIp();
void ConnectTest(CHAR *ip, SHORT port);
void CreateFileTest(CHAR *file_path);


void RunContainerTests()
{
    printf("We are running in an app container\n\n");

    FilesystemTest();
    NetworkTest();
    ProcessListTest();
}

void NetworkTest()
{
    printf("[+] Running network test...\n");

    CHAR external_ip[] = "74.125.227.200"; //Google
    CHAR *network_ip = GatewayIp(); //Default Gateway

    //Connections to external IPs should be blocked
    ConnectTest(external_ip, 80);

    //Connections to network IPs should be allowed (except for public networks)
    ConnectTest(network_ip, 80);;

    printf("[+] Network testing done\n\n");
}

void FilesystemTest()
{
    printf("[+] Running filesystem test...\n");

    CHAR path[MAX_PATH];
    CHAR test1_path[MAX_PATH];
    CHAR test2_path[MAX_PATH];
    CHAR test3_path[MAX_PATH];

    ExpandEnvironmentStringsA("%temp%", path, MAX_PATH-1);
    printf("New path of %%temp%%: %s\n", path);

    ExpandEnvironmentStringsA("%localappdata%", path, MAX_PATH-1);
    printf("New path of %%localappdata%%: %s\n", path);

    ExpandEnvironmentStringsA("%temp%\\allowed_test.txt", test1_path, MAX_PATH-1);
    ExpandEnvironmentStringsA("%userprofile%\\desktop\\allowed_test.txt", test2_path, MAX_PATH-1);
    ExpandEnvironmentStringsA("%userprofile%\\desktop\\blocked_test.txt", test3_path, MAX_PATH-1);

    //Writes allowed_test.txt to the application's %temp% directory (should be allowed by default)
    CreateFileTest(test1_path);

    //Writes allowed_test.txt to the desktop directory (should be allowed because we explicitly gave access)
    CreateFileTest(test2_path);

    //Writes blocked_test.txt to the desktop directory (should be blocked by default)
    CreateFileTest(test3_path);

    printf("[+] Filesystem testing done\n\n");
}

/*
    Should only list the System pseudo-process, conhost (the application's console host process), and the application
*/
void ProcessListTest()
{
    printf("[+] Running process list testing...\n");
    tagPROCESSENTRY32W process_entry;
    HANDLE snapshot;

    process_entry.dwSize = sizeof(process_entry);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot)
    {
        if(Process32First(snapshot, &process_entry))
        {
            do 
            {
                printf("Found process: %ws\n", process_entry.szExeFile);
            } while (Process32Next(snapshot, &process_entry));
        }
        CloseHandle(snapshot);
    }else{
        printf("Failed to get process list\n");
    }

     printf("[+] Process list testing done\n\n");
}

CHAR *GatewayIp()
{
    static CHAR ip[16];
    PVOID memory_buffer;
    PIP_ADAPTER_INFO adapter_info = NULL;
    DWORD buffer_size = 0;
    CHAR *return_buffer = NULL;

    GetAdaptersInfo(adapter_info, &buffer_size);

    memory_buffer = malloc(buffer_size);
    adapter_info = (PIP_ADAPTER_INFO)memory_buffer;

    if(GetAdaptersInfo(adapter_info, &buffer_size) == ERROR_SUCCESS)
    {
        while(adapter_info)
        {
            if(strcmp(adapter_info->GatewayList.IpAddress.String, "0.0.0.0"))
            {
                memcpy(ip, &adapter_info->GatewayList.IpAddress.String, 16);
                return_buffer = ip;
                break;
            }
            adapter_info = adapter_info->Next;
        }
    }

    free(memory_buffer);
    return return_buffer;
}

void ConnectTest(CHAR *ip, SHORT port)
{
    WSADATA wsadata;
    SOCKET sock;
    sockaddr_in addr;

    WSAStartup(MAKEWORD(2, 2), &wsadata);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock != INVALID_SOCKET) 
    {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(ip);
        addr.sin_port = htons(port);

        if(connect(sock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) 
        {
            if(WSAGetLastError() == WSAEACCES)
            {
                printf("Connection to %s was blocked\n", ip);
            }else{
                printf("Connection to %s was unsuccessful but not blocked\n", ip);
            }
        }else{
            printf("Connection to %s was successful\n", ip);
            closesocket(sock);
        }
    }else{
        printf("Failed to create socket, error code: %d\n", WSAGetLastError());
    }

    WSACleanup();
    return;
}

void CreateFileTest(CHAR *file_path)
{
    HANDLE file_handle;

    file_handle = CreateFileA(file_path, GENERIC_ALL, 0, NULL, OPEN_ALWAYS, NULL, NULL);
    if(file_handle != INVALID_HANDLE_VALUE)
    {
        printf("Opening of file %s was successful\n", file_path);
        CloseHandle(file_handle);
        DeleteFileA(file_path);
    }else{
        if(GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Opening of file %s returned access denied\n", file_path);
        }else{
            printf("Opening of file %s failed but was not blocked\n", file_path);
        }
    }
}