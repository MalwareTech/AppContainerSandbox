#include <windows.h>
#include <strsafe.h>
#include <Sddl.h>
#include <Userenv.h>
#include <AccCtrl.h>
#include <Aclapi.h>

#pragma comment(lib, "Userenv.lib")

//List of allowed capabilities for the application
extern WELL_KNOWN_SID_TYPE app_capabilities[] =
{
    WinCapabilityPrivateNetworkClientServerSid,
};

WCHAR container_name[] = L"MtSandboxTest";
WCHAR container_desc[] = L"MalwareTech Sandbox Test";

BOOL IsInAppContainer();
BOOL SetSecurityCapabilities(PSID container_sid, SECURITY_CAPABILITIES *capabilities, PDWORD num_capabilities);
BOOL GrantNamedObjectAccess(PSID appcontainer_sid, CHAR *object_name, SE_OBJECT_TYPE object_type, DWORD access_mask);

/*
    Create a container with container_name and run the specified application inside it
*/
BOOL RunExecutableInContainer(CHAR *executable_path)
{
    PSID sid = NULL;
    HRESULT result;
    SECURITY_CAPABILITIES SecurityCapabilities = {0};
    DWORD num_capabilities = 0, attribute_size = 0;;
    STARTUPINFOEXA startup_info = {0};
    PROCESS_INFORMATION process_info = {0};
    CHAR desktop_file[MAX_PATH];
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    CHAR *string_sid = NULL;
    BOOL success = FALSE;

    do //Not a loop
    { 
        result = CreateAppContainerProfile(container_name, container_name, container_desc, NULL, 0, &sid);
        if(!SUCCEEDED(result))
        {
            if(HRESULT_CODE(result) == ERROR_ALREADY_EXISTS)
            {
                result = DeriveAppContainerSidFromAppContainerName(container_name, &sid);
                if(!SUCCEEDED(result))
                {
                    printf("Failed to get existing AppContainer name, error code: %d", HRESULT_CODE(result));
                    break;
                }
            }else{
                printf("Failed to create AppContainer, last error: %d\n", HRESULT_CODE(result));
                break;
            }   
        }

        printf("[Container Info]\nname: %ws\ndescription: %ws\n", container_name, container_desc);

        if(ConvertSidToStringSidA(sid, &string_sid))
            printf("Sid: %s\n\n", string_sid);

        if(!SetSecurityCapabilities(sid, &SecurityCapabilities, &num_capabilities))
        {
            printf("Failed to set security capabilities, last error: %d\n", GetLastError());
            break;
        }

        ExpandEnvironmentStringsA("%userprofile%\\desktop\\allowed_test.txt", desktop_file, MAX_PATH-1);

        file_handle = CreateFileA(desktop_file, GENERIC_ALL, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
        if(file_handle == INVALID_HANDLE_VALUE)
        {
            printf("Failed to create file %s, last error: %d\n", desktop_file);
            break;
        }
        
        if(!GrantNamedObjectAccess(sid, desktop_file, SE_FILE_OBJECT, FILE_ALL_ACCESS))
        {
            printf("Failed to grant explicit access to %s\n", desktop_file);
            break;
        }

        InitializeProcThreadAttributeList(NULL, 1, NULL, &attribute_size);
        startup_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_size);

        if(!InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, NULL, &attribute_size))
        {
            printf("InitializeProcThreadAttributeList() failed, last error: %d", GetLastError());
            break;
        }

        if(!UpdateProcThreadAttribute(startup_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                      &SecurityCapabilities, sizeof(SecurityCapabilities), NULL, NULL))
        {
            printf("UpdateProcThreadAttribute() failed, last error: %d", GetLastError());
            break;
        }

        if(!CreateProcessA(executable_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, 
                           (LPSTARTUPINFOA)&startup_info, &process_info))
        {
            printf("Failed to create process %s, last error: %d\n", executable_path, GetLastError());
            break;
        }

        printf("Successfully executed %s in AppContainer\n", executable_path);
        success = TRUE;

    } while (FALSE);

    if(startup_info.lpAttributeList)
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
 
    if(SecurityCapabilities.Capabilities)
        free(SecurityCapabilities.Capabilities);

    if(sid)
        FreeSid(sid);

    if(string_sid)
        LocalFree(string_sid);

    if(file_handle != INVALID_HANDLE_VALUE)
        CloseHandle(file_handle);

    if(file_handle != INVALID_HANDLE_VALUE && !success)
        DeleteFileA(desktop_file);

    return success;
}

/*
    Check if the current process is running inside an AppContainer
*/
BOOL IsInAppContainer()
{
    HANDLE process_token;
    BOOL is_container = 0; 
    DWORD return_length;

    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token);

    if (!GetTokenInformation(process_token, TokenIsAppContainer, &is_container, sizeof(is_container), &return_length)) 
        return false;

    return is_container;
}

/*
    Set the security capabilities of the container to those listed in app_capabilities
*/
BOOL SetSecurityCapabilities(PSID container_sid, SECURITY_CAPABILITIES *capabilities, PDWORD num_capabilities)
{
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    DWORD num_capabilities_ =  sizeof(app_capabilities) / sizeof(DWORD);
    SID_AND_ATTRIBUTES *attributes;
    BOOL success = TRUE;

    attributes = (SID_AND_ATTRIBUTES *)malloc(sizeof(SID_AND_ATTRIBUTES) * num_capabilities_);

    ZeroMemory(capabilities, sizeof(SECURITY_CAPABILITIES));
    ZeroMemory(attributes, sizeof(SID_AND_ATTRIBUTES) * num_capabilities_);

    for(unsigned int i = 0; i < num_capabilities_; i++)
    {
        attributes[i].Sid = malloc(SECURITY_MAX_SID_SIZE);
        if(!CreateWellKnownSid(app_capabilities[i], NULL, attributes[i].Sid, &sid_size))
        {
            success = FALSE;
            break;
        }
        attributes[i].Attributes = SE_GROUP_ENABLED;
    }

    if(success == FALSE)
    {
        for(unsigned int i = 0; i < num_capabilities_; i++)
        {
            if(attributes[i].Sid)
                LocalFree(attributes[i].Sid);
        }

        free(attributes);
        attributes = NULL;
        num_capabilities_ = 0;
    }

    capabilities->Capabilities = attributes;
    capabilities->CapabilityCount = num_capabilities_;
    capabilities->AppContainerSid = container_sid;
    *num_capabilities =  num_capabilities_;

    return success;
}

/*
    Explicitly grants the container access to a named object (file, section, etc)
*/
BOOL GrantNamedObjectAccess(PSID appcontainer_sid, CHAR *object_name, SE_OBJECT_TYPE object_type, DWORD access_mask)
{
    EXPLICIT_ACCESS_A explicit_access;
    PACL original_acl = NULL, new_acl = NULL;
    DWORD status;
    BOOL success = FALSE;

    do 
    {
        explicit_access.grfAccessMode = GRANT_ACCESS;
        explicit_access.grfAccessPermissions =  access_mask;
        explicit_access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

        explicit_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        explicit_access.Trustee.pMultipleTrustee = NULL;
        explicit_access.Trustee.ptstrName = (CHAR *)appcontainer_sid;
        explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicit_access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

        status = GetNamedSecurityInfoA(object_name, object_type, DACL_SECURITY_INFORMATION, NULL, NULL, &original_acl, 
                                       NULL, NULL);
        if(status != ERROR_SUCCESS)
        {
            printf("GetNamedSecurityInfoA() failed for %s, error: %d\n", object_name, status);
            break;
        }

        status = SetEntriesInAclA(1, &explicit_access, original_acl, &new_acl);
        if(status != ERROR_SUCCESS)
        {
            printf("SetEntriesInAclA() failed, error: %d\n", object_name, status);
            break;
        }

        status = SetNamedSecurityInfoA(object_name, object_type, DACL_SECURITY_INFORMATION, NULL, NULL, new_acl, NULL);
        if(status != ERROR_SUCCESS)
        {
            printf("SetNamedSecurityInfoA() failed for %s, error: %d\n", object_name, status);
            break;
        }

        success = TRUE;

    } while (FALSE);

   if(original_acl)
       LocalFree(original_acl);

   if(new_acl)
       LocalFree(new_acl);

    return success;
}