#pragma once
#include <intrin.h>
#include <winternl.h>

#if _WIN64			
#define DWORD64 unsigned long long
#else
#define DWORD64 unsigned long
#endif

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif




bool TLSflag = 0;
typedef struct _PEB_LDR_DATA_Mine
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA_Mine, * PPEB_LDR_DATA_Mine;


typedef struct _LDR_DATA_TABLE_ENTRY_Mine {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_Mine, * PLDR_DATA_TABLE_ENTRY_Mine;

LPVOID GetModuleBaseByName(WCHAR* ModuleName)
{
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA_Mine ldr = (PPEB_LDR_DATA_Mine)peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY_Mine Flink = *((PLDR_DATA_TABLE_ENTRY_Mine*)(&list));
    PLDR_DATA_TABLE_ENTRY_Mine CurrentModule = Flink;

    while (CurrentModule != NULL && CurrentModule->BaseAddress != NULL) {
        if (CurrentModule->BaseDllName.Buffer == NULL) continue;
        WCHAR* CurrentModuleName = CurrentModule->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; ModuleName[i] != 0 && CurrentModuleName[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, ModuleName[i]);
            TO_LOWERCASE(c2, CurrentModuleName[i]);
            if (c1 != c2) break;
        }
        if (ModuleName[i] == 0 && CurrentModuleName[i] == 0) {
            //found
            return CurrentModule->BaseAddress;
        }
        // not found, try next:
        CurrentModule = (PLDR_DATA_TABLE_ENTRY_Mine)CurrentModule->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

LPVOID GetFunctionAddressByName(LPVOID ModuleBase, char* FunctionName)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)ModuleBase;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)ModuleBase + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)ModuleBase);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)ModuleBase + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)ModuleBase + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)ModuleBase + (*nameIndex) * sizeof(DWORD));

        LPSTR CurrentAPIName = (LPSTR)(*nameRVA + (BYTE*)ModuleBase);
        size_t k = 0;
        for (k = 0; FunctionName[k] != 0 && CurrentAPIName[k] != 0; k++) {
            if (FunctionName[k] != CurrentAPIName[k]) break;
        }
        if (FunctionName[k] == 0 && CurrentAPIName[k] == 0) {
            //found
            return (BYTE*)ModuleBase + (*funcRVA);
        }
    }
    return NULL;
}



void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
//linker spec
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()
//end 
// tls declaration
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    if (TLSflag == TRUE) {
        return;
    }
    // so that the TLS CallBack will not run more that once and corrupt the IAT
    TLSflag = TRUE;

    typedef HMODULE(WINAPI* _LoadLibraryA)(
        LPCSTR lpLibFileName
        );

    typedef FARPROC(WINAPI* _GetProcAddress)(
        HMODULE hModule,
        LPCSTR  lpProcName
        );

    typedef BOOL(WINAPI* _VirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
        );

    typedef HMODULE(WINAPI* _GetModuleHandleA)(
        LPCSTR lpModuleName
        );


    WCHAR kernel32[] = L"kernel32.dll";
    CHAR loadlibrary[] = "LoadLibraryA";
    CHAR GetModuleHandleName[] = "GetModuleHandleA";
    CHAR getprocaddress[] = "GetProcAddress";
    CHAR VirtualProtect[] = "VirtualProtect";
    LPVOID kernel32Base;
    LPVOID MainModuleBase;
    _LoadLibraryA loadlibraryAddr;
    _GetProcAddress getprocaddressAddr;
    _VirtualProtect VirtualProtectAddr;
    _GetModuleHandleA GetModuleHandleAAddr;

    kernel32Base = GetModuleBaseByName(kernel32);
    loadlibraryAddr = (_LoadLibraryA)GetFunctionAddressByName(kernel32Base, loadlibrary);
    getprocaddressAddr = (_GetProcAddress)GetFunctionAddressByName(kernel32Base, getprocaddress);
    VirtualProtectAddr = (_VirtualProtect)GetFunctionAddressByName(kernel32Base, VirtualProtect);
    GetModuleHandleAAddr = (_GetModuleHandleA)GetFunctionAddressByName(kernel32Base, GetModuleHandleName);
   
    MainModuleBase = GetModuleHandleAAddr(NULL);
    //BYTE* MainModuleBase = (BYTE*)MainModuleBase1;

    PIMAGE_NT_HEADERS pSourceHeaders = (PIMAGE_NT_HEADERS)((DWORD64)MainModuleBase + ((PIMAGE_DOS_HEADER)MainModuleBase)->e_lfanew);

    DWORD CommitSize;
    if (!VirtualProtectAddr(MainModuleBase, pSourceHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &CommitSize)) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;

    IMAGE_DATA_DIRECTORY importsDirectory = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((importsDirectory.VirtualAddress + (DWORD_PTR)MainModuleBase));

    LPCSTR libraryName = "";
    HMODULE library = NULL;

    CHAR* OldAPI = NULL;
    DWORD64* OldThunck = NULL;
    DWORD64 OldFun = NULL;
    int index = 0;

    PIMAGE_THUNK_DATA thunk = NULL;
    PIMAGE_THUNK_DATA OriginalThunk = NULL;
    while (importDescriptor->Name != NULL)
    {

        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)MainModuleBase;
        library = loadlibraryAddr(libraryName);
        index = 0;
        if (library)
        {
            OriginalThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)MainModuleBase + importDescriptor->OriginalFirstThunk);
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)MainModuleBase + importDescriptor->FirstThunk);

            while (OriginalThunk->u1.AddressOfData != NULL)
            {

                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {

                }
                else {
                    if (index % 2 == 1) {
                        CHAR* functionName = (char*)((DWORD_PTR)MainModuleBase + OriginalThunk->u1.AddressOfData + 2);

                        thunk->u1.Function = (DWORD64)OldFun;
                        *OldThunck = (DWORD64)getprocaddressAddr(library, functionName);
                    }
                    else {
                        OldAPI = (CHAR*)((DWORD64)MainModuleBase + OriginalThunk->u1.AddressOfData + 2);
                        OldThunck = (DWORD64*)&thunk->u1.Function;
                        OldFun = thunk->u1.Function;
                    }
                    index++;
                }

                ++thunk;
                ++OriginalThunk;
            }
        }

        importDescriptor++;
    }


    return;
}