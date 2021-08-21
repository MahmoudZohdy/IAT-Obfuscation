#include <stdio.h>
#include <Windows.h>

#if _WIN64			
#define DWORD64 unsigned long long
#else
#define DWORD64 unsigned long
#endif



void PrintUsage() {
	printf("IAT-Obfuscation.exe <Executable to protect> <Output File Name>\n");
	return;
}

int main(int argc, CHAR* argv[]){

	HANDLE hFile = NULL;
	DWORD FileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID FileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA ThunkData = {};
	DWORD64 thunk = NULL;
	DWORD64 IATRawOffset = NULL;

	if (argc < 2) {
		PrintUsage();
		return 0;
	}

	CHAR* OutputFileName;

	if (argc == 3) {
		OutputFileName = argv[2];
	}
	else {
		OutputFileName = argv[1];
	}

	hFile = CreateFileA(argv[1], GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Failed To Opne File %s For Read Error Code %x\n", argv[1],GetLastError());
		return -1;
	}

	FileSize = GetFileSize(hFile, NULL);
	FileData = HeapAlloc(GetProcessHeap(), 0, FileSize);
	ReadFile(hFile, FileData, FileSize, &bytesRead, NULL);

	dosHeader = (PIMAGE_DOS_HEADER)FileData;

	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD64)FileData + dosHeader->e_lfanew);

	DWORD64 sectionLocation = (DWORD64)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD64 sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	DWORD64 importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	//DWORD64 RVAtoOffsetConversion = (DWORD64)importSection->PointerToRawData - (DWORD64)importSection->VirtualAddress;
	DWORD64 StartIATOffset = (DWORD64)importDirectoryRVA - (DWORD64)importSection->VirtualAddress + (DWORD64)importSection->PointerToRawData;

	IATRawOffset = (DWORD64)FileData + importSection->PointerToRawData;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(IATRawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

	IMAGE_IMPORT_DESCRIPTOR* MYIAT = (IMAGE_IMPORT_DESCRIPTOR*)(StartIATOffset + (DWORD64)FileData);
	int index = 0;
	DWORD64 PrevValue;
	DWORD64* PrevLocation = NULL;
	DWORD64 CurrentValue;
	DWORD64* CurrentLocation = NULL;
	for (; MYIAT->Name != 0; MYIAT++) {
		thunk = MYIAT->OriginalFirstThunk == 0 ? MYIAT->FirstThunk : MYIAT->OriginalFirstThunk;
		ThunkData = (PIMAGE_THUNK_DATA)(IATRawOffset + (thunk - importSection->VirtualAddress));
		index = 0;
		for (; ThunkData->u1.AddressOfData != 0; ThunkData++) {

			if (ThunkData->u1.AddressOfData > 0x80000000) {
			}
			else {
				CHAR* functionOrdinal = (CHAR*)((DWORD64)IATRawOffset + (ThunkData->u1.AddressOfData - importSection->VirtualAddress + 2));
				if (index % 2 == 1) {
					CurrentValue = ThunkData->u1.AddressOfData;
					CurrentLocation = (DWORD64*)&ThunkData->u1.AddressOfData;;
					
					*(DWORD64*)CurrentLocation = PrevValue;
					*(DWORD64*)PrevLocation = CurrentValue;
				}
				else {
					PrevValue = ThunkData->u1.AddressOfData;
					PrevLocation = (DWORD64*)&ThunkData->u1.AddressOfData;
				}
				index++;
				 
			}
		}
	}
	CloseHandle(hFile);

	HANDLE hOutputFile = CreateFileA(OutputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE) {
		printf("Faile TO open file %s for write Error Code %x\n", OutputFileName,GetLastError());
		return 0;
	}

	DWORD dwBytesWritten;
	BOOL bErrorFlag = WriteFile(hOutputFile, FileData, FileSize, &dwBytesWritten, NULL);

	if (FALSE == bErrorFlag) {
		printf("Terminal failure: Unable to write to file.\n");
	}

	printf("Finished\n");

	return 0;



    
    return 0;
}
