# ASM-Experiments
[![](https://img.shields.io/badge/Category-Binary%20Exploitation-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C++%20%2f%20ASM-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Version-1.0-E5A505?style=flat-square&color=green)]()

Experiments with ASM Shellcodes in C++

## Methodology (ASM & ASM2)

Obtain address of GetProcAddress from address table

Call GetProcAddress to obtain address of LoadLibrary within kernel32.dll

Call LoadLibrary to load user32.dll

Call GetProcAddress to obtain address of a function within user32.dll

    eg. SwapMouseButton / MessageBoxA

Call function with required variables --> exploited!

Call GetProcAddress to obtain address of ExitProcess within kernel32.dll

Call ExitProcess to kill the executable process cleanly

REF: [Windows Shellcode Exploit](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)

## Methodology (code & Crashinjector)

Iterates through kernel32.dll ordinals and compare function hashes for function to be injected

When function hash is found, call function with required variables within injected parent process --> exploited!

REF: [Shellcode PID Injection](http://www.rohitab.com/discuss/topic/40820-writing-shellcode-in-c/)
