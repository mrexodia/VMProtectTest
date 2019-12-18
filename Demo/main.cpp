#include "pch.h"

#include <iostream>
#include <VMProtectSDK.h>

#ifdef __WIN32
__declspec(naked) void sub_eax_1()
{
	VMProtectBeginVirtualization(__FUNCTION__);
	__asm
	{
		sub eax, 1;
	}
	volatile unsigned long long rax = 1; // lol
	rax -= 1;
	VMProtectEnd();
}
#else
void sub_eax_1()
{
	VMProtectBeginVirtualization(__FUNCTION__);
	volatile unsigned long long rax = 1; // lol
	rax -= 1;
	VMProtectEnd();
}
#endif

int main()
{
	std::cout << std::hex << sub_eax_1 << std::endl;
	return 0;
}