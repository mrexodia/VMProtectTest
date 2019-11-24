#include "pch.h"

#include "deobfuscator.hpp"
#pragma comment(lib, "xed.lib")

int main()
{
	// Once, before using Intel XED, you must call xed_tables_init() to initialize the tables Intel XED uses for encoding and decoding:
	xed_tables_init();

	vmprotect_test(0x502c);
	return 0;
}