#pragma once
#include <stdint.h>
#pragma pack(4)
struct NativeDumpFile
{
	int32_t magic; //  = 0x5654414E; // 'NATV'
	int32_t version; //  = 1;       // version of dump
	int32_t native_count; //  = 0;   // number of dumped natives (MUST NOT include failed ones during native dump!)
						  /*
						  Depending on which version dump you are using, the natives list
						  may or may not follow directly after the native count.

						  For version 1 dumps, the list is directly after the count.
						  */
	struct NativeEntry
	{
		int64_t hash; // native hash
		int64_t func_offset; // function offset in the EXE
	} natives[6000]; // Native list size will be (native_count * sizeof(NativeTableEntry))
};
