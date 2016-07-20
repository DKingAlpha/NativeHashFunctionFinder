#pragma once
#include <vector>
#include <functional>

using namespace std;

class MemoryShim
{
public:

    vector <unsigned char> memVector;
    intptr_t memBaseAddress = 0;
	::function < vector <unsigned char>(intptr_t)> readMemoryFn;

    unsigned char *assign(const unsigned char* buffer, size_t length,uint64_t address) {
		memVector.assign(buffer, buffer + length);
		return &memVector[0];
	}

	void setAutoLoader(::function<vector <unsigned char>(intptr_t)> callback) {
		readMemoryFn = callback;
	}

	vector <unsigned char> getVector() {
		return memVector;
	}
	unsigned char * readMemory(intptr_t address, size_t length = 15) {
		if (address >= memBaseAddress && (address + length) <= (memBaseAddress + memVector.size())) {
			return &memVector[address - memBaseAddress];
		}
		if (readMemoryFn) {
			memVector = readMemoryFn(memBaseAddress = address);
			if (length <= memVector.size()) {
				return &memVector[address - memBaseAddress];
			}
			else {
				printf("readMemory request exceeds buffer length of %lld", memVector.size());
			}
		}
		else {
			printf("readMemory request exceeds existing buffer and no readMemoryFn defined");
		}
	
		return NULL;
	}
	unsigned char * memoryAsBuffer() {
		return &memVector[0];
	}
		

	MemoryShim()
	{
	}

	virtual ~MemoryShim()
	{
	}
};

