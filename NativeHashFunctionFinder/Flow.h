#pragma once
#include <list>
class Flow
{
public:

	std::list < std::pair<uint64_t, uint8_t> > contents;

	Flow()
	{
	}

	~Flow()
	{
	}

	void push_back(uint64_t offset, uint8_t byte) {
		contents.push_back(std::pair<uint64_t, uint8_t>(offset, byte));
	}
};

