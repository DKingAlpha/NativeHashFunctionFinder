#pragma once
#include <vector>
#include <functional>

namespace MemoryLib {
	class Memory {
	public:
		static std::size_t FindPattern(std::vector<unsigned char> data, const char* pszPattern, std::size_t baseAddress = 0, std::size_t offset = 0, int occurrence = 0, std::function<void(size_t)> callback = NULL);
	};
}