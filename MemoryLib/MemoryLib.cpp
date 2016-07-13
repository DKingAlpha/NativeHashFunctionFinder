#include "MemoryLib.h"
#include <algorithm>
#include <cctype>
#include <string>


/// @brief Signature Scanning
/// Here is an updated version of my scanner. I rewrote the pattern/mask usage to now just be a single string.
/// I got tired of maintaining masks and patterns separately so they are now in a single string.
/// This does not include half-byte scans as I do not find them useful or needed. -- atm0s
///  
/// Source: http://atom0s.com/forums/viewtopic.php?f=5&t=4&start=10

using namespace std;
namespace MemoryLib {


	struct PatternByte
	{
		struct PatternNibble
		{
			unsigned char data;
			bool wildcard;
		} nibble[2];
	};

	static string FormatPattern(string patterntext)
	{
		string result;
		size_t len = patterntext.length();
		for (int i = 0; i < len; i++)
			if (patterntext[i] == '?' || isxdigit(patterntext[i]))
				result += toupper(patterntext[i]);
		return result;
	}

	static int HexChToInt(char ch)
	{
		if (ch >= '0' && ch <= '9')
			return ch - '0';
		else if (ch >= 'A' && ch <= 'F')
			return ch - 'A' + 10;
		else if (ch >= 'a' && ch <= 'f')
			return ch - 'a' + 10;
		return 0;
	}

	static bool TransformPattern(string patterntext, vector<PatternByte> & pattern)
	{
		pattern.clear();
		patterntext = FormatPattern(patterntext);
		size_t len = patterntext.length();
		if (!len)
			return false;

		if (len % 2) // not a multiple of 2
		{
			patterntext += '?';
			len++;
		}

		PatternByte newByte;
		for (int i = 0, j = 0; i < len; i++)
		{
			if (patterntext[i] == '?') // wildcard
			{
				newByte.nibble[j].wildcard = true; // match anything
			}
			else //hex
			{
				newByte.nibble[j].wildcard = false;
				newByte.nibble[j].data = HexChToInt(patterntext[i]) & 0xF;
			}

			j++;
			if (j == 2) // two nibbles = one byte
			{
				j = 0;
				pattern.push_back(newByte);
			}
		}
		return true;
	}

	static bool MatchByte(const unsigned char byte, const PatternByte & pbyte)
	{
		int matched = 0;

		unsigned char n1 = (byte >> 4) & 0xF;
		if (pbyte.nibble[0].wildcard)
			matched++;
		else if (pbyte.nibble[0].data == n1)
			matched++;

		unsigned char n2 = byte & 0xF;
		if (pbyte.nibble[1].wildcard)
			matched++;
		else if (pbyte.nibble[1].data == n2)
			matched++;

		return (matched == 2);
	}

	/**
	* Scans the given data for the pattern.
	* by github/mrexodia based on code by mrexodia and atm0s
	* @param {vector} data                     The data to scan within for the given pattern.
	* @param {const char*} pszPattern          The pattern to scan for. (Wildcards are marked as ?? per byte.)
	* @param {intptr_t} baseAddress            The base address of where the scan is starting from (to add to return value)
	* @param {intptr_t} offset                 The offset to add to the found location (to add to return value)
	* @param {intptr_t} occurence              The occurance to find (default 0), -1 for infinite (used with replace callback)
	* @returns {intptr_t}                      The address where the pattern was found, < 0 otherwise (-1 - occurances found)
	*/
	std::size_t Memory::FindPattern(std::vector<unsigned char> data, const char * pszPattern, std::size_t baseAddress, std::size_t offset, int occurrence, std::function<void(size_t)> callback)
	{
		// Build vectored pattern..
		vector<PatternByte> patterndata;
		if (!TransformPattern(pszPattern, patterndata))
			return -1;

		// The result count for multiple results..
		int resultCount = 0;
		vector<unsigned char>::iterator scanStart = data.begin();

		while (true)
		{
			// Search for the pattern..
			vector<unsigned char>::iterator ret = search(scanStart, data.end(), patterndata.begin(), patterndata.end(), MatchByte);

			// Did we find a match..
			if (ret != data.end())
			{
				if (callback) {
					callback(baseAddress + distance(data.begin(), ret) + offset);
				}
				// If we hit the usage count, return the result..
				if (occurrence == 0 || resultCount == occurrence)
					return baseAddress + distance(data.begin(), ret) + offset;

				// Increment the found count and scan again..
				resultCount++;
				scanStart = ++ret;
			}
			else
				break;
		}

		return -1 - resultCount;
	}

}