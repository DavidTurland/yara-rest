#ifndef YARAHELPERS_H
#define YARAHELPERS_H
// #include "YaraHelpers.h"
#include <fstream>
#include <streambuf>
#include <algorithm>

#include "Rule.h"
namespace org::turland::yara
{

// https://en.cppreference.com/w/cpp/string/byte/tolower
inline std::string str_tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), 
                // static_cast<int(*)(int)>(std::tolower)         // wrong
                // [](int c){ return std::tolower(c); }           // wrong
                // [](char c){ return std::tolower(c); }          // wrong
                   [](unsigned char c){ return std::tolower(c); } // correct
                  );
    return s;
}

inline bool vectorContainsString(std::vector<std::string> haystack, std::string needle)
{
    std::string low_needle = str_tolower(needle);
	for (std::string& hay : haystack)
	{
		if (str_tolower(hay) == low_needle)
		{
			return true;
		}
	}
	return false;
}

void log_rule(const org::turland::yara::model::Rule& rule);

} // namespace org::turland::yara
#endif
