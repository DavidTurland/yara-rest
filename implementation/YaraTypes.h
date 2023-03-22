#ifndef YARA_TYPES_H
#define YARA_TYPES_H
// #include "YaraTypes.h"
#include <vector>
#include <string>
#include <map>
#include <yara.h>
#include "simple_cpp_logger/Logger.h"

namespace org::turland::yara
{
struct YaraInfo{
    std::vector<std::string> matched_rules;
};

struct YaraScanner{
    YR_SCANNER* scanner;
    long        rule_version;
    YaraScanner(long  _rule_version):scanner(nullptr),rule_version(_rule_version){}
    YaraScanner(YR_SCANNER* _scanner,long  _rule_version):scanner(_scanner),rule_version(_rule_version){}
};

typedef std::map<long,YaraScanner>  scanner_container;
typedef scanner_container::iterator scanner_container_it;
}
#endif
