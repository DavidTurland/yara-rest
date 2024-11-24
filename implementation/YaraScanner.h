#ifndef YARA_SCANNER_H
#define YARA_SCANNER_H
// #include "YaraScanner.h"
#include <vector>
#include <string>
#include <map>

#include <yara.h>

#include "Rule.h"
#include "ExternalVariable.h"

namespace org::turland::yara
{
namespace modell = org::turland::yara::model;

struct YaraScanner{
    YR_SCANNER* scanner;
    long        rule_version;
    YaraScanner(long  _rule_version):scanner(nullptr),rule_version(_rule_version){}
    YaraScanner(YR_SCANNER* _scanner,long  _rule_version):scanner(_scanner),rule_version(_rule_version){}
    bool defineExternal(const modell::ExternalVariable &externalVariable);
};

typedef std::map<long,YaraScanner>  scanner_container;
typedef scanner_container::iterator scanner_container_it;

} // namespace org::turland::yara
#endif
