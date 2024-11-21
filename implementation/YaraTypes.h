#ifndef YARA_TYPES_H
#define YARA_TYPES_H
// #include "YaraTypes.h"
#include <vector>
#include <string>
#include <map>

#include <yara.h>

#include "Rule.h"
#include "ExternalVariable.h"

namespace org::turland::yara
{

using  org::turland::yara::model::Rule;
using  org::turland::yara::model::ExternalVariable;
struct YaraScanResultRules{
    /**
     * provides an aceesible  vector rules
     * unfortunately the ScanResult class does not offer reference access to its Rules
     */
    std::vector<Rule> matched_rules;
};

struct YaraCompiler{
    YaraCompiler(int &rule_version);
    ~YaraCompiler();
    bool create();
    bool destroy();
    int add_file(FILE* rule_file, const char * ns, const char *error_file);
    int get_rules(YR_RULES** rules);
    bool defineExternal(const ExternalVariable &externalVariable);
private:
    // this should handle the invalidation of the compiler by a failed add
    // ie destroy the compiler on a failure
    // But it needs to return failure for a failed add so the 
    // client can replay(sigh) the adds prior to the failure
    YR_COMPILER* compiler;
    int &rule_version;
    bool get_rules_called;
    bool add_called;
 };

struct YaraScanner{
    YR_SCANNER* scanner;
    long        rule_version;
    YaraScanner(long  _rule_version):scanner(nullptr),rule_version(_rule_version){}
    YaraScanner(YR_SCANNER* _scanner,long  _rule_version):scanner(_scanner),rule_version(_rule_version){}
    bool defineExternal(const ExternalVariable &externalVariable);
};

typedef std::map<long,YaraScanner>  scanner_container;
typedef scanner_container::iterator scanner_container_it;
}
#endif
