#ifndef YARA_COMPILER_H
#define YARA_COMPILER_H
// #include "YaraCompiler.h"
#include <vector>
#include <string>
#include <map>

#include <yara.h>

#include "Rule.h"
#include "ExternalVariable.h"

namespace org::turland::yara
{
    namespace modell = org::turland::yara::model;

    struct YaraCompiler
    {
        YaraCompiler(int &rule_version);
        ~YaraCompiler();
        // bool create();
        bool destroy();

        YR_COMPILER *_get_compiler();
        int add_file(FILE *rule_file, const char *ns, const char *error_file);
        int get_rules(YR_RULES **rules);
        bool defineExternal(const modell::ExternalVariable &externalVariable);

    private:
        // this should handle the invalidation of the compiler by a failed add
        // ie destroy the compiler on a failure
        // But it needs to return failure for a failed add so the
        // client can replay(sigh) the adds prior to the failure
        YR_COMPILER *compiler;
        int &rule_version;
        bool _compiler_get_rules_called;
        bool _compiler_add_called;
        bool _compiler_broken;
    };

} // namespace org::turland::yara
#endif
