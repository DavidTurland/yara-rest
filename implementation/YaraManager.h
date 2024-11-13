#ifndef YARAMANAGER_H_
#define YARAMANAGER_H_
/**
 * This and YaraManager.cpp are based on the YaraEngine 
 * https://github.com/mez-0/YaraEngine
 * 
 * This is shrunk,extended from: 
 * https://raw.githubusercontent.com/mez-0/YaraEngine/main/YaraEngine/Yara.hpp
 * 
 * 
*/

#include <thread>
#include <map>
#include <shared_mutex>
#include "YaraTypes.h"
#include "ScannerThreadLocal.h"
#include "ExternalVariable.h"


namespace org::turland::yara
{
    using org::turland::yara::model::ExternalVariable;

    class Manager{
    public:
        // capture start up errors 
        bool startupSuccess = false;

        Manager();

        ~Manager();


        bool compileRulesFromFile(std::string file_name,const char * ns);

        // not exposed in rest api
        bool compileRulesFromDirectory(std::string rule_directory, bool bVerbose);

        /**
         * if cached then returns existing scanner
         * else creates new scanner from current rules
        */
        YaraScanner getScanner(long scanner_id);
        scanner_container_it getScanner_safe_(long scanner_id);

        std::vector<YaraInfo> scanFile(const std::string& filename,long scanner_id);
        std::vector<YaraInfo> scanString(const std::string& memory,int32_t length,long scanner_id);
        /**
         * defines external variables for compiler, scanner, or rules
         * 'meta' contained in externalVariable
         * if scanner (defined by id) then see getScanner for how that 
         * scanner is retrieved
        */
        bool defineExternal(const ExternalVariable &externalVariable);

    private:
        YaraCompiler compiler;

        // One Rules object - needs to be instantiated via say 
        // compileRulesFromDirectory before we can use it 
        YR_RULES* rules = nullptr;
        bool compiler_has_stuff = false;
        // when we expect an instantiated rules object
        YR_RULES* getRules();

        int rule_version;

        // but multiple scanners
        scanner_container scanners;
        mutable std::shared_mutex scanners_mutex_;

        // compiling rules should be mutexed
        mutable std::shared_mutex compiler_mutex_;

        void createCompiler();

        std::string getErrorMsg(int err);

        inline static thread_local ScannerThreadLocal yaratl;
    };
}

#endif
