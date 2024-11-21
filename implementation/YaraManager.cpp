/**
 * This and YaraManager.h are based on the YaraEngine 
 * https://github.com/mez-0/YaraEngine
 * 
 * This is shrunk,extended from: 
 * https://raw.githubusercontent.com/mez-0/YaraEngine/main/YaraEngine/Yara.hpp
 * 
 * 
*/

#include <iostream>
#include <mutex>
#include <shared_mutex>

#include <glog/logging.h>

//#include "YaraRestFSM.h"
#include "YaraManager.h"
#include "YaraHelpers.hpp"
#include "Helpers.h"
#include "ExternalVariable.h"

namespace org::turland::yara
{
// for the helper::<blah> methods
// using namespace org::openapitools::server;

Manager::Manager():rule_version{},compiler(rule_version){
    int init = yr_initialize();
    if (init != ERROR_SUCCESS){
        startupSuccess = false;
        LOG(ERROR)  << "yr_initialize failed: " << getErrorMsg(init);
        return;
    }
    createCompiler();
}

Manager::~Manager(){

    int finalise = yr_finalize();
    if (finalise != ERROR_SUCCESS){
        LOG(ERROR) << "yr_finalize failed: " << getErrorMsg(finalise);
        return;
    }
}

bool Manager::compileRulesFromFile(std::string file_name,const char * ns){
    LOG(INFO) << "compileRulesFromFile file name "  << file_name << ", ns " << ns;    
    FILE* rule_file = fopen(file_name.c_str(), "r");
    if (rule_file == NULL){
        LOG(ERROR) << "Failed to open " << file_name << "," << getErrorMsg(errno);
        return false;
    }
    if (compiler_is_broke){
        LOG(ERROR) << "compileRulesFromFile from " << file_name 
             << ", failed as compiler is broke";
        return false;
    }
    std::unique_lock sc_unique_lock(compiler_mutex_);
    if( nullptr != rules){
         LOG(ERROR) << "compileRulesFromFile from " << file_name 
             << ", failed as already obtained rules";
        return false;
        // need to destroy the rules and create a new compiler
        // yr_compiler_destroy()
        // https://yara.readthedocs.io/en/stable/capi.html?highlight=YR_CALLBACK_FUNC#c.yr_rules_destroy
        // yr_rules_destroy()
        // and invalidate any scanners .....
    }

    const char *error_file= nullptr;
    int result = compiler.add_file(rule_file, ns, error_file);
    if (result != ERROR_SUCCESS){
        LOG(ERROR) << "compileRulesFromFile Failed to add rules from " 
           << file_name << ",compiler is now broke. " << getErrorMsg(result);
        compiler_is_broke = true;
        return false;
    }
    compiler_has_stuff = true;
    // result = compiler.get_rules(&rules);

    // if (result != ERROR_SUCCESS){
    //     LOG(ERROR) << "Failed to get rules from " << file_name << "," << getErrorMsg(result);
    //     return false;
    // }

    // LOG(INFO) << "compileRulesFromFile Added" << file_name;
    // rule_version++;
    return true;
}

bool Manager::compileRulesFromDirectory(std::string rule_directory, bool bVerbose){
    int file_count = 0;
    int succes_count = 0;
    std::unique_lock sc_unique_lock(compiler_mutex_);
    for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(rule_directory)){
        if (".yar" != dirEntry.path().extension()){
            continue;
        }
        const char * ns = nullptr;
        if (compileRulesFromFile(dirEntry.path().string(), ns)){
            succes_count++;
            compiler_has_stuff = true;
        }
        file_count++;
    }
   
    LOG(INFO) << "compileRulesFromDirectory Added " << succes_count << "/" <<  file_count;
    return (succes_count > 0);
}

bool Manager::defineExternal(const ExternalVariable &externalVariable){
    LOG(INFO) << "define_external type " << externalVariable.getType() <<  ","
                << "identifier " << externalVariable.getIdentifier() << ","
                << "getComponent " << externalVariable.getComponent();// no error
    if(externalVariable.getComponent() == "compiler"){
        return compiler.defineExternal(externalVariable);
    }
    else if(externalVariable.getComponent() == "rules"){
        if( externalVariable.getType() == "integer"){
            int32_t value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_integer_variable(getRules(),externalVariable.getIdentifier().c_str(),value);
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "float"){
            float value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_float_variable(getRules(),externalVariable.getIdentifier().c_str(),value);
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "boolean"){
            bool value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_boolean_variable(getRules(),externalVariable.getIdentifier().c_str(),value);
                LOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "string"){
            int success =  yr_rules_define_string_variable(getRules(),externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }else{
            //std::cout << "default\n"; // no error
            return false;
        }
    }
    else if(externalVariable.getComponent() == "scanner"){
        long scanner_id = externalVariable.getScanner();
        getScanner(scanner_id).defineExternal(externalVariable);
        return true;
    }
    return false;
}

YaraScanner Manager::getScanner(long id){
    {
        // https://en.cppreference.com/w/cpp/thread/shared_mutex
        std::shared_lock sc_shared_lock(scanners_mutex_);
        scanner_container_it scit = scanners.find(id);
        if (scit != scanners.end()){
            return scit->second;
        }
    }
    {    
        // no upgrade_to_write so:
        std::unique_lock sc_unique_lock(scanners_mutex_);
        // retry as we we lost the lock
        scanner_container_it scit = scanners.find(id);
        if (scit != scanners.end()){
            return scit->second;
        }  
        YaraScanner yscanner(rule_version);

        int result = yr_scanner_create(getRules(), &yscanner.scanner);
        if (result != ERROR_SUCCESS){
            LOG(ERROR) << "Failed to create scanner" << result;
            yscanner.scanner = nullptr;
            yscanner.rule_version = -1;
            return yscanner;
        }
        scanners.insert(std::pair{id,yscanner});
        LOG(INFO) << "get_scanner created with id:" << id;
        return yscanner;
    }
}

// called from response thread
YaraScanResultRules Manager::scanFile(const std::string& filename,long scanner_id){
    //std::vector<YaraInfo> allYaraInfo;

    yaratl.init(this);
    int result = yr_scanner_scan_file(yaratl.get_scanner(scanner_id), filename.c_str());

    if (yaratl.yaraInfo.matched_rules.size() > 0) {
        for (auto r : yaratl.yaraInfo.matched_rules){
            log_rule(r);
        }
    }
    return yaratl.yaraInfo;
}

// called from response thread
YaraScanResultRules Manager::scanString(const std::string& memory,int32_t length,long scanner_id){

    yaratl.init(this);
    int result = yr_scanner_scan_mem(yaratl.get_scanner(scanner_id), 
    (const unsigned char*)(memory.c_str()),length);

    if (yaratl.yaraInfo.matched_rules.size() > 0) {
        for (auto r : yaratl.yaraInfo.matched_rules){
            log_rule(r);
        }
    }
    return yaratl.yaraInfo;
}

void Manager::createCompiler(){
    int create = compiler.create();
    startupSuccess = (create == ERROR_SUCCESS);
}

YR_RULES* Manager::getRules(){

    if(compiler_has_stuff){
        if( nullptr == rules){
            std::unique_lock sc_unique_lock(compiler_mutex_);
            int result = compiler.get_rules(&rules);

            if (result != ERROR_SUCCESS){
                LOG(ERROR) << "getRules Failed yr_compiler_get_rules ,"<< getErrorMsg(result);
                return nullptr;
            }
            else{
                LOG(INFO) <<  "getRules yr_compiler_get_rules";
                rule_version++;
                return rules;
            }            
        }
    }else{
        throw std::runtime_error("Attempting to use rules before creation");
    }

    return rules;

}

std::string Manager::getErrorMsg(int err){
    std::string msg;
    switch (err){
    case ERROR_SUCCESS:
        msg = "ERROR_SUCCESS";
        break;
    case ERROR_INSUFFICIENT_MEMORY:
        msg = "ERROR_INSUFFICIENT_MEMORY";
        break;
    case ERROR_COULD_NOT_OPEN_FILE:
        msg = "ERROR_COULD_NOT_OPEN_FILE";
        break;
    case ERROR_COULD_NOT_MAP_FILE:
        msg = "ERROR_COULD_NOT_MAP_FILE";
        break;
    case ERROR_INVALID_FILE:
        msg = "ERROR_INVALID_FILE";
        break;
    case ERROR_CORRUPT_FILE:
        msg = "ERROR_CORRUPT_FILE";
        break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
        msg = "ERROR_UNSUPPORTED_FILE_VERSION";
        break;
    case ERROR_TOO_MANY_SCAN_THREADS:
        msg = "ERROR_TOO_MANY_SCAN_THREADS";
        break;
    case ERROR_SCAN_TIMEOUT:
        msg = "ERROR_SCAN_TIMEOUT";
        break;
    case ERROR_CALLBACK_ERROR:
        msg = "ERROR_CALLBACK_ERROR";
        break;
    case ERROR_TOO_MANY_MATCHES:
        msg = "ERROR_TOO_MANY_MATCHES";
        break;
    case ERROR_BLOCK_NOT_READY:
        msg = "ERROR_BLOCK_NOT_READY";
        break;
    default:
        break;
    }
    return msg;
}
}
