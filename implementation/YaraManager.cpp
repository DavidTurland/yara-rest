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
#include <pistache/http_defs.h>

//#include "YaraRestFSM.h"
#include "YaraManager.h"
#include "YaraHelpers.h"
#include "Helpers.h"
#include "ExternalVariable.h"

namespace org::turland::yara
{
// for the helper::<blah> methods
// using namespace org::openapitools::server;

Manager::Manager():rule_version{},compiler(rule_version),
    scanner_is_broke{false}{
    int init = yr_initialize();
    if (init != ERROR_SUCCESS){
        startupSuccess = false;
        LOG(ERROR)  << "yr_initialize failed: " << getYaraErrorMsg(init);
        // hmm maybe not throw in constructor
        return;
    }
}

Manager::~Manager(){

    int finalise = yr_finalize();
    if (finalise != ERROR_SUCCESS){
        LOG(ERROR) << "yr_finalize failed: " << getYaraErrorMsg(finalise);
        return;
    }
}

bool Manager::compileRulesFromFile(std::string file_name,const char * ns){
    LOG(INFO) << "compileRulesFromFile file name "  << file_name << ", ns " << ns;    
    FILE* rule_file = fopen(file_name.c_str(), "r");
    if (rule_file == NULL){
        LOG(ERROR) << "Failed to open " << file_name << "," << getYaraErrorMsg(errno);
        throw Pistache::Http::HttpError(
              Pistache::Http::Code::Bad_Request,   // CODE 400
              "failed to open file");
    }

    std::unique_lock sc_unique_lock(compiler_mutex_);
    const char *error_file= nullptr;
    int result = compiler.add_file(rule_file, ns, error_file);
     
    compiler_has_stuff = true;
    // result = compiler.get_rules(&rules);

    // if (result != ERROR_SUCCESS){
    //     LOG(ERROR) << "Failed to get rules from " << file_name << "," << getYaraErrorMsg(result);
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

bool Manager::defineExternal(const modell::ExternalVariable &externalVariable){
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
                if (ERROR_SUCCESS !=success){
                    throw HttpYaraError(
                        Pistache::Http::Code::Bad_Request,                   // CODE 400
                        "failed call to yr_rules_define_integer_variable",
                        success);
                }
                rule_version++;
                return true;
            }
        }
        else if( externalVariable.getType() == "float"){
            float value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_float_variable(getRules(),externalVariable.getIdentifier().c_str(),value);
                if (ERROR_SUCCESS !=success){
                    throw HttpYaraError(
                        Pistache::Http::Code::Bad_Request,   // CODE 400
                        "failed call to yr_rules_define_float_variable",
                        success);
                }
                rule_version++;
                return true;
            }
        }
        else if( externalVariable.getType() == "boolean"){
            bool value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_boolean_variable(getRules(),externalVariable.getIdentifier().c_str(),value);
                LOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
                if (ERROR_SUCCESS !=success){
                    throw HttpYaraError(
                        Pistache::Http::Code::Bad_Request,   // CODE 400
                        "failed call to yr_rules_define_boolean_variable",
                        success);
                }
                rule_version++;
                return true;
            }
        }
        else if( externalVariable.getType() == "string"){
            int success =  yr_rules_define_string_variable(getRules(),externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            if (ERROR_SUCCESS !=success){
                throw HttpYaraError(
                    Pistache::Http::Code::Bad_Request,   // CODE 400
                    "failed call to yr_rules_define_string_variable",
                    success);
            }
            rule_version++;
            return true;
        }else{
            throw Pistache::Http::HttpError(
                Pistache::Http::Code::Bad_Request,
                "failed call to yr_rules_define_string_variable");
        }
    }
    else if(externalVariable.getComponent() == "scanner"){
        long scanner_id = externalVariable.getScanner();
        return getScanner(scanner_id).defineExternal(externalVariable);
    }
    return false;
}

YaraScanner Manager::getScanner(long id){
    {
        if (scanner_is_broke){
            LOG(ERROR) << "scanner is broke from previos call";
            throw Pistache::Http::HttpError(
                Pistache::Http::Code::Internal_Server_Error,
                "failed call to yr_scanner_create");
        }        
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
            scanner_is_broke = true;
            throw HttpYaraError(
                Pistache::Http::Code::Internal_Server_Error,
                "failed call to yr_scanner_create",
                result);
        }
        scanners.insert(std::pair{id,yscanner});
        LOG(INFO) << "get_scanner created with id:" << id;
        return yscanner;
    }
}

// called from response thread
YaraScanResultRules Manager::scanFile(const std::string& filename,long scanner_id){
    yaratl.init(this);
    int result = yr_scanner_scan_file(yaratl.get_scanner(scanner_id), filename.c_str());
    if(ERROR_SUCCESS != result){
        throw HttpYaraError(
            Pistache::Http::Code::Precondition_Failed,
            "failed call to yr_scanner_scan_file",
            result);
    }
    log_rules(yaratl.yaraInfo.matched_rules);
    return yaratl.yaraInfo;
}

// called from response thread
YaraScanResultRules Manager::scanString(const std::string& memory,int32_t length,long scanner_id){

    yaratl.init(this);
    int result = yr_scanner_scan_mem(yaratl.get_scanner(scanner_id), 
    (const unsigned char*)(memory.c_str()),length);

    if(ERROR_SUCCESS != result){
        throw HttpYaraError(
            Pistache::Http::Code::Precondition_Failed,
            "failed call to yr_scanner_scan_mem",
            result);
    }
        log_rules(yaratl.yaraInfo.matched_rules);

    return yaratl.yaraInfo;
}

// void Manager::createCompiler(){
//     //int create = compiler.create();
//     // startupSuccess = (create == ERROR_SUCCESS);
// }

YR_RULES* Manager::getRules(){
    if(compiler_has_stuff){
        if( nullptr == rules){
            std::unique_lock sc_unique_lock(compiler_mutex_);
            int result = compiler.get_rules(&rules);
            return rules;        
        }
    }else{
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Precondition_Failed,
            "Attempting to use rules before creation");
    }

    return rules;

}


}
