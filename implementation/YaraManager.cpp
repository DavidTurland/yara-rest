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
#include "YaraManager.h"
#include "YaraHelpers.hpp"

#include "Helpers.h"
#include "ExternalVariable.h"

#include "simple_cpp_logger/Logger.h"

namespace org::turland::yara
{

Manager::Manager():rule_version{}{
    int init = yr_initialize();
    if (init != ERROR_SUCCESS){
        startupSuccess = false;
        LogFatal << "yr_initialize failed: " << getErrorMsg(init);
        return;
    }
    createCompiler();
}

Manager::~Manager(){
    if (compiler != NULL){
        yr_compiler_destroy(compiler);
    }

    int finalise = yr_finalize();
    if (finalise != ERROR_SUCCESS){
        LogError << "yr_finalize failed: " << getErrorMsg(finalise);
        return;
    }
}

bool Manager::compileRulesFromFile(std::string file_name,const char * ns){
    FILE* rule_file = fopen(file_name.c_str(), "r");
    if (rule_file == NULL){
        LogError << "Failed to open " << file_name << "," << getErrorMsg(errno);
        return false;
    }
    const char *error_file= nullptr;
    int result = yr_compiler_add_file(compiler, rule_file, ns, error_file);
    if (result != ERROR_SUCCESS){
        LogError << "Failed to add rules from " << file_name << "," << getErrorMsg(result);
        return false;
    }

    result = yr_compiler_get_rules(compiler, &rules);

    if (result != ERROR_SUCCESS){
        LogError << "Failed to get rules from " << file_name << "," << getErrorMsg(result);
        return false;
    }

    LogInfo << "compileRulesFromFile Added" << file_name;
    rule_version++;
    return true;
}

bool Manager::compileRulesFromDirectory(std::string rule_directory, bool bVerbose){
    int file_count = 0;
    int succes_count = 0;

    for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(rule_directory)){
        if (".yar" != dirEntry.path().extension()){
            continue;
        }
        const char * ns = nullptr;
        if (compileRulesFromFile(dirEntry.path().string(), ns)){
            succes_count++;
        }
        file_count++;
    }

    LogInfo << "compileRulesFromDirectory Added " << succes_count << "/" <<  file_count;

    int result = yr_compiler_get_rules(compiler, &rules);

    if (result != ERROR_SUCCESS){
        LogError << "compileRulesFromDirectory Failed yr_compiler_get_rules from" <<  
               rule_directory << ","<< getErrorMsg(result);
        return false;
    }
    else{
        LogInfo <<  "compileRulesFromDirectory yr_compiler_get_rules";
        rule_version++;
        return true;
    }
}

bool Manager::defineExternal(const ExternalVariable &externalVariable){
    LogInfo << "define_external type " << externalVariable.getType() <<  ","
                << "identifier " << externalVariable.getIdentifier() << ","
                << "getComponent " << externalVariable.getComponent();// no error
    if(externalVariable.getComponent() == "compiler"){
        if( externalVariable.getType() == "integer"){
            int32_t value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_compiler_define_integer_variable(compiler,externalVariable.getIdentifier().c_str(),value);
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "float"){
            float value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_compiler_define_float_variable(compiler,externalVariable.getIdentifier().c_str(),value);
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "boolean"){
            bool value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_compiler_define_boolean_variable(compiler,externalVariable.getIdentifier().c_str(),value);
                LogInfo << "define_external" << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "string"){
            int success =  yr_compiler_define_string_variable(compiler,externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            return (ERROR_SUCCESS ==success);
        }else{
            return false;
        }
    }
    else if(externalVariable.getComponent() == "rules"){
        if( externalVariable.getType() == "integer"){
            int32_t value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_integer_variable(rules,externalVariable.getIdentifier().c_str(),value);
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "float"){
            float value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_float_variable(rules,externalVariable.getIdentifier().c_str(),value);
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "boolean"){
            bool value;
            if(helpers::fromStringValue(externalVariable.getValue(),value)){
                int success =  yr_rules_define_boolean_variable(rules,externalVariable.getIdentifier().c_str(),value);
                LogInfo << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
                rule_version++;
                return (ERROR_SUCCESS ==success);
            }
        }
        else if( externalVariable.getType() == "string"){
            int success =  yr_rules_define_string_variable(rules,externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }else{
            //std::cout << "default\n"; // no error
            return false;
        }
    }
    else{
        return false;
    }
    return false;
}

YaraScanner Manager::getScanner(long id){
    scanner_container_it scit = scanners.find(id);
    if (scit != scanners.end()){
        return scit->second;
    }

    YaraScanner yscanner(rule_version);

    int result = yr_scanner_create(rules, &yscanner.scanner);
    if (result != ERROR_SUCCESS){
        LogError << "Failed to create scanner" << result;
        yscanner.scanner = nullptr;
        yscanner.rule_version = -1;
        return yscanner;
    }
    scanners.insert(std::pair{id,yscanner});
    LogInfo << "get_scanner created with id:" << id;
    return yscanner;
}

// called from response thread
std::vector<YaraInfo> Manager::scanFile(const std::string& filename,long scanner_id){
    std::vector<YaraInfo> allYaraInfo;

    yaratl.init(this);
    int result = yr_scanner_scan_file(yaratl.get_scanner(scanner_id), filename.c_str());

    if (yaratl.yaraInfo.matched_rules.size() > 0) {
        allYaraInfo.push_back(yaratl.yaraInfo);
        for (auto m : allYaraInfo){
            for (auto r : m.matched_rules){
                std::cout << r << std::endl;
            }
        }
    }
    return allYaraInfo;
}


void Manager::createCompiler(){
    int create = yr_compiler_create(&compiler);
    startupSuccess = (create == ERROR_SUCCESS);
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
