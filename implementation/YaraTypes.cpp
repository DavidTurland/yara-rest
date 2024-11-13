#include <glog/logging.h>

#include "YaraTypes.h"
#include "Helpers.h"
#include "pistache/http_defs.h"

namespace org::turland::yara
{
//using namespace org::openapitools::server;
YaraCompiler::YaraCompiler(int &_rule_version):compiler{nullptr},rule_version(_rule_version){}

 bool YaraCompiler::create(){
    if(nullptr != compiler){
        return false;
    }
    int create = yr_compiler_create(&compiler);
    DLOG(INFO) << "create compiler witth success " << create;
    return create;
 }

YaraCompiler::~YaraCompiler(){
    yr_compiler_destroy(compiler);   
}

bool YaraCompiler::destroy(){
    yr_compiler_destroy(compiler);
    compiler = nullptr;
    return true;
}

int YaraCompiler::add_file(FILE* rule_file, const char * ns, const char *error_file){
    if( get_rules_called){
        throw Pistache::Http::HttpError(404,"add_file but get_rules already called");
    }
    //if( add_called){
    //    throw Pistache::Http::HttpError(404,"add_XXX already called");
    //}    
    int result = yr_compiler_add_file(compiler, rule_file, ns, error_file);
    DLOG(INFO) << "add_file yr_compiler_add_file with success " << result;
    add_called = true;
    return result;
}

int YaraCompiler::get_rules(YR_RULES** rules){
    if(!add_called){
        throw std::runtime_error("Attempting to use rules before creation");
    }
    if(yr_compiler_get_rules(compiler,rules)){
        get_rules_called = true;
        return true;
    }
    return false;
}

bool YaraCompiler::defineExternal(const ExternalVariable &externalVariable){
    if( externalVariable.getType() == "integer"){
        int32_t value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_integer_variable(compiler,externalVariable.getIdentifier().c_str(),value);
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "float"){
        float value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_float_variable(compiler,externalVariable.getIdentifier().c_str(),value);
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "boolean"){
        bool value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_boolean_variable(compiler,externalVariable.getIdentifier().c_str(),value);
            DLOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "string"){
        int success =  yr_compiler_define_string_variable(compiler,externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
        rule_version++;
        return (ERROR_SUCCESS ==success);
    }else{
        //std::cout << "default\n"; // no error
        return false;
    }
    return false;
}


bool YaraScanner::defineExternal(const ExternalVariable &externalVariable){

    if( externalVariable.getType() == "integer"){
        int32_t value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_integer_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "float"){
        float value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_float_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "boolean"){
        bool value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_boolean_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            DLOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
            rule_version++;
            return (ERROR_SUCCESS ==success);
        }
    }
    else if( externalVariable.getType() == "string"){
        int success =  yr_scanner_define_string_variable(scanner,externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
        rule_version++;
        return (ERROR_SUCCESS ==success);
    }else{
        //std::cout << "default\n"; // no error
        return false;
    }
    return false;
}
}