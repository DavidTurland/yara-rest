#include <glog/logging.h>
#include "pistache/http_defs.h"

#include "YaraCompiler.h"
#include "YaraTypes.h"
#include "Helpers.h"
using namespace std::string_literals;
namespace org::turland::yara
{

YaraCompiler::YaraCompiler(int &_rule_version):compiler{nullptr},
    rule_version(_rule_version),
    _compiler_get_rules_called{false},
    _compiler_add_called{false},
    _compiler_broken{false}{
}

YaraCompiler::~YaraCompiler(){
    if(nullptr != compiler){
        yr_compiler_destroy(compiler);
    }
}

bool YaraCompiler::destroy(){
    yr_compiler_destroy(compiler);
    return true;
}

YR_COMPILER* YaraCompiler::_get_compiler(){
    if(nullptr == compiler){
        int result = yr_compiler_create(&compiler);
        if (result != ERROR_SUCCESS){
            _compiler_broken = true;
            LOG(ERROR) << "_get_compiler Failed yr_compiler_create with " << result;
            throw Pistache::Http::HttpError(
                Pistache::Http::Code::Precondition_Failed, // CODE 412
                "failed call to yr_compiler_create");
        }
    }
    return compiler;
}

int YaraCompiler::add_file(FILE* rule_file, const char * ns, const char *error_file){
    if( _compiler_get_rules_called){
        LOG(ERROR) << "add_file but get_rules already called";
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Precondition_Failed, // CODE 412
            "add_file but get_rules already called");
    }
    if( _compiler_broken){
        LOG(ERROR) << "add_file but broken by previous error";
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Internal_Server_Error, // CODE 500
            "add_file but broken by previous error");
    }
  
    int result = yr_compiler_add_file(_get_compiler(), rule_file, ns, error_file);
    if (result != ERROR_SUCCESS){
        // check result before deciding broken = true;
        _compiler_broken = true;
        LOG(ERROR) << "add_file Failed yr_compiler_create";
        throw HttpYaraError(
            Pistache::Http::Code::Precondition_Failed, // CODE 412
            "failed call to yr_compiler_add_file",
            result);
    }
    DLOG(INFO) << "add_file yr_compiler_add_file with success " << result;
    _compiler_add_called = true;
    return result;
}

int YaraCompiler::get_rules(YR_RULES** rules){
    if(!_compiler_add_called){
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Precondition_Failed, // CODE 412
            "get rules called but no rules added");        
    }
    if( _compiler_broken){
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Internal_Server_Error, // CODE 500
            "get_rules but broken by previous error");
    }
    int result = yr_compiler_get_rules(_get_compiler(),rules);
    if (result != ERROR_SUCCESS){
        // check result before deciding broken = true;
        _compiler_broken - true;
        LOG(ERROR) << "get_rules Failed yr_compiler_get_rules";
        throw HttpYaraError(
            Pistache::Http::Code::Internal_Server_Error,  // CODE 500
            "failed call to yr_compiler_get_rules",
            result);
    }    
    _compiler_get_rules_called = true;
    return true;
}

bool YaraCompiler::defineExternal(const modell::ExternalVariable &externalVariable){
    if( _compiler_get_rules_called){
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Precondition_Failed, // CODE 412
            "defineExternal but get_rules already called");
    }    
    if( _compiler_broken){
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Internal_Server_Error, // CODE 500
            "defineExternal but broken by previous error");
    }    
    if( externalVariable.getType() == "integer"){
        int32_t value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_integer_variable(_get_compiler(),externalVariable.getIdentifier().c_str(),value);
            if (ERROR_SUCCESS !=success){
                // check result before deciding broken = true;
                _compiler_broken - true;
                throw HttpYaraError(
                    Pistache::Http::Code::Bad_Request,  // CODE 400
                    "failed call to yr_compiler_define_integer_variable",
                    success);
            }
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "float"){
        float value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_float_variable(_get_compiler(),externalVariable.getIdentifier().c_str(),value);
            if (ERROR_SUCCESS !=success){
                // check result before deciding broken = true;
                _compiler_broken - true;
                throw HttpYaraError(
                    Pistache::Http::Code::Bad_Request,// CODE 400
                    "failed call to yr_compiler_define_float_variable",
                    success);
            }
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "boolean"){
        bool value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_compiler_define_boolean_variable(_get_compiler(),externalVariable.getIdentifier().c_str(),value);
            DLOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
            if (ERROR_SUCCESS !=success){
                // check result before deciding broken = true;
                _compiler_broken - true;
                throw HttpYaraError(
                    Pistache::Http::Code::Bad_Request,// CODE 400
                    "failed call to yr_compiler_define_boolean_variable",
                    success);
            }
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "string"){
        int success =  yr_compiler_define_string_variable(_get_compiler(),externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            if (ERROR_SUCCESS !=success){
                // check result before deciding broken = true;
                _compiler_broken - true;
                throw HttpYaraError(
                    Pistache::Http::Code::Bad_Request,   // CODE 400
                    "failed call to yr_compiler_define_string_variable",
                    success);
            }
            rule_version++;
            return true;
    }else{
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Bad_Request,    // CODE 400
            "unpossible type "s + externalVariable.getType() + " passed to defineExternal");
    }
    return false;
}

}

