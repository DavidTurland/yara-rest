#include <glog/logging.h>
#include "pistache/http_defs.h"

#include "YaraScanner.h"
#include "Helpers.h"

namespace org::turland::yara
{

bool YaraScanner::defineExternal(const modell::ExternalVariable &externalVariable){

    if( externalVariable.getType() == "integer"){
        int32_t value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_integer_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            if (ERROR_SUCCESS !=success){
                throw Pistache::Http::HttpError(
                    Pistache::Http::Code::Bad_Request,  // CODE 400
                    "failed call to yr_scanner_define_integer_variable");
            }
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "float"){
        float value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_float_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            if (ERROR_SUCCESS !=success){
                throw Pistache::Http::HttpError(
                    Pistache::Http::Code::Bad_Request,  // CODE 400
                    "failed call to yr_scanner_define_float_variable");
            }
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "boolean"){
        bool value;
        if(helpers::fromStringValue(externalVariable.getValue(),value)){
            int success =  yr_scanner_define_boolean_variable(scanner,externalVariable.getIdentifier().c_str(),value);
            if (ERROR_SUCCESS !=success){
                throw Pistache::Http::HttpError(
                    Pistache::Http::Code::Bad_Request,  // CODE 400
                    "failed call to yr_scanner_define_boolean_variable");
            }
            DLOG(INFO) << "define_external " << externalVariable.getType() <<  externalVariable.getIdentifier();// no error
            rule_version++;
            return true;
        }
    }
    else if( externalVariable.getType() == "string"){
        int success =  yr_scanner_define_string_variable(scanner,externalVariable.getIdentifier().c_str(),externalVariable.getValue().c_str());
            if (ERROR_SUCCESS !=success){
                throw Pistache::Http::HttpError(
                    Pistache::Http::Code::Bad_Request,  // CODE 400
                    "failed call to yr_scanner_define_string_variable");
            }
            rule_version++;
            return true;
    }else{
        throw Pistache::Http::HttpError(
            Pistache::Http::Code::Bad_Request,
            "unpossible: defineExternal");
    }
    return false;
}

} //namespace org::turland::yara
