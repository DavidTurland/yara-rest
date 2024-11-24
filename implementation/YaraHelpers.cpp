#include <glog/logging.h>

#include <pistache/http_defs.h>
#include <yara.h>

#include "YaraHelpers.h"

namespace org::turland::yara
{
namespace modell =  org::turland::yara::model;

void log_rules(const std::vector<modell::Rule>& rules){
    // --v=1        will not log VLOG(2)
    // -e GLOG_v=1
    if (VLOG_IS_ON(1)) {
       for (auto r : rules){
        log_rule(r);
       }
    }
}

void log_rule(const modell::Rule& rule){
    // --v=1        will not log VLOG(2)
    // -e GLOG_v=1
    if (VLOG_IS_ON(1)) {
        VLOG(1)  << "identifier: " << rule.getIdentifier();
        for(auto const& [key, val] : rule.getMeta()){
            VLOG(1) << ", meta key: " << key << ", value: "<< val << std::endl;
        }
    }
}


std::string getYaraErrorMsg(int yara_err){
    std::string msg;
    switch (yara_err){
    case ERROR_SUCCESS:
        msg = "ERROR_SUCCESS";
        break;
    case ERROR_INSUFFICIENT_MEMORY:
        msg = "A number of reason but maybe ERROR_INSUFFICIENT_MEMORY";
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
} // namespace org::turland::yara
