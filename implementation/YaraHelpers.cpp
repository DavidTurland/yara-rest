#include <glog/logging.h>

#include "YaraHelpers.hpp"

namespace org::turland::yara
{

void log_rule(const org::turland::yara::model::Rule& rule){
    // --v=1        will not log VLOG(2)
    // -e GLOG_v=1
    if (VLOG_IS_ON(1)) {
        VLOG(1)  << "identifier: " << rule.getIdentifier();
        for(auto const& [key, val] : rule.getMeta()){
            VLOG(1) << ", meta key: " << key << ", value: "<< val << std::endl;
        }
    }
}
} // namespace org::turland::yara