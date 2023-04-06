/**
* Yara Rest Server
* A simple Yara Rest server
*
* The version of the OpenAPI document: 0.0.1
* Contact: david@turland.org
* NOTE: 
* class name retained as DefaultApiImpl to ease diff'ing with the generated gen/impl/DefaultApiImpl.h
*/

#include "DefaultApiImpl.h"
#include "Helpers.h"
#include "YaraHelpers.hpp"
#include "ScanResult.h"
#include <iostream>
#include <thread>
#include <chrono>
#include "simple_cpp_logger/Logger.h"

namespace org {
namespace turland {
namespace yara {
namespace api {

using namespace std::chrono_literals;
using namespace org::turland::yara::model;

DefaultApiImpl::DefaultApiImpl(const std::shared_ptr<Pistache::Rest::Router>& rtr,
                            org::turland::yara::Manager& _yara)
    : DefaultApi(rtr),yara(_yara)
{
}

void DefaultApiImpl::externalvar(const ExternalVariable &externalVariable, Pistache::Http::ResponseWriter &response) {
    if(yara.defineExternal(externalVariable)){
        response.send(Pistache::Http::Code::Ok, "ExternalVariable defined \n");    
    }else{
        response.send(Pistache::Http::Code::Not_Acceptable, "ExternalVariable not defined \n");
    }
}
void DefaultApiImpl::get_info(Pistache::Http::ResponseWriter &response) {
    InfoResult info;
    nlohmann::json j = info;
    response.send(Pistache::Http::Code::Ok, j.dump());
}
void DefaultApiImpl::rules_compile_post(const RuleFiles &ruleFiles, Pistache::Http::ResponseWriter &response) {
    for(auto rulefile : ruleFiles.getRules()){
        const char *ns = rulefile.rNamespaceIsSet()?rulefile.getRNamespace().c_str():nullptr;
        if(!yara.compileRulesFromFile(rulefile.getFilepath(),ns)){
            response.send(Pistache::Http::Code::Method_Not_Allowed, "rules_compile_put failed\n");
        }
    }
    response.send(Pistache::Http::Code::Ok, "rules_compile_put all compiled \n");
}
void DefaultApiImpl::rules_load_post(const std::string &filename, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Not_Implemented, "work in progress\n");
}
void DefaultApiImpl::rules_save_put(const std::string &filename, Pistache::Http::ResponseWriter &response) {
    printf("DefaultApiImpl::rules_save_put!\n");
    response.send(Pistache::Http::Code::Not_Implemented, "work in progress\n");
}
void DefaultApiImpl::scanfile_post(const ScanFile &scanFile, Pistache::Http::ResponseWriter &response) {
        std::thread::id this_id = std::this_thread::get_id();
    ScanResult sr;
    std::vector<org::turland::yara::YaraInfo> yis = yara.scanFile(scanFile.getFilename(),scanFile.getScannerid());
    for (auto m : yis){
        for (auto r : m.matched_rules){
            LogInfo << "scanner_scanfile_post" << r;
        }
    }
    for(auto yi : yis){
      sr.setRules(yi.matched_rules);
    }
    nlohmann::json j = sr;
    response.send(Pistache::Http::Code::Ok, j.dump());
    //to_json(j,sr);
    //Pistache::Http::ResponseStream stream = response.stream(Pistache::Http::Code::Ok);
    //stream << j.;
    //response.send(Pistache::Http::Code::Ok, j.dump());
}

} //api
} //yara
} //turland
} //org

