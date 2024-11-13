/**
* Yara Rest Server
* A simple Yara Rest server
*
* The version of the OpenAPI document: 0.0.1
* Contact: david@turland.org
* NOTE: 
* class name retained as DefaultApiImpl to ease diff'ing with the generated gen/impl/DefaultApiImpl.h
*/
#include <iostream>
#include <thread>
#include <chrono>

#include <glog/logging.h>

#include "DefaultApiImpl.h"
#include "Helpers.h"
#include "YaraHelpers.hpp"
#include "ScanResult.h"

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
        LOG(INFO)  << "rules_compile_post  rNamespaceIsSet " << rulefile.rNamespaceIsSet();
        std::string ns{};
        //const char *ns = rulefile.rNamespaceIsSet()?rulefile.getRNamespace().c_str():nullptr;
        if(rulefile.rNamespaceIsSet()){
            ns =  rulefile.getRNamespace();
            LOG(INFO)  << "rules_compile_post  namespace " << rulefile.getRNamespace() << ", ns.c_str " << ns.c_str();

        }
        if(!yara.compileRulesFromFile(rulefile.getFilepath(),ns.c_str())){
            response.send(Pistache::Http::Code::Method_Not_Allowed, "rules_compile_post failed\n");
        }
    }
    response.send(Pistache::Http::Code::Ok, "rules_compile_post all files compiled \n");
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
            LOG(INFO) << "scanner_scanfile_post" << r;
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

void DefaultApiImpl::scanstring_post(const ScanString &scanString, Pistache::Http::ResponseWriter &response) {
        std::thread::id this_id = std::this_thread::get_id();
    ScanResult sr;
    std::vector<org::turland::yara::YaraInfo> yis = yara.scanString(scanString.getData(),scanString.getLength(),scanString.getScannerid());
    for (auto m : yis){
        for (auto r : m.matched_rules){
            LOG(INFO)  << "scanner_scanfile_post" << r;
        }
    }
    for(auto yi : yis){
      sr.setRules(yi.matched_rules);
    }
    nlohmann::json j = sr;
    response.send(Pistache::Http::Code::Ok, j.dump());
}

} //api
} //yara
} //turland
} //org

