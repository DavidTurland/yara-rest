/**
* Yara Rest Server
* A simple Yara Rest server
*
* The version of the OpenAPI document: 0.0.1
* Contact: david@turland.org
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

/*
* DefaultApiImpl.h
*
*
*/

#ifndef DEFAULT_API_IMPL_H_
#define DEFAULT_API_IMPL_H_


#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>
#include <optional>

#include <DefaultApi.h>
#include <thread>
#include <yara.h>
#include "YaraManager.h"
#include "Error.h"
#include "ExternalVariable.h"
#include "ScanFile.h"
#include "ScanResult.h"
#include <string>

/**
 * NOTE: 
 * class name retained as DefaultApiImpl to ease diff'ing with the generated gen/impl/DefaultApiImpl.h
 * 
 * 
*/
namespace org::turland::yara::api
{

using namespace org::turland::yara::model;

class  DefaultApiImpl : public org::turland::yara::api::DefaultApi {
public:
    explicit DefaultApiImpl(const std::shared_ptr<Pistache::Rest::Router>& rtr,
                            org::turland::yara::Manager& yara);
    ~DefaultApiImpl() override = default;
    void externalvar(const ExternalVariable &externalVariable, Pistache::Http::ResponseWriter &response);
    void get_info(Pistache::Http::ResponseWriter &response);
    void rules_compile_post(const RuleFiles &ruleFiles, Pistache::Http::ResponseWriter &response);
    void rules_load_post(const std::string &filename, Pistache::Http::ResponseWriter &response);
    void rules_save_put(const std::string &filename, Pistache::Http::ResponseWriter &response);
    void scanfile_post(const ScanFile &scanFile, Pistache::Http::ResponseWriter &response);

private:
    org::turland::yara::Manager& yara;
};

} // namespace org::turland::yara::api



#endif
