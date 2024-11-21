/**
* Yara Rest Server
* A simple Yara Rest server
*
* The version of the OpenAPI document: 0.3.0
* Contact: david@turland.org
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * DefaultApi.h
 *
 * 
 */

#ifndef DefaultApi_H_
#define DefaultApi_H_


#include "ApiBase.h"

#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>

#include <optional>
#include <utility>

#include "ExternalVariable.h"
#include "InfoResult.h"
#include "RuleFiles.h"
#include "ScanFile.h"
#include "ScanResult.h"
#include "ScanString.h"
#include <string>

namespace org::turland::yara::api
{

class  DefaultApi : public ApiBase {
public:
    explicit DefaultApi(const std::shared_ptr<Pistache::Rest::Router>& rtr);
    ~DefaultApi() override = default;
    void init() override;

    static const std::string base;

private:
    void setupRoutes();

    void externalvar_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void get_info_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void rules_compile_post_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void rules_load_post_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void rules_save_put_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void scanfile_post_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void scanstring_post_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void default_api_default_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);

    /// <summary>
    /// Helper function to handle unexpected Exceptions during Parameter parsing and validation.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual void handleParsingException(const std::exception& ex, Pistache::Http::ResponseWriter &response) const noexcept;

    /// <summary>
    /// Helper function to handle unexpected Exceptions during Parameter parsing and validation.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual std::pair<Pistache::Http::Code, std::string> handleParsingException(const std::exception& ex) const noexcept;

    /// <summary>
    /// Helper function to handle unexpected Exceptions during processing of the request in handler functions.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual void handleOperationException(const std::exception& ex, Pistache::Http::ResponseWriter &response) const noexcept;

    /// <summary>
    /// Helper function to handle unexpected Exceptions during processing of the request in handler functions.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual std::pair<Pistache::Http::Code, std::string> handleOperationException(const std::exception& ex) const noexcept;

    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// defines a new external variable
    /// </remarks>
    /// <param name="externalVariable">variable to be defined</param>
    virtual void externalvar(const org::turland::yara::model::ExternalVariable &externalVariable, Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
    virtual void get_info(Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// comiles rule files, each with optional namespace
    /// </remarks>
    /// <param name="ruleFiles">variable to be defined</param>
    virtual void rules_compile_post(const org::turland::yara::model::RuleFiles &ruleFiles, Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// loads presaved compiled rules
    /// </remarks>
    /// <param name="filename">filename to load compiled rules from</param>
    virtual void rules_load_post(const std::string &filename, Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// saves precompiled rules
    /// </remarks>
    /// <param name="filename">filename to save compiled rules to</param>
    virtual void rules_save_put(const std::string &filename, Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// scan a file using a specific scanner
    /// </summary>
    /// <remarks>
    /// scans a file using a specific scanner 
    /// </remarks>
    /// <param name="scanFile">A JSON object containing a scan file request</param>
    virtual void scanfile_post(const org::turland::yara::model::ScanFile &scanFile, Pistache::Http::ResponseWriter &response) = 0;
    /// <summary>
    /// scan a string using a specific scanner
    /// </summary>
    /// <remarks>
    /// scans a string using a specific scanner 
    /// </remarks>
    /// <param name="scanString">A JSON object containing a scan string request</param>
    virtual void scanstring_post(const org::turland::yara::model::ScanString &scanString, Pistache::Http::ResponseWriter &response) = 0;

};

} // namespace org::turland::yara::api

#endif /* DefaultApi_H_ */

