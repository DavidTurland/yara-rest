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
 * ScanResult.h
 *
 * 
 */

#ifndef ScanResult_H_
#define ScanResult_H_


#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace org::turland::yara::model
{

/// <summary>
/// 
/// </summary>
class  ScanResult
{
public:
    ScanResult();
    virtual ~ScanResult() = default;


    /// <summary>
    /// Validate the current data in the model. Throws a ValidationException on failure.
    /// </summary>
    void validate() const;

    /// <summary>
    /// Validate the current data in the model. Returns false on error and writes an error
    /// message into the given stringstream.
    /// </summary>
    bool validate(std::stringstream& msg) const;

    /// <summary>
    /// Helper overload for validate. Used when one model stores another model and calls it's validate.
    /// Not meant to be called outside that case.
    /// </summary>
    bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

    bool operator==(const ScanResult& rhs) const;
    bool operator!=(const ScanResult& rhs) const;

    /////////////////////////////////////////////
    /// ScanResult members

    /// <summary>
    /// 
    /// </summary>
    std::string getReturncode() const;
    void setReturncode(std::string const& value);
    bool returncodeIsSet() const;
    void unsetReturncode();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getRules() const;
    void setRules(std::vector<std::string> const& value);
    bool rulesIsSet() const;
    void unsetRules();

    friend  void to_json(nlohmann::json& j, const ScanResult& o);
    friend  void from_json(const nlohmann::json& j, ScanResult& o);
protected:
    std::string m_Returncode;
    bool m_ReturncodeIsSet;
    std::vector<std::string> m_Rules;
    bool m_RulesIsSet;
    
};

} // namespace org::turland::yara::model

#endif /* ScanResult_H_ */
