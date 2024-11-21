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
 * RuleFiles.h
 *
 * Container of Rule files
 */

#ifndef RuleFiles_H_
#define RuleFiles_H_


#include <vector>
#include "RuleFile.h"
#include <nlohmann/json.hpp>

namespace org::turland::yara::model
{

/// <summary>
/// Container of Rule files
/// </summary>
class  RuleFiles
{
public:
    RuleFiles();
    virtual ~RuleFiles() = default;


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

    bool operator==(const RuleFiles& rhs) const;
    bool operator!=(const RuleFiles& rhs) const;

    /////////////////////////////////////////////
    /// RuleFiles members

    /// <summary>
    /// 
    /// </summary>
    std::vector<org::turland::yara::model::RuleFile> getRules() const;
    void setRules(std::vector<org::turland::yara::model::RuleFile> const& value);
    bool rulesIsSet() const;
    void unsetRules();

    friend  void to_json(nlohmann::json& j, const RuleFiles& o);
    friend  void from_json(const nlohmann::json& j, RuleFiles& o);
protected:
    std::vector<org::turland::yara::model::RuleFile> m_Rules;
    bool m_RulesIsSet;
    
};

} // namespace org::turland::yara::model

#endif /* RuleFiles_H_ */
