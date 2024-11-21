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
 * Rule.h
 *
 * 
 */

#ifndef Rule_H_
#define Rule_H_


#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>

namespace org::turland::yara::model
{

/// <summary>
/// 
/// </summary>
class  Rule
{
public:
    Rule();
    virtual ~Rule() = default;


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

    bool operator==(const Rule& rhs) const;
    bool operator!=(const Rule& rhs) const;

    /////////////////////////////////////////////
    /// Rule members

    /// <summary>
    /// 
    /// </summary>
    std::string getIdentifier() const;
    void setIdentifier(std::string const& value);
    bool identifierIsSet() const;
    void unsetIdentifier();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getTags() const;
    void setTags(std::vector<std::string> const& value);
    bool tagsIsSet() const;
    void unsetTags();
    /// <summary>
    /// 
    /// </summary>
    std::map<std::string, std::string> getMeta() const;
    void setMeta(std::map<std::string, std::string> const& value);
    bool metaIsSet() const;
    void unsetMeta();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getStrings() const;
    void setStrings(std::vector<std::string> const& value);
    bool stringsIsSet() const;
    void unsetStrings();
    /// <summary>
    /// 
    /// </summary>
    std::string getRNamespace() const;
    void setRNamespace(std::string const& value);
    bool rNamespaceIsSet() const;
    void unsetr_namespace();

    friend  void to_json(nlohmann::json& j, const Rule& o);
    friend  void from_json(const nlohmann::json& j, Rule& o);
protected:
    std::string m_Identifier;
    bool m_IdentifierIsSet;
    std::vector<std::string> m_Tags;
    bool m_TagsIsSet;
    std::map<std::string, std::string> m_Meta;
    bool m_MetaIsSet;
    std::vector<std::string> m_Strings;
    bool m_StringsIsSet;
    std::string m_r_namespace;
    bool m_r_namespaceIsSet;
    
};

} // namespace org::turland::yara::model

#endif /* Rule_H_ */
