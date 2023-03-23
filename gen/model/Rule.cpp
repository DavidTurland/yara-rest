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


#include "Rule.h"
#include "Helpers.h"

#include <sstream>

namespace org::turland::yara::model
{

Rule::Rule()
{
    m_Identifier = "";
    m_IdentifierIsSet = false;
    m_TagsIsSet = false;
    m_MetaIsSet = false;
    m_StringsIsSet = false;
    m_r_namespaceIsSet = false;
    
}

void Rule::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::turland::yara::helpers::ValidationException(msg.str());
    }
}

bool Rule::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool Rule::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "Rule" : pathPrefix;

             
    if (tagsIsSet())
    {
        const std::vector<std::string>& value = m_Tags;
        const std::string currentValuePath = _pathPrefix + ".tags";
                
        
        if (value.size() > 3)
        {
            success = false;
            msg << currentValuePath << ": must have at most 3 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const std::string& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        
 
                i++;
            }
        }

    }
         
    if (metaIsSet())
    {
        const std::vector<org::turland::yara::model::Meta>& value = m_Meta;
        const std::string currentValuePath = _pathPrefix + ".meta";
                
        
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const org::turland::yara::model::Meta& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".meta") && success;
 
                i++;
            }
        }

    }
         
    if (stringsIsSet())
    {
        const std::vector<std::string>& value = m_Strings;
        const std::string currentValuePath = _pathPrefix + ".strings";
                
        
        if (value.size() > 3)
        {
            success = false;
            msg << currentValuePath << ": must have at most 3 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const std::string& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        
 
                i++;
            }
        }

    }
        
    return success;
}

bool Rule::operator==(const Rule& rhs) const
{
    return
    
    
    
    ((!identifierIsSet() && !rhs.identifierIsSet()) || (identifierIsSet() && rhs.identifierIsSet() && getIdentifier() == rhs.getIdentifier())) &&
    
    
    ((!tagsIsSet() && !rhs.tagsIsSet()) || (tagsIsSet() && rhs.tagsIsSet() && getTags() == rhs.getTags())) &&
    
    
    ((!metaIsSet() && !rhs.metaIsSet()) || (metaIsSet() && rhs.metaIsSet() && getMeta() == rhs.getMeta())) &&
    
    
    ((!stringsIsSet() && !rhs.stringsIsSet()) || (stringsIsSet() && rhs.stringsIsSet() && getStrings() == rhs.getStrings())) &&
    
    
    ((!rNamespaceIsSet() && !rhs.rNamespaceIsSet()) || (rNamespaceIsSet() && rhs.rNamespaceIsSet() && getRNamespace() == rhs.getRNamespace()))
    
    ;
}

bool Rule::operator!=(const Rule& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const Rule& o)
{
    j = nlohmann::json();
    if(o.identifierIsSet())
        j["identifier"] = o.m_Identifier;
    if(o.tagsIsSet() || !o.m_Tags.empty())
        j["tags"] = o.m_Tags;
    if(o.metaIsSet() || !o.m_Meta.empty())
        j["meta"] = o.m_Meta;
    if(o.stringsIsSet() || !o.m_Strings.empty())
        j["strings"] = o.m_Strings;
    if(o.rNamespaceIsSet())
        j["namespace"] = o.m_r_namespace;
    
}

void from_json(const nlohmann::json& j, Rule& o)
{
    if(j.find("identifier") != j.end())
    {
        j.at("identifier").get_to(o.m_Identifier);
        o.m_IdentifierIsSet = true;
    } 
    if(j.find("tags") != j.end())
    {
        j.at("tags").get_to(o.m_Tags);
        o.m_TagsIsSet = true;
    } 
    if(j.find("meta") != j.end())
    {
        j.at("meta").get_to(o.m_Meta);
        o.m_MetaIsSet = true;
    } 
    if(j.find("strings") != j.end())
    {
        j.at("strings").get_to(o.m_Strings);
        o.m_StringsIsSet = true;
    } 
    if(j.find("namespace") != j.end())
    {
        j.at("namespace").get_to(o.m_r_namespace);
        o.m_r_namespaceIsSet = true;
    } 
    
}

std::string Rule::getIdentifier() const
{
    return m_Identifier;
}
void Rule::setIdentifier(std::string const& value)
{
    m_Identifier = value;
    m_IdentifierIsSet = true;
}
bool Rule::identifierIsSet() const
{
    return m_IdentifierIsSet;
}
void Rule::unsetIdentifier()
{
    m_IdentifierIsSet = false;
}
std::vector<std::string> Rule::getTags() const
{
    return m_Tags;
}
void Rule::setTags(std::vector<std::string> const& value)
{
    m_Tags = value;
    m_TagsIsSet = true;
}
bool Rule::tagsIsSet() const
{
    return m_TagsIsSet;
}
void Rule::unsetTags()
{
    m_TagsIsSet = false;
}
std::vector<org::turland::yara::model::Meta> Rule::getMeta() const
{
    return m_Meta;
}
void Rule::setMeta(std::vector<org::turland::yara::model::Meta> const& value)
{
    m_Meta = value;
    m_MetaIsSet = true;
}
bool Rule::metaIsSet() const
{
    return m_MetaIsSet;
}
void Rule::unsetMeta()
{
    m_MetaIsSet = false;
}
std::vector<std::string> Rule::getStrings() const
{
    return m_Strings;
}
void Rule::setStrings(std::vector<std::string> const& value)
{
    m_Strings = value;
    m_StringsIsSet = true;
}
bool Rule::stringsIsSet() const
{
    return m_StringsIsSet;
}
void Rule::unsetStrings()
{
    m_StringsIsSet = false;
}
org::turland::yara::model::Namespace Rule::getRNamespace() const
{
    return m_r_namespace;
}
void Rule::setRNamespace(org::turland::yara::model::Namespace const& value)
{
    m_r_namespace = value;
    m_r_namespaceIsSet = true;
}
bool Rule::rNamespaceIsSet() const
{
    return m_r_namespaceIsSet;
}
void Rule::unsetr_namespace()
{
    m_r_namespaceIsSet = false;
}


} // namespace org::turland::yara::model
