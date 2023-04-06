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


#include "ScanResult.h"
#include "Helpers.h"

#include <sstream>

namespace org::turland::yara::model
{

ScanResult::ScanResult()
{
    m_Returncode = "";
    m_RulesIsSet = false;
    
}

void ScanResult::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::turland::yara::helpers::ValidationException(msg.str());
    }
}

bool ScanResult::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ScanResult::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ScanResult" : pathPrefix;

             
    if (rulesIsSet())
    {
        const std::vector<std::string>& value = m_Rules;
        const std::string currentValuePath = _pathPrefix + ".rules";
                
        
        if (value.size() > 5)
        {
            success = false;
            msg << currentValuePath << ": must have at most 5 elements;";
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

bool ScanResult::operator==(const ScanResult& rhs) const
{
    return
    
    
    (getReturncode() == rhs.getReturncode())
     &&
    
    
    ((!rulesIsSet() && !rhs.rulesIsSet()) || (rulesIsSet() && rhs.rulesIsSet() && getRules() == rhs.getRules()))
    
    ;
}

bool ScanResult::operator!=(const ScanResult& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ScanResult& o)
{
    j = nlohmann::json();
    j["returncode"] = o.m_Returncode;
    if(o.rulesIsSet() || !o.m_Rules.empty())
        j["rules"] = o.m_Rules;
    
}

void from_json(const nlohmann::json& j, ScanResult& o)
{
    j.at("returncode").get_to(o.m_Returncode);
    if(j.find("rules") != j.end())
    {
        j.at("rules").get_to(o.m_Rules);
        o.m_RulesIsSet = true;
    } 
    
}

std::string ScanResult::getReturncode() const
{
    return m_Returncode;
}
void ScanResult::setReturncode(std::string const& value)
{
    m_Returncode = value;
}
std::vector<std::string> ScanResult::getRules() const
{
    return m_Rules;
}
void ScanResult::setRules(std::vector<std::string> const& value)
{
    m_Rules = value;
    m_RulesIsSet = true;
}
bool ScanResult::rulesIsSet() const
{
    return m_RulesIsSet;
}
void ScanResult::unsetRules()
{
    m_RulesIsSet = false;
}


} // namespace org::turland::yara::model

