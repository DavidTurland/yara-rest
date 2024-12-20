/**
* Yara REST Server
* A Yara REST server
*
* The version of the OpenAPI document: 0.4.0
* Contact: david@turland.org
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "Meta.h"
#include "Helpers.h"

#include <sstream>

namespace org::turland::yara::model
{

Meta::Meta()
{
    m_Name = "";
    m_NameIsSet = false;
    
}

void Meta::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::turland::yara::helpers::ValidationException(msg.str());
    }
}

bool Meta::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool Meta::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "Meta" : pathPrefix;

        
    return success;
}

bool Meta::operator==(const Meta& rhs) const
{
    return
    
    
    
    ((!nameIsSet() && !rhs.nameIsSet()) || (nameIsSet() && rhs.nameIsSet() && getName() == rhs.getName()))
    
    ;
}

bool Meta::operator!=(const Meta& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const Meta& o)
{
    j = nlohmann::json::object();
    if(o.nameIsSet())
        j["name"] = o.m_Name;
    
}

void from_json(const nlohmann::json& j, Meta& o)
{
    if(j.find("name") != j.end())
    {
        j.at("name").get_to(o.m_Name);
        o.m_NameIsSet = true;
    } 
    
}

std::string Meta::getName() const
{
    return m_Name;
}
void Meta::setName(std::string const& value)
{
    m_Name = value;
    m_NameIsSet = true;
}
bool Meta::nameIsSet() const
{
    return m_NameIsSet;
}
void Meta::unsetName()
{
    m_NameIsSet = false;
}


} // namespace org::turland::yara::model

