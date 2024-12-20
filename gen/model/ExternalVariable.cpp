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


#include "ExternalVariable.h"
#include "Helpers.h"

#include <sstream>

namespace org::turland::yara::model
{

ExternalVariable::ExternalVariable()
{
    m_Component = "";
    m_Type = "";
    m_Identifier = "";
    m_Value = "";
    m_Scanner = 0L;
    m_ScannerIsSet = false;
    
}

void ExternalVariable::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::turland::yara::helpers::ValidationException(msg.str());
    }
}

bool ExternalVariable::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ExternalVariable::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ExternalVariable" : pathPrefix;

                        
    return success;
}

bool ExternalVariable::operator==(const ExternalVariable& rhs) const
{
    return
    
    
    (getComponent() == rhs.getComponent())
     &&
    
    (getType() == rhs.getType())
     &&
    
    (getIdentifier() == rhs.getIdentifier())
     &&
    
    (getValue() == rhs.getValue())
     &&
    
    
    ((!scannerIsSet() && !rhs.scannerIsSet()) || (scannerIsSet() && rhs.scannerIsSet() && getScanner() == rhs.getScanner()))
    
    ;
}

bool ExternalVariable::operator!=(const ExternalVariable& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ExternalVariable& o)
{
    j = nlohmann::json::object();
    j["component"] = o.m_Component;
    j["type"] = o.m_Type;
    j["identifier"] = o.m_Identifier;
    j["value"] = o.m_Value;
    if(o.scannerIsSet())
        j["scanner"] = o.m_Scanner;
    
}

void from_json(const nlohmann::json& j, ExternalVariable& o)
{
    j.at("component").get_to(o.m_Component);
    j.at("type").get_to(o.m_Type);
    j.at("identifier").get_to(o.m_Identifier);
    j.at("value").get_to(o.m_Value);
    if(j.find("scanner") != j.end())
    {
        j.at("scanner").get_to(o.m_Scanner);
        o.m_ScannerIsSet = true;
    } 
    
}

std::string ExternalVariable::getComponent() const
{
    return m_Component;
}
void ExternalVariable::setComponent(std::string const& value)
{
    m_Component = value;
}
std::string ExternalVariable::getType() const
{
    return m_Type;
}
void ExternalVariable::setType(std::string const& value)
{
    m_Type = value;
}
std::string ExternalVariable::getIdentifier() const
{
    return m_Identifier;
}
void ExternalVariable::setIdentifier(std::string const& value)
{
    m_Identifier = value;
}
std::string ExternalVariable::getValue() const
{
    return m_Value;
}
void ExternalVariable::setValue(std::string const& value)
{
    m_Value = value;
}
int64_t ExternalVariable::getScanner() const
{
    return m_Scanner;
}
void ExternalVariable::setScanner(int64_t const value)
{
    m_Scanner = value;
    m_ScannerIsSet = true;
}
bool ExternalVariable::scannerIsSet() const
{
    return m_ScannerIsSet;
}
void ExternalVariable::unsetScanner()
{
    m_ScannerIsSet = false;
}


} // namespace org::turland::yara::model

