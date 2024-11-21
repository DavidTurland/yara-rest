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


#include "Error.h"
#include "Helpers.h"

#include <sstream>

namespace org::turland::yara::model
{

Error::Error()
{
    m_Code = 0;
    m_Message = "";
    
}

void Error::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::turland::yara::helpers::ValidationException(msg.str());
    }
}

bool Error::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool Error::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "Error" : pathPrefix;

            
    return success;
}

bool Error::operator==(const Error& rhs) const
{
    return
    
    
    (getCode() == rhs.getCode())
     &&
    
    (getMessage() == rhs.getMessage())
    
    
    ;
}

bool Error::operator!=(const Error& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const Error& o)
{
    j = nlohmann::json::object();
    j["code"] = o.m_Code;
    j["message"] = o.m_Message;
    
}

void from_json(const nlohmann::json& j, Error& o)
{
    j.at("code").get_to(o.m_Code);
    j.at("message").get_to(o.m_Message);
    
}

int32_t Error::getCode() const
{
    return m_Code;
}
void Error::setCode(int32_t const value)
{
    m_Code = value;
}
std::string Error::getMessage() const
{
    return m_Message;
}
void Error::setMessage(std::string const& value)
{
    m_Message = value;
}


} // namespace org::turland::yara::model

