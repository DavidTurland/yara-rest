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
 * Meta.h
 *
 * 
 */

#ifndef Meta_H_
#define Meta_H_


#include <string>
#include <nlohmann/json.hpp>

namespace org::turland::yara::model
{

/// <summary>
/// 
/// </summary>
class  Meta
{
public:
    Meta();
    virtual ~Meta() = default;


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

    bool operator==(const Meta& rhs) const;
    bool operator!=(const Meta& rhs) const;

    /////////////////////////////////////////////
    /// Meta members

    /// <summary>
    /// 
    /// </summary>
    std::string getName() const;
    void setName(std::string const& value);
    bool nameIsSet() const;
    void unsetName();

    friend  void to_json(nlohmann::json& j, const Meta& o);
    friend  void from_json(const nlohmann::json& j, Meta& o);
protected:
    std::string m_Name;
    bool m_NameIsSet;
    
};

} // namespace org::turland::yara::model

#endif /* Meta_H_ */
