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
/*
 * ScanString.h
 *
 * scan string with a scanner( referenced by id)
 */

#ifndef ScanString_H_
#define ScanString_H_


#include <string>
#include <nlohmann/json.hpp>

namespace org::turland::yara::model
{

/// <summary>
/// scan string with a scanner( referenced by id)
/// </summary>
class  ScanString
{
public:
    ScanString();
    virtual ~ScanString() = default;


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

    bool operator==(const ScanString& rhs) const;
    bool operator!=(const ScanString& rhs) const;

    /////////////////////////////////////////////
    /// ScanString members

    /// <summary>
    /// scanner id to use (default 0)
    /// </summary>
    int32_t getScannerid() const;
    void setScannerid(int32_t const value);
    bool scanneridIsSet() const;
    void unsetScannerid();
    /// <summary>
    /// 
    /// </summary>
    std::string getData() const;
    void setData(std::string const& value);
    /// <summary>
    /// length of data. If ommitted then data is assumed to be                  a string and length &#x3D;&#x3D; strlen ( you have been warned) 
    /// </summary>
    int32_t getLength() const;
    void setLength(int32_t const value);
    bool lengthIsSet() const;
    void unsetLength();

    friend  void to_json(nlohmann::json& j, const ScanString& o);
    friend  void from_json(const nlohmann::json& j, ScanString& o);
protected:
    int32_t m_Scannerid;
    bool m_ScanneridIsSet;
    std::string m_Data;

    int32_t m_Length;
    bool m_LengthIsSet;
    
};

} // namespace org::turland::yara::model

#endif /* ScanString_H_ */
