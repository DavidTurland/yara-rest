#ifndef YARA_TYPES_H
#define YARA_TYPES_H
// #include "YaraTypes.h"
#include <vector>
#include <iostream>

#include "pistache/http_defs.h"

#include "Rule.h"
#include "YaraHelpers.h"

namespace org::turland::yara
{
namespace modell = org::turland::yara::model;

struct YaraScanResultRules{
    /**
     * provides an aceesible  vector rules
     * unfortunately the (pistache)ScanResult class does not offer reference access to its Rules
     */
    std::vector<modell::Rule> matched_rules;
};


struct HttpYaraError : public Pistache::Http::HttpError
{
    HttpYaraError(Pistache::Http::Code code, std::string reason, int yara_error_code):
        HttpError(code,reason),yara_error_code_(yara_error_code){
        std::ostringstream ss;
        ss << "Yara Error " << yara_error_code_ << ", " << getYaraErrorMsg(yara_error_code_) << ", because " << reason;
        better_reason_ = ss.str();
        LOG(ERROR) << better_reason_;

    }
    HttpYaraError(int code, std::string reason, int yara_error_code):
        HttpError(code,reason),yara_error_code_(yara_error_code){
        std::ostringstream ss;
        ss << "Yara Error " << yara_error_code_ << ", " << getYaraErrorMsg(yara_error_code_) << ", because " << reason;
        better_reason_ = ss.str();
        LOG(ERROR) << better_reason_;
    }

    ~HttpYaraError() noexcept override = default;
    std::string reason() const { return better_reason_; }
    const char* what() const noexcept override { return better_reason_.c_str(); }


private:
    int yara_error_code_;
    std::string better_reason_;
};

} // namespace org::turland::yara
#endif
