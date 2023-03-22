#include "ScannerThreadLocal.h"
#include "YaraManager.h"
#include "YaraHelpers.hpp"
#include "yara_scanner_copy.h"
namespace org::turland::yara
{
ScannerThreadLocal::ScannerThreadLocal():manager{}{}

ScannerThreadLocal::~ScannerThreadLocal(){
    for(auto scanner: scanners){
        yr_scanner_destroy(scanner.second.scanner);
    }
}

void ScannerThreadLocal::init(Manager * _manager){
   manager = _manager;
}

YR_SCANNER* ScannerThreadLocal::get_scanner(long id){
    scanner_container_it scit = scanners.find(id);
    if (scit != scanners.end()){
        return scit->second.scanner;
    }
    YaraScanner scanner_golden = manager->getScanner(id);

    YaraScanner yscanner(nullptr,scanner_golden.rule_version);

    int result = yr_scanner_copy(scanner_golden.scanner, &yscanner.scanner);
    //int result = yr_new_scanner_copy(scanner_golden.scanner, &yscanner.scanner);
    if (result != ERROR_SUCCESS){
        printf("Failed to yr_scanner_copy scanner: %d\n", result);
        return nullptr;
    }
    scanners.insert(std::pair{id,yscanner} );
    yr_scanner_set_callback(yscanner.scanner,capture_matches,&yaraInfo);
    return yscanner.scanner;
}

//static
int ScannerThreadLocal::capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data){
    YaraInfo* yaraInfo = static_cast<YaraInfo*>(user_data);

    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        YR_RULE* rule = (YR_RULE*)message_data;
        YR_STRING* string;

        yr_rule_strings_foreach(rule, string){
            std::string rule_name = rule->identifier;
            if (vectorContainsString(yaraInfo->matched_rules, rule_name) == false){
                yaraInfo->matched_rules.push_back(rule_name);
            }
        }
    }
    return CALLBACK_CONTINUE;
}
} //namespace org::turland::yara
