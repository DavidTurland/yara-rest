#include <string> 
#include <iostream> 

#include <glog/logging.h>

#include "ScannerThreadLocal.h"
#include "YaraManager.h"
#include "YaraHelpers.h"
#include "yara_scanner_copy.h"

namespace org::turland::yara
{
ScannerThreadLocal::ScannerThreadLocal():manager{},rule_version{}{}

ScannerThreadLocal::~ScannerThreadLocal(){
    for(auto scanner: scanners){
        yr_scanner_destroy(scanner.second.scanner);
    }
}

void ScannerThreadLocal::init(Manager * _manager){
   manager = _manager;
   yaraInfo.matched_rules.clear();
}

YR_SCANNER* ScannerThreadLocal::get_scanner(long scanner_id){
    scanner_container_it scit = scanners.find(scanner_id);
    if (scit != scanners.end()){
        return scit->second.scanner;
    }
    YaraScanner scanner_golden = manager->getScanner(scanner_id);
    if (scanner_golden.rule_version != rule_version){
        //TODO : invalidate cache

    }else{
        rule_version = scanner_golden.rule_version;
    }

    YaraScanner yscanner(nullptr,scanner_golden.rule_version);

    int result = yr_scanner_copy(scanner_golden.scanner, &yscanner.scanner);
    //int result = yr_new_scanner_copy(scanner_golden.scanner, &yscanner.scanner);
    if (result != ERROR_SUCCESS){
        LOG(ERROR) << "Failed to yr_scanner_copy scanner: " << result << std::endl;
        return nullptr;
    }
    scanners.insert(std::pair{scanner_id,yscanner} );
    yr_scanner_set_callback(yscanner.scanner,capture_matches,&yaraInfo);
    return yscanner.scanner;
}

//static
int ScannerThreadLocal::capture_matches(
    /**
     * see yara/cli/yara.c::handle_message for inspiration
     * rule->identifier aka rule name
     * this is called for each matching rule
     */
    YR_SCAN_CONTEXT* context, 
    int message, 
    void* message_data, 
    void* user_data){
    YaraScanResultRules* yaraInfo = static_cast<YaraScanResultRules*>(user_data);

    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        modell::Rule s_rule;
        YR_RULE* rule = (YR_RULE*)message_data;
        {
            std::string rule_name = rule->identifier;
            s_rule.setIdentifier(rule_name);

            if ( nullptr != rule->ns){           
                if ( nullptr != rule->ns->name){
                    std::string naimspace = rule->ns->name;
                    s_rule.setRNamespace(naimspace);
                }
            }
            // these are all the strings
            // not just the matching strings
            // so make opitonal
            // std::vector<std::string> m_Strings;
            // YR_STRING* stringy;
            // yr_rule_strings_foreach(rule, stringy){
            //     std::string s((char *)stringy->string,stringy->length);
            //     if (vectorContainsString(m_Strings, s) == false){
            //         m_Strings.push_back(s);
            //     }
            // }
            // s_rule.setStrings(m_Strings);            
        } 

        {    
            std::map<std::string, std::string> m_Meta;
            YR_META* meta;
            // from cli/yara.c
            yr_rule_metas_foreach(rule, meta){
                // it's a LL so this tests if
                // it is not the first element
                // if (meta != rule->metas){
                //   _tprintf(_T(","));
                // }

                switch(meta->type) {
                case META_TYPE_INTEGER:
                    VLOG(2) << "capture_matches meta int " << meta->identifier  << ":" << std::to_string(meta->integer) << std::endl;
                    m_Meta.insert({meta->identifier,std::to_string(meta->integer)});
                    break;
                case META_TYPE_STRING:
                    VLOG(2)  << "capture_matches meta string " << meta->identifier  << ":" << meta->string << std::endl;
                    m_Meta.insert({meta->identifier,meta->string});
                    break;
                case META_TYPE_BOOLEAN:
                    VLOG(2) << "capture_matches meta int " << meta->identifier  << ":" << std::to_string(meta->integer) << std::endl;
                    m_Meta.insert({meta->identifier,meta->integer ? "true" : "false"});
                }
            }
            s_rule.setMeta(m_Meta);            
        }
        yaraInfo->matched_rules.push_back(std::move(s_rule));
    }
    return CALLBACK_CONTINUE;
}
} //namespace org::turland::yara
