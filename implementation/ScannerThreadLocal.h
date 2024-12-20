#ifndef SCANNER_THREAD_LOCAL_H
#define SCANNER_THREAD_LOCAL_H
// #include "ScannerThreadLocal.h"
#include "YaraTypes.h"
#include "YaraScanner.h"


namespace org::turland::yara
{
namespace modell = org::turland::yara::model;

//forward
class Manager;

class ScannerThreadLocal{
public:
    ScannerThreadLocal();

    ~ScannerThreadLocal();

    void init(Manager * manager);

    YR_SCANNER* get_scanner(long id);

    YaraScanResultRules yaraInfo;
private:
    bool CreateScanner();
    static int capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

    // each thread has its own scanners, copied from the managers on demand
    scanner_container scanners;

    Manager * manager;

    // track this to see if scanners need recopying from manager
    double rule_version;
};


}
#endif
