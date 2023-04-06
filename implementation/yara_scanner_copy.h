#ifndef YARA_SCANNER_COPY_H
#define YARA_SCANNER_COPY_H

#include <yara/types.h>
extern "C" YR_API int yr_new_scanner_copy(YR_SCANNER* scanner_root,YR_SCANNER** scanner);
#endif