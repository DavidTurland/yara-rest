#ifndef YARA_SCANNER_COPY_H
#define YARA_SCANNER_COPY_H
#include <stdlib.h>
#include <yara/ahocorasick.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/exefiles.h>
#include <yara/libyara.h>
#include <yara/mem.h>
#include <yara/object.h>
#include <yara/proc.h>
#include <yara/scanner.h>
#include <yara/strutils.h>
#include <yara/types.h>

YR_API int yr_new_scanner_copy(YR_SCANNER* scanner_root,YR_SCANNER** scanner){
  //YR_DEBUG_FPRINTF(2, stderr, "- %s() {} \n", __FUNCTION__);

  YR_EXTERNAL_VARIABLE* external;
  YR_SCANNER* new_scanner;

  new_scanner = (YR_SCANNER*) yr_calloc(1, sizeof(YR_SCANNER));

  if (new_scanner == NULL)
    return ERROR_INSUFFICIENT_MEMORY;
  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_create(64, &new_scanner->objects_table),
      yr_free(new_scanner));

  new_scanner->flags_int = SCAN_INT_FLAGS_CLONE;
  YR_RULES* rules = scanner_root->rules;
  new_scanner->rules = rules;
  new_scanner->canary = scanner_root->canary;
  new_scanner->flags = scanner_root->flags;


  new_scanner->entry_point = YR_UNDEFINED;
  new_scanner->file_size = YR_UNDEFINED;

  new_scanner->rule_matches_flags = (YR_BITMASK*) yr_calloc(
      sizeof(YR_BITMASK), YR_BITMASK_SIZE(rules->num_rules));

  new_scanner->ns_unsatisfied_flags = (YR_BITMASK*) yr_calloc(
      sizeof(YR_BITMASK), YR_BITMASK_SIZE(rules->num_namespaces));

  new_scanner->strings_temp_disabled = (YR_BITMASK*) yr_calloc(
      sizeof(YR_BITMASK), YR_BITMASK_SIZE(rules->num_strings));

  new_scanner->matches = (YR_MATCHES*) yr_calloc(
      rules->num_strings, sizeof(YR_MATCHES));

  new_scanner->unconfirmed_matches = (YR_MATCHES*) yr_calloc(
      rules->num_strings, sizeof(YR_MATCHES));

  if (new_scanner->rule_matches_flags == NULL ||
      new_scanner->ns_unsatisfied_flags == NULL ||
      new_scanner->strings_temp_disabled == NULL ||
      new_scanner->matches == NULL ||  //
      new_scanner->unconfirmed_matches == NULL)
  {
    yr_scanner_destroy(new_scanner);
    return ERROR_INSUFFICIENT_MEMORY;
  }

#ifdef YR_PROFILING_ENABLED
  new_scanner->profiling_info = yr_calloc(
      rules->num_rules, sizeof(YR_PROFILING_INFO));

  if (new_scanner->profiling_info == NULL)
  {
    yr_scanner_destroy(new_scanner);
    return ERROR_INSUFFICIENT_MEMORY;
  }
#else
  new_scanner->profiling_info = NULL;
#endif

  YR_HASH_TABLE* table = scanner_root->objects_table;
  YR_HASH_TABLE_ENTRY* entry;

  if (table == NULL){
    *scanner = new_scanner;
    return ERROR_SUCCESS;
  }

  for (int i = 0; i < table->size; i++)
  {
    entry = table->buckets[i];
    while (entry != NULL)
    {
      YR_OBJECT* object;
      FAIL_ON_ERROR_WITH_CLEANUP(
        yr_object_copy((YR_OBJECT*)entry->value, &object),
        // cleanup
        yr_scanner_destroy(new_scanner));
      FAIL_ON_ERROR_WITH_CLEANUP(yr_hash_table_add(
                                    new_scanner->objects_table,
                                    object->identifier,
                                    NULL,
                                    (void*) object),
                                // cleanup
                                yr_object_destroy(object);
                                yr_scanner_destroy(new_scanner));
      yr_object_set_canary(object, new_scanner->canary);
      entry = entry->next;
    }
  }
  *scanner = new_scanner;

  return ERROR_SUCCESS;
}
#endif