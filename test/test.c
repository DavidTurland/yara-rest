#include <yara.h>
//#include "util.h"
// Compiler object
YR_COMPILER* s_compiler = NULL;
char compile_error[1024];
// Number of warnings produced by the last call to compile_rule
int warnings;
// Rules object
YR_RULES* s_rules = NULL;
static void _compiler_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_WARNING)
    (*((int*) user_data))++;

  snprintf(
      compile_error,
      sizeof(compile_error),
      "line %d: %s",
      line_number,
      message);
}


int compile_rule(YR_COMPILER* compiler,char* string, YR_RULES** rules)
{
  //YR_COMPILER* compiler = NULL;
  int result = ERROR_SUCCESS;

  yr_compiler_set_callback(compiler, _compiler_callback, &warnings);

  // Define some variables that will be used in test cases.
  yr_compiler_define_integer_variable(compiler, "var_zero", 0);
  yr_compiler_define_integer_variable(compiler, "var_one", 1);
  yr_compiler_define_boolean_variable(compiler, "var_true", 1);
  yr_compiler_define_boolean_variable(compiler, "var_false", 0);

  if (yr_compiler_add_string(compiler, string, NULL) != 0)
  {
    result = compiler->last_error;
    goto _exit;
  }

  result = yr_compiler_get_rules(compiler, rules);

_exit:
  yr_compiler_destroy(compiler);
  return result;
}

int main(int argc, char** argv){
    int init = yr_initialize();
    int create = yr_compiler_create(&s_compiler);

  if (compile_rule(s_compiler,
          "\
    rule should_match {\
      strings:\
        $a = { 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 }\
      condition:\
        all of them\
    } \
    rule should_not_match { \
      condition: \
        filesize < 100000000 \
    }",
          &s_rules) != ERROR_SUCCESS)
  {
    perror("compile_rule");
    exit(EXIT_FAILURE);
  }
  YR_SCANNER* scanner;  
  int result = yr_scanner_create(s_rules, &scanner);
  if(ERROR_SUCCESS != result){
    printf("yr_scanner_create %d",result);
    exit(EXIT_FAILURE);
  }
  YR_SCANNER* scanner_copy = NULL;  
  {

    int result = yr_scanner_copy(scanner,&scanner_copy);
    if(ERROR_SUCCESS != result){
      printf("yr_scanner_copy %d",result);
      exit(EXIT_FAILURE);
    }
  }

  const char *buf = "VAR='Hello, world!'";
  int rc = yr_scanner_scan_mem(scanner_copy, (uint8_t*) buf, strlen(buf));

  //printf("yr_scanner_create %d",result);
  yr_scanner_destroy(scanner);
  printf("before yr_scanner_destroy(scanner_copy)");
  yr_scanner_destroy(scanner_copy);  

  return 0;

}
