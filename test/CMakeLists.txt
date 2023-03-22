add_executable (Test test.c)
link_directories(${PROJECT_SOURCE_DIR}/../yara_install/lib)
target_link_libraries (Test
                       yara
                       )
include_directories(${PROJECT_SOURCE_DIR}/../yara_install/include) 
include_directories(${PROJECT_SOURCE_DIR}/../yara/libyara/include)   
include_directories( ${PROJECT_SOURCE_DIR}/../yara/tests)                       
                       
add_test (NAME MyTest COMMAND Test)
