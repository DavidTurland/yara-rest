cmake_minimum_required (VERSION 3.2)

project(yara-rest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17" )

include(ExternalProject)

set(EXTERNAL_INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)
set(GEN_DIR              ${CMAKE_CURRENT_SOURCE_DIR}/gen)
set(YARA_INSTALL_DIR     ${PROJECT_SOURCE_DIR}/../yara_install
    CACHE PATH "path to yara install")

ExternalProject_Add(PISTACHE
    GIT_REPOSITORY https://github.com/pistacheio/pistache.git
    BUILD_IN_SOURCE true
    INSTALL_COMMAND meson setup build --prefix=${EXTERNAL_INSTALL_DIR} --libdir=lib && meson install -C build
)

ExternalProject_Add(NLOHMANN
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_DIR} -DJSON_BuildTests=OFF
)


ExternalProject_Add(SIMPLE_CPP_LOGGER
    GIT_REPOSITORY https://github.com/nadrino/simple-cpp-logger.git
    CONFIGURE_COMMAND mkdir -p ${EXTERNAL_INSTALL_DIR}/include/simple_cpp_logger
    BUILD_COMMAND     ""
    INSTALL_COMMAND   rsync -a "<SOURCE_DIR>/include/" ${EXTERNAL_INSTALL_DIR}/include/simple_cpp_logger/
)

include_directories(${EXTERNAL_INSTALL_DIR}/include)
link_directories(${EXTERNAL_INSTALL_DIR}/lib)
link_directories(${YARA_INSTALL_DIR}/lib)

include_directories(${YARA_INSTALL_DIR}/include)
include_directories(${GEN_DIR}/model)
include_directories(${GEN_DIR}/api)

include_directories(impl)

file(GLOB SRCS
    ${GEN_DIR}/api/*.cpp
    ${GEN_DIR}/model/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/implementation/DefaultApiImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/implementation/main-api-server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/implementation/ScannerThreadLocal.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/implementation/YaraManager.cpp
)

add_executable(${PROJECT_NAME} ${SRCS} )
# add_dependencies(${PROJECT_NAME} PISTACHE)
# add_dependencies(${PROJECT_NAME} SIMPLE_CPP_LOGGER)

target_link_libraries(${PROJECT_NAME} pistache pthread yara)

enable_testing ()
add_subdirectory (test)
