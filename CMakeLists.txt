cmake_minimum_required (VERSION 3.2)

project(yara-rest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17" )

find_package (glog 0.4.0 REQUIRED)
find_package (RapidJSON 0.4.0 REQUIRED)

include(ExternalProject)

set(EXTERNAL_INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)

set(GEN_DIR              ${CMAKE_CURRENT_SOURCE_DIR}/gen)

set(YARA_INSTALL_DIR     ${PROJECT_SOURCE_DIR}/../yara_install
    CACHE PATH "path to yara install")

option( YARA_REST_INSTALL "generation of yara-rest install targets" no)

set(BUILD_SIMPLE_CPP_LOGGER yes
    CACHE BOOL "should we install simple_cpp_logger")
set(BUILD_NLOHMANN yes
    CACHE BOOL "should we build nlohmann")

set(BUILD_YAML_CPP yes
    CACHE BOOL "should we build yaml cpp")

set(BUILD_PISTACHE yes
    CACHE BOOL "should we build pistache")

if (BUILD_PISTACHE)
    ExternalProject_Add(PISTACHE
        GIT_REPOSITORY https://github.com/pistacheio/pistache.git
        BUILD_IN_SOURCE true
        BUILD_COMMAND meson setup build  ##--wipe
            --prefix=${EXTERNAL_INSTALL_DIR}
            --default-library=static
            -DPISTACHE_USE_SSL=true
            --libdir=lib
        INSTALL_COMMAND   meson install -C build
    )
endif()

if (BUILD_NLOHMANN)
    ExternalProject_Add(NLOHMANN
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_DIR} -DJSON_BuildTests=OFF
    )
endif()

if (BUILD_YAML_CPP)
    ExternalProject_Add(YAML_CPP
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_DIR} -DYAML_BUILD_SHARED_LIBS=OFF
    )
endif()

include_directories(${EXTERNAL_INSTALL_DIR}/include)
link_directories(${EXTERNAL_INSTALL_DIR}/lib)
message(STATUS "link_directories ${YARA_INSTALL_DIR}/lib")
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
    ${CMAKE_CURRENT_SOURCE_DIR}/implementation/YaraTypes.cpp
)

add_executable(${PROJECT_NAME} ${SRCS} )

if (BUILD_PISTACHE)
    add_dependencies(${PROJECT_NAME} PISTACHE)
endif()

if (BUILD_YAML_CPP)
    add_dependencies(${PROJECT_NAME} YAML_CPP)
endif()

target_link_libraries(${PROJECT_NAME} pistache pthread yara crypto ssl yaml-cpp)
target_link_libraries (${PROJECT_NAME} glog::glog)

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

enable_testing ()
add_subdirectory (test)
