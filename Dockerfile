# The new base image to contain runtime dependencies

FROM debian:sid-slim AS base

# gcc 10 - nope!!!
# FROM bitnami/minideb:latest AS base

ENV INSTALL_DIR=/usr/local
ENV BUILD_DIR=/usr/local/build
RUN set -ex        ; \
    apt-get update ; \
    apt-get install -y libgoogle-glog-dev rapidjson-dev libjansson-dev libssl-dev 

# The builder stage will install build dependencies on top of the
# runtime dependencies: this should not change once built
FROM base AS builder

RUN set -ex                                                                                                                    ; \
    apt-get install -y g++ curl meson flex bison  make cmake  pkg-config git automake autoconf libtool openjdk-17-jre-headless ; \
    mkdir -p $INSTALL_DIR/bin                                                                                                  ; \
    mkdir -p $INSTALL_DIR/lib                                                                                                  ; \
    mkdir -p $BUILD_DIR/bin                                                                                                    ; \
    curl -L https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/6.3.0/openapi-generator-cli-6.3.0.jar   \
         -o $BUILD_DIR/openapi-generator-cli.jar

# build custom yara  
RUN set -ex                                               ; \
    mkdir -p $BUILD_DIR/src                               ; \ 
    cd $BUILD_DIR/src                                     ; \ 
    git clone https://github.com/DavidTurland/yara        ; \
    cd yara                                               ; \
    git switch dturland_feature_yr_scanner_copy           ; \
    ./bootstrap.sh                                        ; \
    ./configure --prefix=$INSTALL_DIR                 \
                --disable-static                      \
                --enable-cuckoo                           ; \
    make install

# build nlohmann
RUN set -ex                                               ; \
    mkdir -p $BUILD_DIR/src                               ; \ 
    cd $BUILD_DIR/src                                     ; \ 
    git clone https://github.com/nlohmann/json.git        ; \
    cd json                                               ; \
    rm -rf   build                                        ; \
    mkdir -p build                                        ; \
    cmake -S . -G Ninja -B build                               \
               -D CMAKE_INSTALL_PREFIX=$INSTALL_DIR   \
               -D JSON_BuildTests=OFF                     ; \
    cmake --build build                                   ; \
    cmake --build build --target install

# build yaml-cpp
RUN set -ex                                               ; \
    mkdir -p $BUILD_DIR/src                               ; \ 
    cd $BUILD_DIR/src                                     ; \ 
    git clone https://github.com/jbeder/yaml-cpp.git      ; \
    cd yaml-cpp                                           ; \
    rm -rf   build                                        ; \
    mkdir -p build                                        ; \
    cmake -S . -G Ninja -B build                                \
               -D CMAKE_INSTALL_PREFIX=$INSTALL_DIR    \
               -D YAML_BUILD_SHARED_LIBS=OFF              ; \
    cmake --build build                                   ; \
    cmake --build build --target install

# build pistache
# --wipe
RUN set -ex                                               ; \
    mkdir -p $BUILD_DIR/src                               ; \ 
    cd $BUILD_DIR/src                                     ; \ 
    git clone https://github.com/pistacheio/pistache.git  ; \
    cd pistache                                           ; \
    meson setup build                      \   
              --prefix=$INSTALL_DIR        \ 
              --default-library=static     \     
              -D PISTACHE_USE_SSL=true     \   
              --libdir=lib                                ; \
    meson install -C build

# the yara_rest_builder : this will change the most, if any
# so made a new stage to avoid rebuilding the build dependencies
FROM builder AS yara_rest_builder

# build yara-rest
COPY . $BUILD_DIR/yara_rest

RUN set -ex                                         ; \
    cd $BUILD_DIR/yara_rest                         ; \
    bash local_openapi.sh -g                        ; \
    rm -rf   build                                  ; \
    mkdir -p build                                  ; \
    cmake -S . -G Ninja -B build                        \
          -D CMAKE_INSTALL_PREFIX=$INSTALL_DIR \
          -D YARA_INSTALL_DIR=$INSTALL_DIR     \
          -D BUILD_NLOHMANN=no                 \
          -D BUILD_YAML_CPP=no                 \
          -D BUILD_PISTACHE=no                 \
          -D CMAKE_BUILD_TYPE=Release               ; \
    cmake --build build                             ; \
    cmake --build build --target install 

FROM base AS runtime

# a starting point but should mount /etc/yara as volume
COPY conf/config.yaml /etc/yara/config.yaml

COPY --from=yara_rest_builder $INSTALL_DIR/bin/yara-rest /usr/bin
COPY --from=yara_rest_builder $INSTALL_DIR/lib/lib*      /usr/lib/

EXPOSE 8080

ENTRYPOINT ["yara-rest"]
