
# Version 0.4.0
## features:

### building
Improved Dockerfile to only build changed stages ( normally just the last stage (yay) )
### runtime configuration  

## Endpoints
/info endpoint starts to return useful info
## Robustness
Exceptions more copious and useful
compiler error state tracked
Error response added to OpenAPI spec
## Tweaks
split out YaraScanner and YaraCompiler

## bug fixes



# API Spec Version 0.3.0
## features:
  For a scan result each matched rule is returned with
      identifier
      namespace
      meta date
  see gen/model/Rule.h
### building
  Added Makefile:
       build - performs docker build
       run - runs in docker
### runtime configuration  

## Endpoints

## Robustness

## bug fixes

# API Spec Version 0.0.2
## features:
### building
  New No-dependency yara-rest image-build in Docker
### runtime configuration  
  Bare bones Configuration file (yaml)
## Endpoints
  Added `/info` endpoint
## Robustness
  Now encapsulate Yara Compiler in object to preempt some of the
    error conditions yara chacks for
  Libraries
    Moved to prod-ready libraries, glog, rapidjson ....
## bug fixes