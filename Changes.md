
# Version 0.2.0
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