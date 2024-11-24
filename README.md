# yara-rest

A [REST](https://en.wikipedia.org/wiki/Representational_state_transfer) server supporting requests to the [Yara](https://github.com/VirusTotal/yara) compiler and scanner  
The REST API is fully defined in [OpenAPI](https://www.openapis.org/) 3.0, and implemented using the C++ REST server framework [pistache](https://pistacheio.github.io/pistache/)

# Author
David Turland

## Description

Provides a performant, multi-threaded (via threadpool), REST server allowing compiling rules, defining external variables, and efficient file and string scanning using persistent, per-thread, scanner objects

Each thread has its own set of scanners, copied, as required, from the golden set of scanners
maintained in the main thread. This avoids unnecessary scanner creation per request


## REST end-points
Defined in the OpenAPI spec, but here:
1. `/externalvar`   defining external variables for compiler, rules, and 'particular' scanners
1. `/rules/compile` compiling rule(s) from file(s) each with an optional namespace
1. `/scan/file`     scan a file with a particular scanner
1. `/scan/string`   scan a string with a particular scanner
1. `/info`          lightweight call to obtain server status

# Requirements
**NOTE** : _all_ requirements are brought in if the Docker build route is taken 

## yara ( with `yr_scanner_copy` )
The yara api is sadly missing the ability to copy a scanner, ie there is no `yr_scanner_copy`  
Without this, a scanner copy requires:
1. creating a new scanner
1. and redefining all the external variables from the source scanner  
This requires capturing external variables as they are added, for replaying on the copied scanner

I have forked yara, and added a functioning `yr_scanner_copy` on the dturland_feature_yr_scanner_copy branch
```c
YR_API int yr_scanner_copy(YR_SCANNER* scanner_root,YR_SCANNER** scanner)
```

# Downloading
```bash
git clone --recurse-submodules https://github.com/DavidTurland/yara-rest.git
cd yara-rest
git submodule update --init
```
# Building Yara-REST Docker image, and running Yara-REST server in a container
```bash
make build
```
## Running the yara-rest server in a Docker container
These are the mapped volumesL
```
`/etc/yara`           path for config.yaml
`/etc/yara/rules`     default rule file dir (specified in config.yaml)
`/var/yara/samples`   path for files to be tested
```
To run:
```bash
make run
```


# Building and running locally

## Prerequisites

Packages required (Dockerfile option might be easier :-) )
```
apt-get install -y \
  libgoogle-glog-dev \
  rapidjson-dev \
  libjansson-dev \
  libssl-dev \
  g++ \
  curl \
  meson \
  flex \
  bison \
  make \
  cmake \
  pkg-config \
  git \
  automake \
  autoconf \
  libtool \
  openjdk-17-jre-headless
```
## Building locally using cmake

```bash
git clone --recurse-submodules  https://github.com/DavidTurland/yara-rest.git
cd yara-rest
git submodule update --init

# cmake -S . -G Ninja -B build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr/local -S . -G Ninja -B build
cmake --build build  
cmake --build build --target install 
# or change variables, eg YARA_INSTALL_DIR
# ccmake ..
```

## Running Yara REST-server locally
This will start a server running on port `8080`
```bash
yara-server
```
# Clients
## Auto-generating yara-rest server clients
### List available client generators
```bash
make generator_options
```

### Generate a python(the default) client
```bash
make gen_client
```
the generated code will be in the directory `gen_client`  
set the OAPI_GEN_DIR variable to override the directory  
eg, to generate a python(the default) client in ./my_python_client
```bash
make gen_client OAPI_GEN_DIR=my_python_client
```

Set the OAPI_GENERATOR variable to override the default generator

eg, to generate a golang client
```bash
make gen_client OAPI_GENERATOR=spring
```


## Swagger  client
The Swagger OpenAPI editor https://editor.swagger.io is also a flexible client

![editor_swagger_io_screenshot](https://user-images.githubusercontent.com/11562561/226901696-0f7e0371-a8dc-45f7-9d6e-047c75154fb5.png)

# Yara REST API Examples (demo'd using curl)
(The above swa)
### compile a yara rules file ( assumes the the docker volume mount $(pwd)rules:/etc/yara/rules

```bash
cp test/resources/detect_demand.yar rules
curl -X 'POST' \
  'http://127.0.0.1:8080/api/rules/compile' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "rules": [
    {
      "filepath": "/etc/yara/rules/detect_demand.yar",
      "namespace": "test"
    }
  ]
}'
```

### Yara-scan a file
```bash
# request
cp test/resources/pay_immediately.txt samples
curl -X 'POST' \
  'http://127.0.0.1:8080/api/scan/file' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "scannerid": 0,
  "filename": "/var/yara/samples/pay_immediately.txt"
}'

# response body

{"returncode":"","rules":[{"identifier":"Example_One","meta":{"my_identifier_1":"Some string data"},"namespace":"test"}]}

```


### Yara-scan a string
```bash
# request
curl -X 'POST' \
  'http://127.0.0.1:8080/api/scan/string' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "scannerid": 0,
  "data": "pay immediately",
  "length" : 15
}'

# response body
{"returncode":"","rules":[{"identifier":"Example_One","meta":{"my_identifier_1":"Some string data"},"namespace":"test"}]}

```

### Request REST-server info
```bash
curl -X 'GET' \
  'http://127.0.0.1:8080/api/info' \
  -H 'accept: application/json'  \
  -H 'Content-Type: application/json' 


# response body
 {"meta":{"api_version":"0.3.0","num_threads":"20","openapi_version":"3.0.0"},"returncode":""} 
```

# Performance TODO
https://locust.io/#install
```bash
python3 -m venv ./.venv
source ./.venv/bin/activate
pip install locust
```

# TODO

Docker
- [x]  Docker image build
- [x]  Docker image run

Additonal end-points:
- [x] ability to scan strings
- [ ] reload 

Functionality:
- [x] Full Rule informations captured in scan result
- [x] configuration options (ports, rules)
- [ ] configuration options (external variables etc)
- [ ] https support


Implement placeholder functionality
- [ ] save and load compiled rules
- [ ] magic to outdate scanner


## Thanks to
Starting point for YaraManager* taken from this C++ api to yara:

https://mez0.cc/posts/yaraengine/

# Exception Strategy
All calls to yara are expected to succeed, so yara errors will be thrown immediately as HttpErrors
yara likes returning non-ERROR_SUCCESS as ERROR_INSUFFICIENT_MEMORY for many things but HttpErrors should take the yara error code into ccount

