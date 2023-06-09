# yara-rest

A [REST](https://en.wikipedia.org/wiki/Representational_state_transfer) server supporting requests to the [Yara](https://github.com/VirusTotal/yara) scanner  
It is fully defined in [OpenAPI](https://www.openapis.org/) 3.0, and implemented using the C++ REST server framework [pistache](https://pistacheio.github.io/pistache/)

# Author
David Turland

## Description

Provides a performant, multi-threaded (via threadpool), REST server allowing compiling rules, defining external variables, and efficient file scanning using persistent, per-thread, scanner objects

Each thread has its own set of scanners, copied, as required, from the golden set of scanners
maintained in the main thread. This avoids unnecessary scanner creation per request

However If rules are changed, the reliant scanners are magicly outdated

## end-points
Defined in the OpenAPI spec, but here:
1. `/externalvar`   defining external variables for compiler, rules, and 'particular' scanners
1. `/rules/compile` compiling rules from file(s) each with an optional namespace
1. `/scan/file`     scanning files with a particular scanner
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

Fork, and branch, can be checked out and built thusly:
```bash
gh repo clone DavidTurland/yara
cd yara
git switch dturland_feature_yr_scanner_copy
./bootstrap.sh
./configure --prefix=`pwd`/../yara_install --enable-cuckoo
make install
```

## cmake

# Building Docker image, and running as container
```bash
gh repo clone DavidTurland/yara-rest
cd yara-rest
docker build  -f Dockerfile -t yara_rest .
```
## Running container in Docker
`/etc/yara`       path for config.yaml  
`/etc/yara/rules` default rule file dir (specified in config.yaml)

```bash
mkdir -p rules
docker run  -p 8080:8080                   \
            -v $(pwd)/conf:/etc/yara       \
            -v $(pwd)rules:/etc/yara/rules \
            yara_rest
```

# Building and running 'manually'
Assumes the above yara build with yr_scanner_copy has been installed in `yara_install`
## Building 'manually'
```bash
gh repo clone DavidTurland/yara-rest
cd yara-rest
cmake -S . -G Ninja -B build 
cmake --build build  
cmake --build build --target install 
# or change variables, eg YARA_INSTALL_DIR
# ccmake ..
make
```

## Running 'manually'
This will start a server running on port `8080`
```bash
yara-server
```


## Test client
One of the joys of OpenAPI is the swagger editor which not only allows editting
but is a flexible client

https://editor.swagger.io/
![editor_swagger_io_screenshot](https://user-images.githubusercontent.com/11562561/226901696-0f7e0371-a8dc-45f7-9d6e-047c75154fb5.png)

## example requests
### compile a yara rules file
```bash
curl -X 'POST' \
  'http://127.0.0.1:8080/api/rules/compile' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "rules": [
    {
      "filepath": "/home/davidt/_dev/yara-rest-admin/detect_demand.yar"
    }
  ]
}'
```

### Yara-scan a file
```bash
# request
curl -X 'POST' \
  'http://127.0.0.1:8080/api/scan/file' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "scannerid": 0,
  "filename": "/home/davidt/_dev/yara-rest-admin/pay_immediately.txt"
}'

# response body

{"rules":["Example_One"]}

```

# TODO

Docker
- [x]  Docker image build

Additonal end-points:
- [ ] ability to scan strings
- [ ] reload 

Functionality:
- [x] configuration options (ports, rules)
- [ ] configuration options (external variables etc)
- [ ] https support


Implement placeholder functionality
- [ ] save and load compiled rules
- [ ] magic to outdate scanner

## Developing yara-rest
### The manual way

The docker invocation in `docker_openapi.sh` will regenerate the C++ Pistache files in `gen/*`

```bash
# to generate
bash docker_gen_openapi.sh -g
cd build
make
```
### The Docker way
Or you can just build using docker(see above)
```bash
docker build  -f Dockerfile -t yara_rest .
```

## Thanks to
Starting point for YaraManager* taken from this C++ api to yara:
https://mez0.cc/posts/yaraengine/
