pwd:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OAPI_GENERATOR=python
OAPI_GEN_DIR=gen_client


.PHONY: gen_server build gen_dirs generator_options gen_client dirs run

gen_server:
	bash generate_server.sh

build:
	docker build --rm=false -f Dockerfile -t yara_rest .

gen_dirs: $(pwd)/$(OAPI_GEN_DIR)
	mkdir -p $(pwd)/$(OAPI_GEN_DIR)

generator_options:
	docker run openapitools/openapi-generator-cli list

gen_client:
	docker run --rm -v "${pwd}:/local" openapitools/openapi-generator-cli generate \
    -i /local/yara_openapi.yaml \
    -g $(OAPI_GENERATOR) \
    -o /local/$(OAPI_GEN_DIR)


dirs:
	mkdir -p rules
	mkdir -p samples

run: dirs
	docker run  -p 8080:8080                   \
            -v $(pwd)/conf:/etc/yara       \
            -v $(pwd)/rules:/etc/yara/rules \
            -v $(pwd)/samples:/var/yara/samples \
            -e GLOG_logtostderr=1 \
			-e GLOG_v=2 \
            yara_rest
