pwd:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))


.PHONY: build build_remainder run

build:
	docker build  -f Dockerfile -t yara_rest .

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
