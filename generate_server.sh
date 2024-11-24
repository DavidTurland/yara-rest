#!/bin/bash
gen_args="generate \
    -i /local/yara_openapi.yaml \
    -g cpp-pistache-server \
    --model-package org.turland.yara.model \
    --api-package org.turland.yara.api \
    --invoker-package org.turland.yara.invoker \
    --package-name org.turland.yara.bigpackage \
    --additional-properties helpersPackage=org.turland.yara.helpers \
    -o /local/gen"

config_args="config-help -g cpp-pistache-server"


help_args="help generate"

while getopts cgh flag
do
    case "${flag}" in
        g) args=$gen_args
           run_meld=true;;
        c) args=$config_args;;
        h) args=$help_args;;
    esac
done

echo $args
echo $meldy


YARA_RESTDIR=`pwd`

docker run --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli $gen_args

if [[ "true" == "$run_meld" ]]; then
  meld  ${YARA_RESTDIR}/gen/impl/ ${YARA_RESTDIR}/implementation/
fi

# generate implementation/ProjectMeta.hpp

spec_file=${YARA_RESTDIR}/yara_openapi.yaml
template_file=${YARA_RESTDIR}/project_meta_h.tmpl
template_file_dest=$YARA_RESTDIR/implementation/ProjectMeta.hpp

api_version=`perl -lne 'print $1 if /^\s+version:\s+([0-9.]+)/' $spec_file`
echo "API verion      : $api_version"

openapi_version=`perl -lne 'print $1 if /^openapi:\s+\"([0-9.]+)\"/' $spec_file`
echo "OpenAPI version : $openapi_version"

export API_VERSION=$api_version
export OPENAPI_VERSION=$openapi_version
cat $template_file | envsubst > $template_file_dest


  
exit
docker run --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli config-help -g cpp-pistache-server

#docker run --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli help generate


#docker run --user 1000:1000 \
#     --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli generate \
#    -i /local/yara_openapi.yaml \
#    -g cpp-pistache-server \
#    -o /local/gen

