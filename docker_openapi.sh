
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
  
exit
docker run --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli config-help -g cpp-pistache-server

#docker run --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli help generate


#docker run --user 1000:1000 \
#     --rm -v "${YARA_RESTDIR}:/local" openapitools/openapi-generator-cli generate \
#    -i /local/yara_openapi.yaml \
#    -g cpp-pistache-server \
#    -o /local/gen

