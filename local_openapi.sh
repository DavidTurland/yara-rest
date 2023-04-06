gen_args="generate \
    -i ./yara_openapi.yaml \
    -g cpp-pistache-server \
    --model-package org.turland.yara.model \
    --api-package org.turland.yara.api \
    --invoker-package org.turland.yara.invoker \
    --package-name org.turland.yara.bigpackage \
    --additional-properties helpersPackage=org.turland.yara.helpers \
    -o ./gen"

config_args="config-help -g cpp-pistache-server"

help_args="help generate"

while getopts cghm flag
do
    case "${flag}" in
        g) args=$gen_args;;
        m) run_meld=true;;
        c) args=$config_args;;
        h) args=$help_args;;
    esac
done

ADMINDIR=`pwd`
YARA_RESTDIR=$ADMINDIR/../yara-rest
GENDIR=${YARA_RESTDIR}

java -jar /usr/local/build/openapi-generator-cli.jar $args

if [[ "true" == "$run_meld" ]]; then
meld  ${YARA_RESTDIR}/gen/impl/ ${YARA_RESTDIR}/implementation/
fi
