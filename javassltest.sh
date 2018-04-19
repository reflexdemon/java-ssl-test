#!/usr/bin/env bash

CLI_ARGS=
while [ "$1" != "" ]; do
    CLI_ARGS="$CLI_ARGS ${1}" && shift;
done;
#echo "CLI_ARGS = $CLI_ARGS"
java -jar ./jdeploy-bundle/*.jar $CLI_ARGS