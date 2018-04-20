#!/usr/bin/env bash

CURRENTDIR=`dirname $0`
CLI_ARGS=
while [ "$1" != "" ]; do
    CLI_ARGS="$CLI_ARGS ${1}" && shift;
done;
#echo "CLI_ARGS = $CLI_ARGS"
java -jar $CURRENTDIR/*.jar $CLI_ARGS