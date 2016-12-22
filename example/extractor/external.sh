#!/bin/bash

# Simple script that demonstrates how to use Bash and JQ in order to generate
# a PURuntime out of a DockerInfo input as json.

PID=$(echo $1 | jq .State.Pid)
NAME=$(echo $1 | jq .Name)
IPADDRESS=$(echo $1 | jq .NetworkSettings.Networks.bridge.IPAddress)
TAGS=$(echo $1 | jq .Config.Labels)
echo '{"Pid":'$PID',"Name":'$NAME',"IPAddresses":{"bridge":'$IPADDRESS'},"Tags":'$TAGS' }' | jq
