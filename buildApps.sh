#!/bin/bash


go build -o demoapp/demoappclient/ ./demoapp/demoappclient/
go build -o demoapp/demoappserver/ ./demoapp/demoappserver/

cp demoapp/demoappclient/demoappclient ~/go/bin
cp demoapp/demoappserver/demoappserver ~/go/bin

play -q -n synth 0.1 tri  1000.0
