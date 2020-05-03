#!/bin/bash

cd $SC
./scion.sh build 

cd ../scion-apps
make install 
play -q -n synth 0.1 tri  1000.0