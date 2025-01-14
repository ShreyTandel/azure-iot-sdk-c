#!/bin/bash

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
cd $SCRIPTPATH

BIN_NAME="tpuc_dps_enroll"

# Build custom library
cd custom_hsm_lib
rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .

cd $SCRIPTPATH
rm -rf cmake
mkdir cmake
cd cmake
cmake -DCMAKE_BUILD_TYPE=Debug -Dhsm_custom_lib=$SCRIPTPATH/custom_hsm_lib/build/libcustom_hsm_lib.a ..
cmake --build .
cd ..

mv cmake/provisioning_client/samples/prov_dev_client_sample/prov_dev_client_sample ./$BIN_NAME
echo "Azure DPS enrollment binary $BIN_NAME built successfully"