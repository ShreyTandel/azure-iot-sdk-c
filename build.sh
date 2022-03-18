#!/bin/bash

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
cd $SCRIPTPATH

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

mv cmake/provisioning_client/samples/prov_dev_client_sample/prov_dev_client_sample cmake/provisioning_client/samples/prov_dev_client_sample/tpuc_dps_enroll
echo "Azure DPS enrollment binary tpuc_dps_enroll built successfully in cmake/provisioning_client/samples/prov_dev_client_sample directory"