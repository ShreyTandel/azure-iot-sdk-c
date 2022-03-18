cmake_minimum_required(VERSION 3.5)

project(custom_hsm_lib C)

set(AZURE_IOT_SDK_C_PATH "${CMAKE_CURRENT_LIST_DIR}/..")

if (NOT DEFINED AZURE_IOT_SDK_C_PATH)
    message(FATAL_ERROR "AZURE_IOT_SDK_C_PATH not set")
endif()

add_library(custom_hsm_lib STATIC src/custom_hsm_lib.c src/cJSON.c)

target_include_directories(custom_hsm_lib PRIVATE ${AZURE_IOT_SDK_C_PATH}/provisioning_client/adapters)
