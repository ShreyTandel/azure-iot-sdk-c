#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cJSON.h"

#include "hsm_client_data.h"

#ifndef DEVICE_PROVISION_JSON
#define DEVICE_PROVISION_JSON   "device_provision.json"
#endif

typedef struct
{
    char *pJson;
    int jsonLen;
    cJSON *pCJson;
    char *pIdScope;
    char *pRegistrationId;
    char *pCertFile;
    char *pCert;
    int certLen;
    char *pKeyFile;
    char *pKey;
    int keyLen;
    char *pCaCertFile;
    char *pCaCert;
    int caCertLen;
} CustomX509Info;

static char *pDevProvFile = DEVICE_PROVISION_JSON;
static CustomX509Info* pInfo = NULL;

void custom_hsm_set_device_provision_file(char *pFile)
{
    pDevProvFile = pFile;
}

static int readFile(unsigned char *pFile, char **ppData, int *pDataLen)
{
    FILE *pFilePtr = NULL;
    int status = -1;
    int dataLen;
    char *pData;

    pFilePtr = fopen(pFile, "r");
    if (NULL == pFilePtr)
        goto exit;

    fseek(pFilePtr, 0, SEEK_END);
    dataLen = ftell(pFilePtr);
    fseek(pFilePtr, 0, SEEK_SET);
    pData = malloc(dataLen + 1);
    fread(pData, dataLen, 1, pFilePtr);
    pData[dataLen] = '\0';
    fclose(pFilePtr);
    pFilePtr = NULL;

    *ppData = pData;
    *pDataLen = dataLen;

    status = 0;

exit:

    return status;
}

int hsm_client_x509_init(void)
{
    int status = -1;
    cJSON *pItem;

    if (NULL != pInfo)
        hsm_client_x509_deinit();

    pInfo = calloc(sizeof(CustomX509Info), 1);
    if (NULL == pInfo)
    {
        printf("Failed to allocate CustomX509Info structure\n");
        goto exit;
    }

    if (0 != readFile(pDevProvFile, &(pInfo->pJson), &(pInfo->jsonLen)))
    {
        printf("Failed to read %s file\n", pDevProvFile);
        goto exit;
    }

    pInfo->pCJson = cJSON_ParseWithLength(pInfo->pJson, pInfo->jsonLen);
    if (NULL == pInfo->pCJson)
    {
        printf("Failed to parse device provision JSON\n");
        goto exit;
    }

    pItem = cJSON_GetObjectItem(pInfo->pCJson, "id_scope");
    if (NULL == pItem)
    {
        printf("Missing id_scope in device provision JSON\n");
        goto exit;
    }
    pInfo->pIdScope = pItem->valuestring;
    if (NULL == pInfo->pIdScope)
    {
        printf("Found invalid id_scope value\n");
        goto exit;
    }

    pItem = cJSON_GetObjectItem(pInfo->pCJson, "registration_id");
    if (NULL == pItem)
    {
        printf("Missing registration_id in device provision JSON\n");
        goto exit;
    }
    pInfo->pRegistrationId = pItem->valuestring;
    if (NULL == pInfo->pRegistrationId)
    {
        printf("Found invalid registration_id value\n");
        goto exit;
    }

    pItem = cJSON_GetObjectItem(pInfo->pCJson, "device_pem_certificate");
    if (NULL == pItem)
    {
        printf("Missing device_pem_certificate in device provision JSON\n");
        goto exit;
    }
    pInfo->pCertFile = pItem->valuestring;
    if (NULL == pInfo->pCertFile)
    {
        printf("Found invalid device_pem_certificate value\n");
        goto exit;
    }

    pItem = cJSON_GetObjectItem(pInfo->pCJson, "device_pem_private_key");
    if (NULL == pItem)
    {
        printf("Missing device_pem_private_key in device provision JSON\n");
        goto exit;
    }
    pInfo->pKeyFile = pItem->valuestring;
    if (NULL == pInfo->pKeyFile)
    {
        printf("Found invalid device_pem_private_key value\n");
        goto exit;
    }

    pItem = cJSON_GetObjectItem(pInfo->pCJson, "ca_cert_pem");
    if (NULL != pItem)
    {
        pInfo->pCaCertFile = pItem->valuestring;
    }

    if (0 != readFile(pInfo->pCertFile, &(pInfo->pCert), &(pInfo->certLen)))
    {
        printf("Failed to read %s file\n", pInfo->pCertFile);
        goto exit;
    }

    if (0 != readFile(pInfo->pKeyFile, &(pInfo->pKey), &(pInfo->keyLen)))
    {
        printf("Failed to read %s file\n", pInfo->pKeyFile);
        goto exit;
    }

    if (NULL != pInfo->pCaCertFile)
    {
        if (0 != readFile(pInfo->pCaCertFile, &(pInfo->pCaCert), &(pInfo->caCertLen)))
        {
            printf("Failed to read %s file\n", pInfo->pCaCertFile);
            goto exit;
        }
    }

    status = 0;

exit:

    return status;
}

void hsm_client_x509_deinit(void)
{
    if (NULL != pInfo)
    {
        if (NULL != pInfo->pCaCert)
        {
            free(pInfo->pCaCert);
        }

        if (NULL != pInfo->pKey)
        {
            free(pInfo->pKey);
        }

        if (NULL != pInfo->pCert)
        {
            free(pInfo->pCert);
        }

        if (NULL != pInfo->pCJson)
        {
            cJSON_Delete(pInfo->pCJson);
        }

        if (NULL != pInfo->pJson)
        {
            free(pInfo->pJson);
        }

        free(pInfo);
    }
}

int hsm_client_tpm_init(void)
{
    return 0;
}

void hsm_client_tpm_deinit(void)
{
}

HSM_CLIENT_HANDLE custom_hsm_create(void)
{
    return pInfo;
}

void custom_hsm_destroy(HSM_CLIENT_HANDLE pHandle)
{
}

char* custom_hsm_get_certificate(HSM_CLIENT_HANDLE pHandle)
{
    char *pResult = NULL;
    CustomX509Info *pInfo = (CustomX509Info *) pHandle;

    if ( (NULL == pInfo) || (NULL == pInfo->pCert) )
    {
        goto exit;
    }

    pResult = malloc(pInfo->certLen + 1);
    if (NULL == pResult)
    {
        goto exit;
    }

    memcpy(pResult, pInfo->pCert, pInfo->certLen);
    pResult[pInfo->certLen] = '\0';

exit:

    return pResult;
}

char* custom_hsm_get_key(HSM_CLIENT_HANDLE pHandle)
{
    char *pResult = NULL;
    CustomX509Info *pInfo = (CustomX509Info *) pHandle;

    if ( (NULL == pInfo) || (NULL == pInfo->pKey) )
    {
        goto exit;
    }

    pResult = malloc(pInfo->keyLen + 1);
    if (NULL == pResult)
    {
        goto exit;
    }

    memcpy(pResult, pInfo->pKey, pInfo->keyLen);
    pResult[pInfo->keyLen] = '\0';

exit:

    return pResult;
}

char* custom_hsm_get_common_name(HSM_CLIENT_HANDLE pHandle)
{
    char *pResult = NULL;
    CustomX509Info *pInfo = (CustomX509Info *) pHandle;
    int len;

    if ( (NULL == pInfo) || (NULL == pInfo->pRegistrationId) )
    {
        goto exit;
    }

    len = strlen(pInfo->pRegistrationId);

    pResult = malloc(len + 1);
    if (NULL == pResult)
    {
        goto exit;
    }

    memcpy(pResult, pInfo->pRegistrationId, len);
    pResult[len] = '\0';

exit:

    return pResult;
}

char* custom_hsm_get_id_scope()
{
    if (NULL != pInfo)
        return pInfo->pIdScope;
    else
        return NULL;
}

char* custom_hsm_get_ca_cert()
{
    if (NULL != pInfo)
        return pInfo->pCaCert;
    else
        return NULL;
}

// Defining the v-table for the x509 hsm calls
static const HSM_CLIENT_X509_INTERFACE x509_interface =
{
    custom_hsm_create,
    custom_hsm_destroy,
    custom_hsm_get_certificate,
    custom_hsm_get_key,
    custom_hsm_get_common_name
};

// Defining the v-table for the x509 hsm calls
// static const HSM_CLIENT_TPM_INTERFACE tpm_interface =
// {
//     custom_hsm_create,
//     custom_hsm_destroy,
//     custom_hsm_activate_identity_key,
//     custom_hsm_get_endorsement_key,
//     custom_hsm_get_storage_root_key,
//     custom_hsm_sign_with_identity
// };

// static const HSM_CLIENT_KEY_INTERFACE symm_key_interface =
// {
//     custom_hsm_create,
//     custom_hsm_destroy,
//     custom_hsm_symm_key,
//     custom_hsm_get_registration_name
// };

const HSM_CLIENT_TPM_INTERFACE* hsm_client_tpm_interface(void)
{
    // tpm interface pointer
    // return &tpm_interface;
    return NULL;
}

const HSM_CLIENT_X509_INTERFACE* hsm_client_x509_interface(void)
{
    // x509 interface pointer
    return &x509_interface;
}

const HSM_CLIENT_KEY_INTERFACE* hsm_client_key_interface(void)
{
    // return &symm_key_interface;
    return NULL;
}
