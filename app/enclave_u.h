#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_pwnme(sgx_enclave_id_t eid, const char* str, size_t l);
sgx_status_t generateKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* sealed_key, size_t sealedkey_len);
sgx_status_t loadKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* key, size_t len);
sgx_status_t enclaveProcess(sgx_enclave_id_t eid, int* retval, void* inQueue);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
