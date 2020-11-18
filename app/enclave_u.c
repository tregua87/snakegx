#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_pwnme_t {
	const char* ms_str;
	size_t ms_l;
} ms_ecall_pwnme_t;

typedef struct ms_generateKeyEnclave_t {
	int ms_retval;
	uint8_t* ms_sealed_key;
	size_t ms_sealedkey_len;
} ms_generateKeyEnclave_t;

typedef struct ms_loadKeyEnclave_t {
	int ms_retval;
	uint8_t* ms_key;
	size_t ms_len;
} ms_loadKeyEnclave_t;

typedef struct ms_enclaveProcess_t {
	int ms_retval;
	void* ms_inQueue;
} ms_enclaveProcess_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_pwnme(sgx_enclave_id_t eid, const char* str, size_t l)
{
	sgx_status_t status;
	ms_ecall_pwnme_t ms;
	ms.ms_str = str;
	ms.ms_l = l;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t generateKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* sealed_key, size_t sealedkey_len)
{
	sgx_status_t status;
	ms_generateKeyEnclave_t ms;
	ms.ms_sealed_key = sealed_key;
	ms.ms_sealedkey_len = sealedkey_len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t loadKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* key, size_t len)
{
	sgx_status_t status;
	ms_loadKeyEnclave_t ms;
	ms.ms_key = key;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclaveProcess(sgx_enclave_id_t eid, int* retval, void* inQueue)
{
	sgx_status_t status;
	ms_enclaveProcess_t ms;
	ms.ms_inQueue = inQueue;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

