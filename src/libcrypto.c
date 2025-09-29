#include <stdio.h>

#ifdef TRACING
#define TRACE_CALL() printf("[TRACE] %s\n", __func__);
#else
#define TRACE_CALL()
#endif // TRACING

void X509V3_conf_free(void *conf)
{
	TRACE_CALL()
}

int X509_set_issuer_name(void *x, const void *name)
{
	TRACE_CALL()
	return 0;
}

int X509_set_subject_name(void *x, const void *name)
{
	TRACE_CALL()
	return 0;
}


void* X509_NAME_new(void)
{
	TRACE_CALL()
	return NULL;
}

void *X509_get_ext(const void *x, int loc)
{
	TRACE_CALL()
	return NULL;
}

void *X509_STORE_CTX_get_current_cert(const void *ctx)
{
	TRACE_CALL()
	return NULL;
}

int X509_STORE_add_cert(void *xs, void *x)
{
	TRACE_CALL()
	return 0;
}

void *X509_get_serialNumber(void *x)
{
	TRACE_CALL()
	return NULL;
}

void *X509_get_subject_name(const void *x)
{
	TRACE_CALL()
	return NULL;
}

void *X509_new(void)
{
	TRACE_CALL()
	return NULL;
}

int X509_NAME_add_entry_by_NID(void *name, int nid, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set)
{
	TRACE_CALL()
	return 0;
}

void *d2i_X509(void **a, const unsigned char **pp, long length)
{
	TRACE_CALL()
	return NULL;
}

void *X509_gmtime_adj(void *asn1_time, long offset_sec)
{
	TRACE_CALL()
	return NULL;
}

int X509_set_pubkey(void *x, void *pkey)
{
	TRACE_CALL()
	return 0;
}

int X509_set_version(void *x, long version)
{
	TRACE_CALL()
	return 0;
}

int EVP_PKEY_assign(void *pkey, int type, void *key)
{
	TRACE_CALL()
	return 0;
}

void *RSA_new(void)
{
	TRACE_CALL()
	return NULL;
}

void *EVP_PKEY_new(void)
{
	TRACE_CALL()
	return NULL;
}

void *ASN1_item_d2i(void **pval, const unsigned char **in,
                          long len, const void *it)
{
	TRACE_CALL()
	return 0;
}

void CRYPTO_set_dynlock_create_callback(void*)
{
	TRACE_CALL()
	return;
}

void CRYPTO_set_dynlock_destroy_callback(void*)
{
	TRACE_CALL()
}

void *X509_EXTENSION_get_object(void *ex)
{
	TRACE_CALL()
	return NULL;
}

 int X509_digest(const void *data, const void *type, unsigned char *md,
                        unsigned int *len)
{
	TRACE_CALL()
	return 0;
}

int X509_cmp(const void *a, const void *b)
{
	TRACE_CALL()
	return -1;
}


void X509_free(void *a)
{
	TRACE_CALL()
}

const void *EVP_sha1(void)
{
	TRACE_CALL()
	return NULL;
}

void* X509V3_EXT_get(void*)
{
	TRACE_CALL()
	return NULL;
}

int CRYPTO_num_locks(void)
{
	TRACE_CALL()
	return 0;
}

void X509_NAME_free(void*)
{
	TRACE_CALL()
}

int   X509_STORE_CTX_get_error(const void *ctx)
{
	TRACE_CALL()
	return 0;
}

int X509_get_ext_count(const void *x)
{
	TRACE_CALL()
	return 0;
}