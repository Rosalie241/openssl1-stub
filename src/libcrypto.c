#include <stdio.h>

#ifdef TRACING
#define TRACE_CALL() printf("[TRACE] %s\n", __func__);
#else
#define TRACE_CALL()
#endif // TRACING

//
// CRYPTO functions
//

void CRYPTO_set_dynlock_create_callback(void* cb)
{
	TRACE_CALL()
}

void CRYPTO_set_dynlock_destroy_callback(void* cb)
{
	TRACE_CALL()
}

int CRYPTO_num_locks(void)
{
	TRACE_CALL()
	return 0;
}

void CRYPTO_add_lock(int arg1, int arg2, int arg3, int arg4, int arg5)
{
    TRACE_CALL()
}

void CRYPTO_set_locking_callback(int cb)
{
    TRACE_CALL()
}

void CRYPTO_set_dynlock_lock_callback(void* cb)
{
    TRACE_CALL()
}

void CRYPTO_set_id_callback(void* cb)
{
    TRACE_CALL()
}

//
// X509 functions
//

void* X509_new(void)
{
	TRACE_CALL()
	return NULL;
}

int X509_cmp(const void* a, const void* b)
{
	TRACE_CALL()
	return -1;
}

void X509_free(void* a)
{
	TRACE_CALL()
}

void* X509_EXTENSION_get_object(void* ex)
{
	TRACE_CALL()
	return NULL;
}

 int X509_digest(const void* data, const void* type, unsigned char *md,
                        unsigned int *len)
{
	TRACE_CALL()
	return 0;
}

int X509_set_issuer_name(void* x, const void* name)
{
	TRACE_CALL()
	return 0;
}

int X509_set_subject_name(void* x, const void* name)
{
	TRACE_CALL()
	return 0;
}

void* X509_NAME_new(void)
{
	TRACE_CALL()
	return NULL;
}

void* X509_get_ext(const void* x, int loc)
{
	TRACE_CALL()
	return NULL;
}

void* X509_STORE_CTX_get_current_cert(const void* ctx)
{
	TRACE_CALL()
	return NULL;
}

int X509_STORE_add_cert(void* xs, void* x)
{
	TRACE_CALL()
	return 0;
}

void* X509_get_serialNumber(void* x)
{
	TRACE_CALL()
	return NULL;
}

void* X509_get_subject_name(const void* x)
{
	TRACE_CALL()
	return NULL;
}

int X509_NAME_add_entry_by_NID(void* name, int nid, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set)
{
	TRACE_CALL()
	return 0;
}

void* d2i_X509(void* *a, const unsigned char **pp, long length)
{
	TRACE_CALL()
	return NULL;
}

void* X509_gmtime_adj(void* asn1_time, long offset_sec)
{
	TRACE_CALL()
	return NULL;
}

int X509_set_pubkey(void* x, void* pkey)
{
	TRACE_CALL()
	return 0;
}

int X509_set_version(void* x, long version)
{
	TRACE_CALL()
	return 0;
}

void X509_NAME_free(void* x)
{
	TRACE_CALL()
}

int X509_STORE_CTX_get_error(const void* ctx)
{
	TRACE_CALL()
	return 0;
}

int X509_get_ext_count(const void* x)
{
	TRACE_CALL()
	return 0;
}

void* X509_STORE_CTX_get_ex_data(const void* d, int idx)
{
    TRACE_CALL()
	return NULL;
}

int X509_sign(void* x, void* pkey, const void* md)
{
    TRACE_CALL()
	return 0;
}

int X509_NAME_get_text_by_NID(const void* name, int nid,
                                      char *buf, int len)
{
    TRACE_CALL()
	return 0;
}

void X509V3_conf_free(void* conf)
{
	TRACE_CALL()
}

void* X509V3_EXT_get(void* x)
{
	TRACE_CALL()
	return NULL;
}

//
// EVP functions
//

const void* EVP_md5(void)
{
	TRACE_CALL()
	return NULL;
}

const void* EVP_sha1(void)
{
	TRACE_CALL()
	return NULL;
}

const void* EVP_sha256(void)
{
    TRACE_CALL()
	return NULL;
}


const void* EVP_sha384(void)
{
    TRACE_CALL()
	return NULL;
}


const void* EVP_sha224(void)
{
    TRACE_CALL()
	return NULL;
}

const void* EVP_sha512(void)
{
    TRACE_CALL()
    return NULL;
}

int EVP_PKEY_assign(void* pkey, int type, void* key)
{
	TRACE_CALL()
	return 0;
}

void* EVP_PKEY_new(void)
{
	TRACE_CALL()
	return NULL;
}

void EVP_PKEY_free(void* key)
{
    TRACE_CALL()
}

int EVP_MD_size(const void* md)
{
	TRACE_CALL()
	return 0;
}

int EVP_MD_CTX_cleanup(void* ctx)
{
    TRACE_CALL()
	return 0;
}

int EVP_DigestUpdate(void* ctx, const void* d, size_t cnt)
{
    TRACE_CALL()
	return 0;
}

int EVP_DigestInit_ex(void* ctx, const void* type, void* impl)
{
    TRACE_CALL()
	return 0;
}

int EVP_DigestFinal_ex(void* ctx, unsigned char *md, unsigned int *s)
{
    TRACE_CALL()
	return 0;
}

void EVP_MD_CTX_init(void)
{
    TRACE_CALL()
}

//
// RSA functions
//

void* RSA_new(void)
{
	TRACE_CALL()
	return NULL;
}

void RSA_free(void* rsa)
{
	TRACE_CALL()
}

int RSA_generate_key_ex(void* rsa, int bits, void* e, void* cb)
{
    TRACE_CALL()
    return 0;
}

//
// PEM functions
//

void* PEM_read_bio_PrivateKey(void* bp, void* *x,
                                          void* cb, void* u)
{
	TRACE_CALL()
	return NULL;
}

void* PEM_read_bio_X509(void* bp, void* *x, void* cb, void* u)
{
    TRACE_CALL()
    return NULL;
}

int PEM_write_bio_X509(void* bp, void* x)
{
    TRACE_CALL()
	return 0;
}

//
// ASN1 functions
//

void* ASN1_item_d2i(void* *pval, const unsigned char **in,
                          long len, const void* it)
{
	TRACE_CALL()
	return 0;
}

void ASN1_item_free(void* item)
{
    TRACE_CALL()
}


