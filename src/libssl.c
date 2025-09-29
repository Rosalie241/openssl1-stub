#include <stdio.h>

#ifdef TRACING
#define TRACE_CALL() printf("[TRACE] %s\n", __func__);
#else
#define TRACE_CALL()
#endif // TRACING

int SSL_read(void *ssl, void *buf, int num)
{
	TRACE_CALL()
	return 0;
}

int SSL_write(void *ssl, const void *buf, int num)
{
	TRACE_CALL()
	return 0;
}

int SSL_pending(const void *ssl)
{
	TRACE_CALL()
	return 0;
}

void SSL_free(void*)
{
	TRACE_CALL()
}

void *SSL_new(void *ctx)
{
	TRACE_CALL()
	return NULL;
}

const void *EVP_md5(void)
{
	TRACE_CALL()
	return NULL;
}

int SSL_get_error(const void *ssl, int ret)
{
	TRACE_CALL()
	return 0;
}

void *SSL_CTX_get_cert_store(const void *ctx)
{
	TRACE_CALL()
	return NULL;
}

int SSL_export_keying_material(void *s, unsigned char *out, size_t olen,
                                       const char *label, size_t llen,
                                       const unsigned char *context,
                                       size_t contextlen, int use_context)
{
	TRACE_CALL()
	return 0;
}

long SSL_ctrl(void *ssl, int cmd, long larg, void *parg)
{
	TRACE_CALL()
	return 0;
}

int SSL_CTX_set_cipher_list(void *ctx, const char *str)
{
	TRACE_CALL()
	return 0;
}

int SSL_CTX_use_certificate(void *ctx, void *x)
{
	TRACE_CALL()
	return 0;
}

void SSL_set_bio(void* ssl, void* bio)
{
	TRACE_CALL()
}

int SSL_CTX_use_PrivateKey(void *ctx, void *pkey)
{
	TRACE_CALL()
	return 0;
}

const void *DTLSv1_client_method(void)
{
	TRACE_CALL()
	return NULL;
}

const void* TLSv1_client_method(void)
{
	TRACE_CALL()
	return NULL;
}

const void* TLSv1_server_method(void)
{
	TRACE_CALL()
	return NULL;
}

void RSA_free(void *rsa)
{
	TRACE_CALL()
}

const void *BIO_s_mem(void)
{
	TRACE_CALL()
	return NULL;
}

void *BN_to_ASN1_INTEGER(const void *bn, void *ai)
{
	TRACE_CALL()
	return NULL;
}

void *BIO_new(const void *type)
{
	TRACE_CALL()
	return NULL;
}

void *BIO_new_mem_buf(const void *buf, int len)
{
	TRACE_CALL()
	return NULL;
}

void BIO_set_flags(void *b, int flags)
{
	TRACE_CALL()
}

int BIO_write(void *b, const void *data, int dlen)
{
	TRACE_CALL()
	return 0;
}

void BIO_clear_flags(void*)
{
	TRACE_CALL()
}

void *PEM_read_bio_PrivateKey(void *bp, void **x,
                                          void *cb, void *u)
{
	TRACE_CALL()
	return NULL;
}

int EVP_MD_size(const void *md)
{
	TRACE_CALL()
	return 0;
}

int SSL_CTX_set_tlsext_use_srtp(void *ctx, const char *profiles)
{
    TRACE_CALL()
	return 0;
}

int SSL_CTX_add_client_CA(void *ctx, void *cacert)
{
    TRACE_CALL()
	return 0;
}

int BIO_free(void *a)
{
    TRACE_CALL()
	return 0;
}

long BIO_ctrl(void *bp, int cmd, long larg, void *parg)
{
    TRACE_CALL()
	return -1;
}

const void *EVP_sha256(void)
{
    TRACE_CALL()
	return NULL;
}


const void *EVP_sha384(void)
{
    TRACE_CALL()
	return NULL;
}


const void *EVP_sha224(void)
{
    TRACE_CALL()
	return NULL;
}


const void *EVP_sha512(void)
{
    TRACE_CALL()
    return NULL;
}


void EVP_PKEY_free(void *key)
{
    TRACE_CALL()
	return;
}

long SSL_get_verify_result(const void *ssl)
{
    TRACE_CALL()
	return 0;
}

int SSL_connect(void *ssl)
{
    TRACE_CALL()
	return 0;
}

int SSL_accept(void *ssl)
{
    TRACE_CALL()
	return 0;
}

void *SSL_CTX_new(const void *method)
{
    TRACE_CALL()
	return NULL;
}

void SSL_CTX_free(const void* ctx)
{
    TRACE_CALL()
}

void SSL_CTX_set_verify_depth(void *ctx, int depth)
{
    TRACE_CALL()
}

void *SSL_get_ex_data(const void *d, int idx)
{
    TRACE_CALL()
	return NULL;
}

void *X509_STORE_CTX_get_ex_data(const void *d, int idx)
{
    TRACE_CALL()
	return NULL;
}

void *BN_new(void)
{
    TRACE_CALL()
	return NULL;
}

int BN_set_word(void *a, unsigned long w)
{
    TRACE_CALL()
	return 0;
}

void BN_free(void *a)
{
    TRACE_CALL()
}

int OBJ_obj2nid(const void *o)
{
    TRACE_CALL()
	return 0;
}


unsigned long ERR_get_error(void)
{
    TRACE_CALL()
	return 0;
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
    TRACE_CALL()
}

void SSL_load_error_strings(void)
{
    TRACE_CALL()
}

void ERR_load_BIO_strings(void)
{
    TRACE_CALL()
}

const char *ERR_reason_error_string(unsigned long e)
{
    TRACE_CALL()
	return "";
}

int EVP_MD_CTX_cleanup(void *ctx)
{
    TRACE_CALL()
	return 0;
}

int EVP_DigestUpdate(void *ctx, const void *d, size_t cnt)
{
    TRACE_CALL()
	return 0;
}

int SSL_library_init(void)
{
    TRACE_CALL()
	return 1;
}

void OPENSSL_add_all_algorithms_noconf(void)
{
    TRACE_CALL()
}

void sk_pop_free(void *st, void* func)
{
    TRACE_CALL()
}

int sk_num(const void *)
{
    TRACE_CALL()
	return 0;
}


void *sk_value(const void *sk, int idx)
{
    TRACE_CALL()
	return NULL;
}

int SSL_set_ex_data(void *d, int idx, void *arg)
{
    TRACE_CALL()
	return 0;
}

void *SSL_get_peer_certificate(const void *ssl)
{
    TRACE_CALL()
	return NULL;
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    TRACE_CALL()
	return 0;
}

void SSL_CTX_set_verify(void *ctx, int mode, void* verify_callback)
{
    TRACE_CALL()
}

void *PEM_read_bio_X509(void *bp, void **x, void *cb, void *u)
{
    TRACE_CALL()
    return NULL;
}

int RAND_bytes(unsigned char *buf, int num)
{
    TRACE_CALL()
	return 0;
}

void RAND_seed(const void *buf, int num)
{
    TRACE_CALL()
	return;
}

int BN_pseudo_rand(void *rnd, int bits, int top, int bottom)
{
    TRACE_CALL()
	return 0;
}

int RSA_generate_key_ex(void *rsa, int bits, void *e, void *cb)
{
    TRACE_CALL()
    return 0;
}

int X509_sign(void *x, void *pkey, const void *md)
{
    TRACE_CALL()
	return 0;
}

void ASN1_item_free(void*)
{
    TRACE_CALL()
}

int X509_NAME_get_text_by_NID(const void *name, int nid,
                                      char *buf, int len)
{
    TRACE_CALL()
	return 0;
}

int RAND_poll()
{
    TRACE_CALL()
	return 0;
}

const void *DTLSv1_server_method(void)
{
    TRACE_CALL()
	return NULL;
}

int EVP_DigestFinal_ex(void *ctx, unsigned char *md, unsigned int *s)
{
    TRACE_CALL()
	return 0;
}

void CRYPTO_add_lock(int, int, int, int, int)
{
    TRACE_CALL()
}

void CRYPTO_set_locking_callback(int)
{
    TRACE_CALL()
}

void CRYPTO_set_dynlock_lock_callback(void*)
{
    TRACE_CALL()
}

void CRYPTO_set_id_callback(void*)
{
    TRACE_CALL()
}

void *SSL_get_selected_srtp_profile(void *s)
{
    TRACE_CALL()
	return NULL;
}


int PEM_write_bio_X509(void *bp, void *x)
{
    TRACE_CALL()
	return 0;
}

void EVP_MD_CTX_init(void)
{
    TRACE_CALL()
}

int EVP_DigestInit_ex(void *ctx, const void *type, void *impl)
{
    TRACE_CALL()
	return 0;
}