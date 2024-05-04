#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#endif

typedef struct
{
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY* rsa;
#else
    RSA* rsa;
#endif
    int padding;
    int hashMode;
} rsaData;

enum {
    DECRYPT,
    ENCRYPT,
    PUBLIC_DECRYPT,
    PRIVATE_ENCRYPT
};

/* Key names for the rsa hash structure */

#define KEY_KEY "_Key"
#define PADDING_KEY "_Padding"
#define HASH_KEY "_Hash_Mode"

#define PACKAGE_NAME "Crypt::OpenSSL::RSA"

#define OLD_CRUFTY_SSL_VERSION (OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x03050000fL))

void croakSsl(char* p_file, int p_line)
{
    const char* errorReason;
    /* Just return the top error on the stack */
    errorReason = ERR_reason_error_string(ERR_get_error());
    ERR_clear_error();
    croak("%s:%d: OpenSSL error: %s", p_file, p_line, errorReason);
}

#define CHECK_OPEN_SSL(p_result) if (!(p_result)) croakSsl(__FILE__, __LINE__);

#define PACKAGE_CROAK(p_message) croak("%s", (p_message))
#define CHECK_NEW(p_var, p_size, p_type) \
  if (New(0, p_var, p_size, p_type) == NULL) \
    { PACKAGE_CROAK("unable to alloc buffer"); }

#define THROW(p_result) if (!(p_result)) { error = 1; goto err; }

char _is_private(rsaData* p_rsa)
{
#if OLD_CRUFTY_SSL_VERSION
    d = p_rsa->rsa->d;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    BIGNUM* d = NULL;
    EVP_PKEY_get_bn_param(p_rsa->rsa, OSSL_PKEY_PARAM_RSA_D, &d);
#else
    const BIGNUM* d;
    RSA_get0_key(p_rsa->rsa, NULL, NULL, &d);
#endif
#endif
    return(d != NULL);
}

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
SV* make_rsa_obj(SV* p_proto, EVP_PKEY* p_rsa)
#else
SV* make_rsa_obj(SV* p_proto, RSA* p_rsa)
#endif
{
    rsaData* rsa;

    CHECK_NEW(rsa, 1, rsaData);
    rsa->rsa = p_rsa;
    rsa->hashMode = NID_sha1;
    rsa->padding = RSA_PKCS1_OAEP_PADDING;
    return sv_bless(
        newRV_noinc(newSViv((IV) rsa)),
        (SvROK(p_proto) ? SvSTASH(SvRV(p_proto)) : gv_stashsv(p_proto, 1)));
}

int get_digest_length(int hash_method)
{
    switch(hash_method)
    {
        case NID_md5:
            return MD5_DIGEST_LENGTH;
            break;
        case NID_sha1:
            return SHA_DIGEST_LENGTH;
            break;
#ifdef SHA512_DIGEST_LENGTH
        case NID_sha224:
            return SHA224_DIGEST_LENGTH;
            break;
        case NID_sha256:
            return SHA256_DIGEST_LENGTH;
            break;
        case NID_sha384:
            return SHA384_DIGEST_LENGTH;
            break;
        case NID_sha512:
            return SHA512_DIGEST_LENGTH;
            break;
#endif
        case NID_ripemd160:
            return RIPEMD160_DIGEST_LENGTH;
            break;
#ifdef WHIRLPOOL_DIGEST_LENGTH
        case NID_whirlpool:
            return WHIRLPOOL_DIGEST_LENGTH;
            break;
#endif
        default:
            croak("Unknown digest hash mode %u", hash_method);
            break;
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
EVP_MD *get_md_bynid(int hash_method)
{
    switch(hash_method)
    {
        case NID_md5:
            return EVP_MD_fetch(NULL, "md5", NULL);
            break;
        case NID_sha1:
            return EVP_MD_fetch(NULL, "sha1", NULL);
            break;
#ifdef SHA512_DIGEST_LENGTH
        case NID_sha224:
            return EVP_MD_fetch(NULL, "sha224", NULL);
            break;
        case NID_sha256:
            return EVP_MD_fetch(NULL, "sha256", NULL);
            break;
        case NID_sha384:
            return EVP_MD_fetch(NULL, "sha384", NULL);
            break;
        case NID_sha512:
            return EVP_MD_fetch(NULL, "sha512", NULL);
            break;
#endif
        case NID_ripemd160:
            return EVP_MD_fetch(NULL, "ripemd160", NULL);
            break;
#ifdef WHIRLPOOL_DIGEST_LENGTH
        case NID_whirlpool:
            return EVP_MD_fetch(NULL, "whirlpool", NULL);
            break;
#endif
        default:
            croak("Unknown digest hash mode %u", hash_method);
            break;
    }
}
#endif
unsigned char* get_message_digest(SV* text_SV, int hash_method)
{
    STRLEN text_length;
    unsigned char* text;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    unsigned char *md;
    size_t *mdlen;
    CHECK_NEW(md, get_digest_length(hash_method), unsigned char);
#endif
    text = (unsigned char*) SvPV(text_SV, text_length);
    switch(hash_method)
    {
        case NID_md5:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
            return EVP_Q_digest(NULL, "MD5", NULL, text, text_length, md, NULL) ? md : NULL;
#else
            return MD5(text, text_length, NULL);
#endif
            break;
        case NID_sha1:
            return SHA1(text, text_length, NULL);
            break;
#ifdef SHA512_DIGEST_LENGTH
        case NID_sha224:
            return SHA224(text, text_length, NULL);
            break;
        case NID_sha256:
            return SHA256(text, text_length, NULL);
            break;
        case NID_sha384:
            return SHA384(text, text_length, NULL);
            break;
        case NID_sha512:
            return SHA512(text, text_length, NULL);
            break;
#endif
        case NID_ripemd160:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
            return EVP_Q_digest(NULL, "RIPEMD160", NULL, text, text_length, md, NULL) ? md : NULL;
#else
            return RIPEMD160(text, text_length, NULL);
#endif
            break;
#ifdef WHIRLPOOL_DIGEST_LENGTH
        case NID_whirlpool:
            return WHIRLPOOL(text, text_length, NULL);
            break;
#endif
        default:
            croak("Unknown digest hash mode %u", hash_method);
            break;
    }
}

SV* cor_bn2sv(const BIGNUM* p_bn)
{
    return p_bn != NULL
        ? sv_2mortal(newSViv((IV) BN_dup(p_bn)))
        : &PL_sv_undef;
}

SV* extractBioString(BIO* p_stringBio)
{
    SV* sv;
    BUF_MEM* bptr;

    CHECK_OPEN_SSL(BIO_flush(p_stringBio) == 1);
    BIO_get_mem_ptr(p_stringBio, &bptr);
    sv = newSVpv(bptr->data, bptr->length);

    CHECK_OPEN_SSL(BIO_set_close(p_stringBio, BIO_CLOSE) == 1);
    BIO_free(p_stringBio);
    return sv;
}

int get_key_size(rsaData* p_rsa) {
    int size = 0;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    size = EVP_PKEY_get_size(p_rsa->rsa);
#else
    size = RSA_size(p_rsa->rsa);
#endif
    return size;
}

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
EVP_PKEY* _load_rsa_key(SV* p_keyStringSv,
                        EVP_PKEY*(*p_loader)(BIO *, EVP_PKEY**, pem_password_cb*, void*),
                   SV* p_passphaseSv)

#else
RSA* _load_rsa_key(SV* p_keyStringSv,
                   RSA*(*p_loader)(BIO*, RSA**, pem_password_cb*, void*),
                   SV* p_passphaseSv)
#endif
{
    STRLEN keyStringLength;
    char* keyString;
    char* passphase = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY* rsa;
#else
    RSA* rsa;
#endif
    BIO* stringBIO;

    keyString = SvPV(p_keyStringSv, keyStringLength);

    if (SvPOK(p_passphaseSv)) {
        passphase = SvPV_nolen(p_passphaseSv);
    }

    CHECK_OPEN_SSL(stringBIO = BIO_new_mem_buf(keyString, keyStringLength));

    rsa = p_loader(stringBIO, NULL, NULL, passphase);

    CHECK_OPEN_SSL(BIO_set_close(stringBIO, BIO_CLOSE) == 1);
    BIO_free(stringBIO);

    CHECK_OPEN_SSL(rsa);
    return rsa;
}

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
SV* rsa_crypt(rsaData* p_rsa, SV* p_from,
              int (*p_crypt)(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t), int enc)
#else
SV* rsa_crypt(rsaData* p_rsa, SV* p_from,
              int (*p_crypt)(int, const unsigned char*, unsigned char*, RSA*, int))
#endif
{
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    STRLEN from_length;
    size_t to_length;
#else
    STRLEN from_length;
    int to_length;
#endif
    int size;
    unsigned char* from;
    char* to;
    SV* sv;

    from = (unsigned char*) SvPV(p_from, from_length);
    size = get_key_size(p_rsa);
    CHECK_NEW(to, size, char);
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)p_rsa->rsa, NULL);
    if (!ctx) {
        printf("Failed to create ctx\n");
    }
            int success;
    switch (enc) {
        case DECRYPT:
            if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                printf("DECRYPT: Failed to intialize encryption\n");
            }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0){
                printf("DECRYPT: Failed to set padding: %i\n", p_rsa->padding);
            }
            if (p_crypt(ctx, NULL, &to_length, from, from_length) <=0)
                printf("DECRYPT: Failed to determine buffer length\n");
            if (p_crypt(ctx, to, &to_length, from, from_length) <=0)
                printf("DECRYPT: Failed to decrypt\n");
            break;
        case ENCRYPT:
            if (EVP_PKEY_encrypt_init(ctx) <= 0) {
                printf("ENCRYPT: Failed to intialize encryption\n");
            }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0){
                printf("ENCRYPT: Failed to set padding\n");
            }
            if (p_crypt(ctx, NULL, &to_length, from, from_length) <=0)
                printf("ENCRYPT: Failed to determine buffer length\n");
            if (p_crypt(ctx, to, &to_length, from, from_length) <=0)
                printf("ENCRYPT: Failed to encrypt\n");
            break;
        case PUBLIC_DECRYPT:
            if (EVP_PKEY_verify_recover_init(ctx) <= 0) {
                printf("Failed to intialize signature\n");
            }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0)
                  printf("Failed to set the PADDING\n");
            if (success = p_crypt(ctx, NULL, &to_length, from, from_length) <= 0)
                  printf("Failed to determine buffer length\n");
            if ((success = p_crypt(ctx, to, &to_length, from, from_length)) <= 0)
                 printf("Failed to public decrypt: %i\n", success);

            break;
        case PRIVATE_ENCRYPT:
            if (EVP_PKEY_sign_init(ctx) <= 0) {
                printf("Failed to intialize signature\n");
            }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0)
                  printf("Failed to set the PADDING\n");
            if ((success = p_crypt(ctx, NULL, &to_length, from, from_length)) <= 0)
                  printf("Failed to determine buffer length\n");
            if ((success = p_crypt(ctx, to, &to_length, from, from_length)) <= 0)
                 printf("Failed to private encrypt %i\n", success);
            break;
    }

    EVP_PKEY_CTX_free(ctx);
#else
    to_length = p_crypt(
       from_length, from, (unsigned char*) to, p_rsa->rsa, p_rsa->padding);
#endif
    if (to_length < 0)
    {
        Safefree(to);
        CHECK_OPEN_SSL(0);
    }
    sv = newSVpv(to, to_length);
    Safefree(to);
    return sv;
}

void print_parameter(const EVP_PKEY *pkey, const char *key_name) {
    BIGNUM *param = NULL;
    char *str = NULL;
    if (EVP_PKEY_get_bn_param(pkey, key_name, &param)) {
        str = BN_bn2dec(param);
        fprintf(stdout, "%s: %s\n", key_name, str);
        OPENSSL_free(str);
        BN_free(param);
    }
    else {
        fprintf(stderr, "Failed to fetch %s\n", key_name);
    }
}


MODULE = Crypt::OpenSSL::RSA		PACKAGE = Crypt::OpenSSL::RSA
PROTOTYPES: DISABLE

BOOT:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    # might introduce memory leak without calling EVP_cleanup() on exit
    # see https://wiki.openssl.org/index.php/Library_Initialization
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#else
    # NOOP
#endif

SV*
new_private_key(proto, key_string_SV, passphase_SV=&PL_sv_undef)
    SV* proto;
    SV* key_string_SV;
    SV* passphase_SV;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_PrivateKey, passphase_SV));
#else
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_RSAPrivateKey, passphase_SV));
#endif
  OUTPUT:
    RETVAL

SV*
_new_public_key_pkcs1(proto, key_string_SV)
    SV* proto;
    SV* key_string_SV;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_PUBKEY, &PL_sv_undef));
#else
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_RSAPublicKey, &PL_sv_undef));
#endif
  OUTPUT:
    RETVAL

SV*
_new_public_key_x509(proto, key_string_SV)
    SV* proto;
    SV* key_string_SV;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_PUBKEY, &PL_sv_undef));
#else
    RETVAL = make_rsa_obj(
        proto, _load_rsa_key(key_string_SV, PEM_read_bio_RSA_PUBKEY, &PL_sv_undef));
#endif
  OUTPUT:
    RETVAL

void
DESTROY(p_rsa)
    rsaData* p_rsa;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_free(p_rsa->rsa);
#else
    RSA_free(p_rsa->rsa);
#endif
    Safefree(p_rsa);

SV*
get_private_key_string(p_rsa, passphase_SV=&PL_sv_undef, cipher_name_SV=&PL_sv_undef)
    rsaData* p_rsa;
    SV* passphase_SV;
    SV* cipher_name_SV;
  PREINIT:
    BIO* stringBIO;
    char* passphase = NULL;
    STRLEN passphaseLength = 0;
    char* cipher_name;
    const EVP_CIPHER* enc = NULL;
  CODE:
    if (SvPOK(cipher_name_SV) && !SvPOK(passphase_SV)) {
        croak("Passphrase is required for cipher");
    }
    if (SvPOK(passphase_SV)) {
        passphase = SvPV(passphase_SV, passphaseLength);
        if (SvPOK(cipher_name_SV)) {
            cipher_name = SvPV_nolen(cipher_name_SV);
        }
        else {
            cipher_name = "des3";
        }
        enc = EVP_get_cipherbyname(cipher_name);
        if (enc == NULL) {
            croak("Unsupported cipher: %s", cipher_name);
        }
    }

    CHECK_OPEN_SSL(stringBIO = BIO_new(BIO_s_mem()));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    PEM_write_bio_PrivateKey_traditional(stringBIO, p_rsa->rsa, enc,
                             passphase, passphaseLength,
                             NULL, NULL);
#else
    PEM_write_bio_RSAPrivateKey(
        stringBIO, p_rsa->rsa, enc, passphase, passphaseLength, NULL, NULL);
#endif
    RETVAL = extractBioString(stringBIO);

  OUTPUT:
    RETVAL

SV*
get_public_key_string(p_rsa)
    rsaData* p_rsa;
  PREINIT:
    BIO* stringBIO;
  CODE:
    CHECK_OPEN_SSL(stringBIO = BIO_new(BIO_s_mem()));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    OSSL_ENCODER_CTX *ctx = NULL;

    ctx = OSSL_ENCODER_CTX_new_for_pkey(p_rsa->rsa, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "PEM", "PKCS1", NULL);
    if (ctx == NULL || !OSSL_ENCODER_CTX_get_num_encoders(ctx)) {
        croak("Failed to get an encoder context");
    }
    OSSL_ENCODER_to_bio(ctx, stringBIO);

    OSSL_ENCODER_CTX_free(ctx);
#else
    PEM_write_bio_RSAPublicKey(stringBIO, p_rsa->rsa);
#endif
    RETVAL = extractBioString(stringBIO);

  OUTPUT:
    RETVAL

SV*
get_public_key_x509_string(p_rsa)
    rsaData* p_rsa;
  PREINIT:
    BIO* stringBIO;
  CODE:
    CHECK_OPEN_SSL(stringBIO = BIO_new(BIO_s_mem()));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    PEM_write_bio_PUBKEY(stringBIO, p_rsa->rsa);
#else
    PEM_write_bio_RSA_PUBKEY(stringBIO, p_rsa->rsa);
#endif
    RETVAL = extractBioString(stringBIO);

  OUTPUT:
    RETVAL

SV*
generate_key(proto, bitsSV, exponent = 65537)
    SV* proto;
    SV* bitsSV;
    unsigned long exponent;
  PREINIT:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *rsa = NULL;
#else
    RSA* rsa;
#endif
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    //ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (!ctx)
        croak("Unable to create a CTX instance");
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        croak("Unable to initialize a keygen");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, SvIV(bitsSV)) <= 0)
        croak("Unable to set the rsa bits");

    /* Generate key */
    if (EVP_PKEY_generate(ctx, &rsa) <= 0)
        croak("Unable to generate the key");
        /* Error */

    CHECK_OPEN_SSL(rsa != NULL);
    EVP_PKEY_CTX_free(ctx);
#else
    rsa = RSA_generate_key(SvIV(bitsSV), exponent, NULL, NULL);
    CHECK_OPEN_SSL(rsa != -1);
#endif
    CHECK_OPEN_SSL(rsa);
    RETVAL = make_rsa_obj(proto, rsa);
  OUTPUT:
    RETVAL


SV*
_new_key_from_parameters(proto, n, e, d, p, q)
    SV* proto;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
  PREINIT:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY *rsa = NULL;
#else
    RSA* rsa;
#endif
    BN_CTX* ctx;
    BIGNUM* p_minus_1 = NULL;
    BIGNUM* q_minus_1 = NULL;
    BIGNUM* dmp1 = NULL;
    BIGNUM* dmq1 = NULL;
    BIGNUM* iqmp = NULL;
    int error;
  CODE:
{
    if (!(n && e))
    {
        croak("At least a modulus and public key must be provided");
    }
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL)
        croak("Error: failed to construct params from build");
    if ( EVP_PKEY_fromdata_init(pctx) <= 0)
        croak("Error: EVP_PKEY_fromdata_init failed");
    OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
    if ( ! params_build )
        croak ("OSSL_PARAM_BLD_new error");
    BIGNUM* nt = BN_new();
#else
    CHECK_OPEN_SSL(rsa = RSA_new());
#endif
#if OLD_CRUFTY_SSL_VERSION
    rsa->n = n;
    rsa->e = e;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_N, n) )
        croak ("OSSL_PARAM_BLD_push_BN 'n' error");

    if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_E, e) )
        croak ("OSSL_PARAM_BLD_push_BN 'e' error");
#endif
    if (p || q)
    {
        error = 0;
        THROW(ctx = BN_CTX_new());
        if (!p)
        {
            THROW(p = BN_new());
            THROW(BN_div(p, NULL, n, q, ctx));
        }
        else if (!q)
        {
            q = BN_new();
            THROW(BN_div(q, NULL, n, p, ctx));
        }
#if OLD_CRUFTY_SSL_VERSION
        rsa->p = p;
        rsa->q = q;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#else
        THROW(RSA_set0_factors(rsa, p, q));
#endif
#endif
        THROW(p_minus_1 = BN_new());
        THROW(BN_sub(p_minus_1, p, BN_value_one()));
        THROW(q_minus_1 = BN_new());
        THROW(BN_sub(q_minus_1, q, BN_value_one()));
        if (!d)
        {
            THROW(d = BN_new());
            THROW(BN_mul(d, p_minus_1, q_minus_1, ctx));
            THROW(BN_mod_inverse(d, e, d, ctx));
        }
#if OLD_CRUFTY_SSL_VERSION
        rsa->d = d;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_D, d) )
            croak ("OSSL_PARAM_BLD_push_BN 'd' error");
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_FACTOR1, p) )
            croak ("OSSL_PARAM_BLD_push_BN 'p' error");
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_FACTOR2, q) )
            croak ("OSSL_PARAM_BLD_push_BN 'q' error");
#else
        THROW(RSA_set0_key(rsa, n, e, d));
#endif
#endif
        THROW(dmp1 = BN_new());
        THROW(BN_mod(dmp1, d, p_minus_1, ctx));
        THROW(dmq1 = BN_new());
        THROW(BN_mod(dmq1, d, q_minus_1, ctx));
        THROW(iqmp = BN_new());
        THROW(BN_mod_inverse(iqmp, q, p, ctx));
#if OLD_CRUFTY_SSL_VERSION
        rsa->dmp1 = dmp1;
        rsa->dmq1 = dmq1;
        rsa->iqmp = iqmp;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) )
            croak ("OSSL_PARAM_BLD_push_BN 'dmp1' error");
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) )
            croak ("OSSL_PARAM_BLD_push_BN 'dmq1' error");
        if ( !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp) )
            croak ("OSSL_PARAM_BLD_push_BN 'iqmp' error");

        OSSL_PARAM *params = NULL;
        params = OSSL_PARAM_BLD_to_param(params_build);
        if ( params == NULL )
            croak("Error: failed to construct params from build");

        int status = EVP_PKEY_fromdata(pctx, &rsa, EVP_PKEY_KEYPAIR, params);
        if ( status <= 0 || rsa == NULL )
            croak("Unable to build key");
        EVP_PKEY_CTX* testctx = EVP_PKEY_CTX_new(rsa, NULL);
        if (!testctx) croak("Testing key failed");
        EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &nt);
        //BIGNUM *n2;
        //if (EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &n2) <= 0)
        //    croak("Unable VP_PKEY_get_bn_param");
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_N);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_FACTOR1);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_FACTOR2);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_D);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_E);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
        //printf("========================================================================\n");
#else
        THROW(RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp));
#endif
#endif
        dmp1 = dmq1 = iqmp = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        OSSL_PARAM_BLD_free(params_build);
        OSSL_PARAM_free(params);
#else
        THROW(RSA_check_key(rsa) == 1);
#endif
     err:
        if (p_minus_1) BN_clear_free(p_minus_1);
        if (q_minus_1) BN_clear_free(q_minus_1);
        if (dmp1) BN_clear_free(dmp1);
        if (dmq1) BN_clear_free(dmq1);
        if (iqmp) BN_clear_free(iqmp);
        if (ctx) BN_CTX_free(ctx);
        if (error)
        {
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
            EVP_PKEY_free(rsa);
#else
            RSA_free(rsa);
#endif
            CHECK_OPEN_SSL(0);
        }
    }
    else
    {
#if OLD_CRUFTY_SSL_VERSION
        rsa->d = d;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#else
        CHECK_OPEN_SSL(RSA_set0_key(rsa, n, e, d));
#endif
#endif
    }
    RETVAL = make_rsa_obj(proto, rsa);
}
  OUTPUT:
    RETVAL

void
_get_key_parameters(p_rsa)
    rsaData* p_rsa;
PREINIT:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    BIGNUM* d = NULL;
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* dmp1 = NULL;
    BIGNUM* dmq1 = NULL;
    BIGNUM* iqmp = NULL;
#else
    const BIGNUM* n;
    const BIGNUM* e;
    const BIGNUM* d;
    const BIGNUM* p;
    const BIGNUM* q;
    const BIGNUM* dmp1;
    const BIGNUM* dmq1;
    const BIGNUM* iqmp;
#endif
PPCODE:
{
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY* rsa;
#else
    RSA* rsa;
#endif
    rsa = p_rsa->rsa;
#if OLD_CRUFTY_SSL_VERSION
    n = rsa->n;
    e = rsa->e;
    d = rsa->d;
    p = rsa->p;
    q = rsa->q;
    dmp1 = rsa->dmp1;
    dmq1 = rsa->dmq1;
    iqmp = rsa->iqmp;
#else
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_N);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_D);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_E);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_FACTOR1);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_FACTOR2);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2);
        //print_parameter(rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_D, &d);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);
#else
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
#endif
#endif
    XPUSHs(cor_bn2sv(n));
    XPUSHs(cor_bn2sv(e));
    XPUSHs(cor_bn2sv(d));
    XPUSHs(cor_bn2sv(p));
    XPUSHs(cor_bn2sv(q));
    XPUSHs(cor_bn2sv(dmp1));
    XPUSHs(cor_bn2sv(dmq1));
    XPUSHs(cor_bn2sv(iqmp));
}

SV*
encrypt(p_rsa, p_plaintext)
    rsaData* p_rsa;
    SV* p_plaintext;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = rsa_crypt(p_rsa, p_plaintext, EVP_PKEY_encrypt, ENCRYPT);
#else
    RETVAL = rsa_crypt(p_rsa, p_plaintext, RSA_public_encrypt);
#endif
  OUTPUT:
    RETVAL

SV*
decrypt(p_rsa, p_ciphertext)
    rsaData* p_rsa;
    SV* p_ciphertext;
  CODE:
    if (!_is_private(p_rsa))
    {
        croak("Public keys cannot decrypt");
    }
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = rsa_crypt(p_rsa, p_ciphertext, EVP_PKEY_decrypt, DECRYPT);
#else
    RETVAL = rsa_crypt(p_rsa, p_ciphertext, RSA_private_decrypt);
#endif
  OUTPUT:
    RETVAL

SV*
private_encrypt(p_rsa, p_plaintext)
    rsaData* p_rsa;
    SV* p_plaintext;
  CODE:
    if (!_is_private(p_rsa))
    {
        croak("Public keys cannot private_encrypt");
    }
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = rsa_crypt(p_rsa, p_plaintext, EVP_PKEY_sign, PRIVATE_ENCRYPT);
#else
    RETVAL = rsa_crypt(p_rsa, p_plaintext, RSA_private_encrypt);
#endif
  OUTPUT:
    RETVAL

SV*
public_decrypt(p_rsa, p_ciphertext)
    rsaData* p_rsa;
    SV* p_ciphertext;
  CODE:
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    RETVAL = rsa_crypt(p_rsa, p_ciphertext, EVP_PKEY_verify_recover, PUBLIC_DECRYPT);
#else
    RETVAL = rsa_crypt(p_rsa, p_ciphertext, RSA_public_decrypt);
#endif
  OUTPUT:
    RETVAL

int
size(p_rsa)
    rsaData* p_rsa;
  CODE:
    RETVAL = get_key_size(p_rsa);
  OUTPUT:
    RETVAL

int
check_key(p_rsa)
    rsaData* p_rsa;
  CODE:
    if (!_is_private(p_rsa))
    {
        croak("Public keys cannot be checked");
    }
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, p_rsa->rsa, NULL);
    RETVAL = EVP_PKEY_private_check(pctx);
#else
    RETVAL = RSA_check_key(p_rsa->rsa);
#endif
  OUTPUT:
    RETVAL

 # Seed the PRNG with user-provided bytes; returns true if the
 # seeding was sufficient.

int
_random_seed(random_bytes_SV)
    SV* random_bytes_SV;
  PREINIT:
    STRLEN random_bytes_length;
    char* random_bytes;
  CODE:
    random_bytes = SvPV(random_bytes_SV, random_bytes_length);
    RAND_seed(random_bytes, random_bytes_length);
    RETVAL = RAND_status();
  OUTPUT:
    RETVAL

 # Returns true if the PRNG has enough seed data

int
_random_status()
  CODE:
    RETVAL = RAND_status();
  OUTPUT:
    RETVAL

void
use_md5_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode = NID_md5;

void
use_sha1_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_sha1;

#ifdef SHA512_DIGEST_LENGTH

void
use_sha224_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_sha224;

void
use_sha256_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_sha256;

void
use_sha384_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_sha384;

void
use_sha512_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_sha512;
#endif

void
use_ripemd160_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_ripemd160;

#ifdef WHIRLPOOL_DIGEST_LENGTH

void
use_whirlpool_hash(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->hashMode =  NID_whirlpool;

#endif

void
use_no_padding(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->padding = RSA_NO_PADDING;

void
use_pkcs1_padding(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->padding = RSA_PKCS1_PADDING;

void
use_pkcs1_oaep_padding(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->padding = RSA_PKCS1_OAEP_PADDING;

#if OPENSSL_VERSION_NUMBER < 0x30000000L

void
use_sslv23_padding(p_rsa)
    rsaData* p_rsa;
  CODE:
    p_rsa->padding = RSA_SSLV23_PADDING;

#endif

# Sign text. Returns the signature.

SV*
sign(p_rsa, text_SV)
    rsaData* p_rsa;
    SV* text_SV;
  PREINIT:
    char* signature;
    unsigned char* digest;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    size_t signature_length;
#else
    unsigned int signature_length;
#endif
  CODE:
{
    if (!_is_private(p_rsa))
    {
        croak("Public keys cannot sign messages");
    }

    CHECK_NEW(signature, get_key_size(p_rsa), char);

    CHECK_OPEN_SSL(digest = get_message_digest(text_SV, p_rsa->hashMode));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(p_rsa->rsa, NULL /* no engine */);
    if (!ctx)
        printf("sign: Failed to create ctx EVP_PKEY_CTX_new()\n");
    if(!EVP_PKEY_sign_init(ctx)) {
        printf("sign: Failed to initialize signing\n");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0) {
        printf("sign: Failed to set padding EVP_PKEY_CTX_set_rsa_padding\n");
    }
    EVP_MD* md = get_md_bynid(p_rsa->hashMode);
    if (md == NULL) {
        printf("Unknown message digest %i\n", p_rsa->hashMode);
    }
    int md_status;
    if ((md_status = EVP_PKEY_CTX_set_signature_md(ctx, md)) <= 0) {

        printf("sign: Failed to set signature md: %i\n", md_status);
    }
    /* Determine buffer length */
    if (EVP_PKEY_sign(ctx, NULL, &signature_length, digest, get_digest_length(p_rsa->hashMode)) <= 0)
        printf("sign: Failed to determine buffer length\n");

    signature = OPENSSL_malloc(signature_length);

    if (!signature)
        printf("sign: Failed to alocate length\n");
    /* malloc failure */

    if (EVP_PKEY_sign(ctx, signature, &signature_length, digest, get_digest_length(p_rsa->hashMode)) <= 0)
        printf("sign: failed calling EVP_PKEY_sign %s\n", signature);
    /* Error */
    /*
    EVP_PKEY_sign(ctx,
                  (unsigned char*) signature, &signature_length,
                  const unsigned char *tbs, size_t tbslen);

     Error */
    CHECK_OPEN_SSL(signature);
#else
    CHECK_OPEN_SSL(RSA_sign(p_rsa->hashMode,
                            digest,
                            get_digest_length(p_rsa->hashMode),
                            (unsigned char*) signature,
                            &signature_length,
                            p_rsa->rsa));
#endif
    RETVAL = newSVpvn(signature, signature_length);
    Safefree(signature);
}
  OUTPUT:
    RETVAL

# Verify signature. Returns true if correct, false otherwise.

void
verify(p_rsa, text_SV, sig_SV)
    rsaData* p_rsa;
    SV* text_SV;
    SV* sig_SV;
PPCODE:
{
    unsigned char* sig;
    unsigned char* digest;
    STRLEN sig_length;

    sig = (unsigned char*) SvPV(sig_SV, sig_length);
    if (get_key_size(p_rsa) < sig_length)
    {
        croak("Signature longer than key");
    }

    CHECK_OPEN_SSL(digest = get_message_digest(text_SV, p_rsa->hashMode));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(p_rsa->rsa, NULL /* no engine */);
    if (!ctx)
        printf("sign: Failed to create ctx EVP_PKEY_CTX_new()\n");
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        printf("verify: Failed to intialize EVP_PKEY_verify_init\n");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, p_rsa->padding) <= 0)
        printf("verify: Failed to set the PADDING\n");
    EVP_MD* md = get_md_bynid(p_rsa->hashMode);
    if (md == NULL) {
        printf("Unknown message digest %i\n", p_rsa->hashMode);
    }
    int md_status;
    if ((md_status = EVP_PKEY_CTX_set_signature_md(ctx, md)) <= 0) {

        printf("sign: Failed to set signature md: %i\n", md_status);
    }
    switch (EVP_PKEY_verify(ctx, sig, sig_length, digest, get_digest_length(p_rsa->hashMode)))
#else
    switch(RSA_verify(p_rsa->hashMode,
                      digest,
                      get_digest_length(p_rsa->hashMode),
                      sig,
                      sig_length,
                      p_rsa->rsa))
#endif
    {
        case 0:
            ERR_clear_error();
            XSRETURN_NO;
            break;
        case 1:
            XSRETURN_YES;
            break;
        default:
            CHECK_OPEN_SSL(0);
            break;
    }
}

int
is_private(p_rsa)
    rsaData* p_rsa;
  CODE:
    RETVAL = _is_private(p_rsa);
  OUTPUT:
    RETVAL
