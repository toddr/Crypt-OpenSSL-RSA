#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>

/* Key names for the rsa hash structure */

#define KEY_KEY "_Key"
#define PRIVATE_FLAG_KEY "private_flag"
#define PADDING_MODE_KEY "_Padding_Mode"
#define HASH_KEY "_Hash_Mode"

#define HASH_MD5 1
#define HASH_SHA1 2
#define HASH_RIPEMD160 3

#define PACKAGE_NAME "Crypt::OpenSSL::RSA"

/* convenience hv routines - I'm lazy */

void hvStore(HV *hv, char *key, SV *value)
{
    hv_delete(hv, key, strlen(key), G_DISCARD);

    if( hv_store(hv, key, strlen(key), value, 0) != NULL)
    {
        SvREFCNT_inc(value);
    }
}

SV **hvFetch(HV *hv, char *key)
{
    return hv_fetch(hv, key, strlen(key), 0);
}

/* Free the RSA key, if there is one */
void free_RSA_key(HV *rsa_HV)
{
    SV **rsa_ptr_SV_ptr;
    RSA *rsa;

    rsa_ptr_SV_ptr = hvFetch(rsa_HV, KEY_KEY);
    if( rsa_ptr_SV_ptr != NULL )
    {
        RSA_free ((RSA*) SvIV (*rsa_ptr_SV_ptr));
        hv_delete(rsa_HV, KEY_KEY, strlen(KEY_KEY), G_DISCARD);
    }
}

RSA* get_RSA_key(HV *rsa_HV)
{
    SV **rsa_ptr_SV_ptr;
    RSA *rsa;

    rsa_ptr_SV_ptr = hvFetch(rsa_HV, KEY_KEY);
    if( rsa_ptr_SV_ptr == NULL )
    {
        croak( "There is no key set" );
    }
    else
    {
        return (RSA*) SvIV (*rsa_ptr_SV_ptr);
    }
}

void set_RSA_key(HV *rsa_HV, RSA *rsa)
{
    hvStore( rsa_HV, KEY_KEY, sv_2mortal( newSViv( (I32)rsa ) ) );
}

int get_padding_mode(HV *rsa_HV)
{
    SV **padding_mode;

    padding_mode = hvFetch(rsa_HV, PADDING_MODE_KEY);
    return padding_mode == NULL ? -1 : SvIV(*padding_mode);
}

int get_hash(HV *rsa_HV)
{
    SV **hash;

    hash = hvFetch(rsa_HV, HASH_KEY);
    return hash == NULL ? -1 : SvIV(*hash);
}

char get_private_flag(HV *rsa_HV)
{
    SV **private_flag;

    private_flag = hvFetch(rsa_HV, PRIVATE_FLAG_KEY);
    return private_flag == NULL ? -1 : SvTRUE( *private_flag );
}

void set_private_flag(HV *rsa_HV, char private_flag)
{
    hvStore( rsa_HV, PRIVATE_FLAG_KEY, sv_2mortal( newSViv( private_flag ) ) );
}


HV* get_HV_from_SV_ref(SV *hv_ref)
{
    HV *hv;
    if (! ( SvROK( hv_ref ) && sv_isa( hv_ref, PACKAGE_NAME ) ) )
    {
        croak( "scalar is not a " PACKAGE_NAME " object" );
    }
    if (SvTYPE((SV *)hv = SvRV(hv_ref)) != SVt_PVHV)
    {
        croak( "Passed scalar is not a hash reference" );
    }
    return hv;
}

int get_digest_length( int hash_method )
{
    switch( hash_method )
    {
        case HASH_MD5:
            return 16;
            break;
        case HASH_SHA1:
            return 20;
            break;
        case HASH_RIPEMD160:
            return 20;
            break;
        default:
            croak( "Unknown digest hash code" );
            break;
    }
}

int get_hash_type( int hash_method )
{
    switch( hash_method )
    {
        case HASH_MD5:
            return NID_md5;
            break;
        case HASH_SHA1:
            return NID_sha1;
            break;
        case HASH_RIPEMD160:
            return NID_ripemd160;
    }
}

char* get_message_digest( SV *text_SV, int hash_method )
{
    int text_length;
    unsigned char *text, *message_digest;

    text = SvPV(text_SV, text_length);

    if( New(0, message_digest, get_digest_length(hash_method), char) == NULL )
    {
        croak ( "unable to allocate buffer for message digest in package "
                PACKAGE_NAME );
    }

    switch( hash_method )
    {
        case HASH_MD5:
        {
            if( MD5(text, text_length, message_digest) == NULL )
            {
                croak( "failed to compute the MD5 message digest in package "
                       PACKAGE_NAME );
            }
            break;
        }
        case HASH_SHA1:
        {
            if( SHA1( text, text_length, message_digest ) == NULL )
            {
                croak( "failed to compute the SHA1 message digest in package "
                       PACKAGE_NAME );
            }
            break;
        }
        case HASH_RIPEMD160:
        {
            if( RIPEMD160( text, text_length, message_digest ) == NULL )
            {
                croak( "failed to compute the SHA1 message digest in package "
                       PACKAGE_NAME );
            }
            break;
        }
        default:
        {
            croak( "Unknown digest hash code" );
            break;
        }
    }
    return message_digest;
}


MODULE = Crypt::OpenSSL::RSA		PACKAGE = Crypt::OpenSSL::RSA

BOOT:
    ERR_load_crypto_strings();

void
_load_key(rsa_HV_ref, private_flag_SV, key_string_SV)
     SV * rsa_HV_ref;
     SV * private_flag_SV;
     SV * key_string_SV;
PPCODE:
{
    int key_string_length;  /* Needed to pass to SvPV */
    char *key_string;
    char private_flag;
    RSA *rsa;
    HV *rsa_HV;
    BIO *stringBIO;

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );

    /* First, remove any old rsa structures, to avoid leakage */
    free_RSA_key(rsa_HV);

    private_flag = SvTRUE( private_flag_SV );
    set_private_flag( rsa_HV, private_flag );
    key_string = SvPV( key_string_SV, key_string_length );

    if( (stringBIO = BIO_new_mem_buf(key_string, key_string_length)) == NULL )
    {
        croak( "Failed to create memory BIO" );
    }

    rsa = private_flag
        ? PEM_read_bio_RSAPrivateKey( stringBIO, NULL, NULL, NULL )
        : PEM_read_bio_RSAPublicKey( stringBIO, NULL, NULL, NULL );

    BIO_set_close(stringBIO, BIO_CLOSE);
    BIO_free( stringBIO );

    if ( rsa == NULL )
    {
        croak( "Failed to read key" );
    }
    set_RSA_key(rsa_HV, rsa);
}

void
_free_RSA_key(rsa_HV_ref)
     SV * rsa_HV_ref;
PPCODE:
{
    free_RSA_key( get_HV_from_SV_ref( rsa_HV_ref ) );
}

void
_get_key_string(rsa_HV_ref, private_flag_SV)
     SV * rsa_HV_ref;
     SV * private_flag_SV;
PPCODE:
{
    BUF_MEM *bptr;
    BIO *stringBIO;
    RSA *rsa;

    stringBIO = BIO_new( BIO_s_mem() );
    if (stringBIO == NULL)
    {
        croak( "Failed to create memory BIO" );
    }

    rsa = get_RSA_key( get_HV_from_SV_ref( rsa_HV_ref ) );
    if( SvTRUE( private_flag_SV ) )
    {
      PEM_write_bio_RSAPrivateKey(stringBIO, rsa, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
      PEM_write_bio_RSAPublicKey(stringBIO, rsa);
    }

    BIO_flush(stringBIO);
    BIO_get_mem_ptr(stringBIO, &bptr);

    XPUSHs( sv_2mortal( newSVpv ( bptr->data, bptr->length ) ) );

    BIO_set_close(stringBIO, BIO_CLOSE);
    BIO_free(stringBIO);
    XSRETURN(1);
}

 #
 # Generate a new RSA key.  The optional third argument is a prime.
 # It defaults to 65535
 #

void
generate_key(rsa_HV_ref, bitsSV, ...)
     SV *rsa_HV_ref;
     SV *bitsSV;
PPCODE:
{
    RSA *rsa;
    unsigned long exponent;
    HV *rsa_HV;

    if (items > 3)
    {
        croak( "Usage: rsa->generate_key($bits [, $exponent])" );
    }

    exponent = ( items == 3 ) ? SvIV(ST(2)) : 65535;
    rsa = RSA_generate_key( SvIV(bitsSV), exponent, NULL, NULL );

    if(rsa == NULL)
    {
        croak( "OpenSSL error: %s",
               ERR_reason_error_string( ERR_get_error() ) );
    }

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );
    set_RSA_key(rsa_HV, rsa);
    set_private_flag(rsa_HV, 1);
}

# Encrypt plain text into cipher text.  Returns the cipher text

void
encrypt(rsa_HV_ref, plaintext_SV, ...)
     SV *rsa_HV_ref;
     SV *plaintext_SV;
PPCODE:
{
    int plaintext_length;
    unsigned char *plaintext, *ciphertext;
    size_t size;
    int ciphertext_length;
    RSA *rsa;
    HV *rsa_HV;

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );

    plaintext = SvPV(plaintext_SV, plaintext_length);

    rsa = get_RSA_key(rsa_HV);

    size = RSA_size(rsa);
    if( New( 0,ciphertext, size, char ) == NULL )
    {
        croak ( "unable to allocate buffer for ciphertext in package "
                PACKAGE_NAME );
    }

    ciphertext_length = RSA_public_encrypt( plaintext_length,
                                            plaintext,
                                            ciphertext,
                                            rsa,
                                            get_padding_mode(rsa_HV) );

    if (ciphertext_length < 0)
    {
        Safefree(ciphertext);
        croak( "OpenSSL error: %s",
               ERR_reason_error_string( ERR_get_error() ) );
    }

    XPUSHs(sv_2mortal(newSVpv(ciphertext, size)));
    Safefree(ciphertext);
    XSRETURN(1);
}

# Decrypt cipher text into plain text.  Returns the plain text
void
decrypt(rsa_HV_ref, ciphertext_SV)
     SV * rsa_HV_ref;
     SV * ciphertext_SV;
PPCODE:
{
    int ciphertext_length;  /* Needed to pass to SvPV */
    int plaintext_length;
    char *plaintext, *ciphertext;
    unsigned long size;
    RSA *rsa;
    SV **private_flag_SV_ptr;
    HV *rsa_HV;

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );

    if( ! get_private_flag( rsa_HV ) )
    {
      croak("Public keys cannot decrypt messages.");
    }

    ciphertext = SvPV(ciphertext_SV, ciphertext_length);

    rsa = get_RSA_key(rsa_HV);
    size = RSA_size(rsa);
    if( New( 0, plaintext, size, char ) == NULL )
    {
        croak( "unable to allocate buffer for plaintext in package "
               PACKAGE_NAME );
    }

    plaintext_length = RSA_private_decrypt(size,
                                           ciphertext,
                                           plaintext,
                                           rsa,
                                           get_padding_mode(rsa_HV) );
    if( plaintext_length < 0 )
    {
        Safefree(plaintext);
        croak( "OpenSSL error: %s",
               ERR_reason_error_string( ERR_get_error() ) );
    }

    XPUSHs(sv_2mortal(newSVpv(plaintext, plaintext_length)));
    Safefree(plaintext);
    XSRETURN(1);
}

void
size(rsa_HV_ref)
     SV * rsa_HV_ref;
PPCODE:
{
    XPUSHs( sv_2mortal( newSViv(
                            RSA_size(
                                get_RSA_key(
                                    get_HV_from_SV_ref( rsa_HV_ref ) ) ) ) ) );
    XSRETURN(1);
}

void
check_key(rsa_HV_ref)
     SV * rsa_HV_ref;
PPCODE:
{
    XPUSHs( sv_2mortal(
                newSViv(
                    RSA_check_key(
                        get_RSA_key( get_HV_from_SV_ref(rsa_HV_ref) ) ) ) ) );
    XSRETURN(1);
}

 # Seed the PRNG with user-provided bytes; returns true if the
 # seeding was sufficient.

void
_random_seed(random_bytes_SV)
   SV * random_bytes_SV;
PPCODE:
{
   int random_bytes_length;
   char *random_bytes;
   random_bytes = SvPV(random_bytes_SV, random_bytes_length);
   RAND_seed(random_bytes, random_bytes_length);
   XPUSHs( sv_2mortal( newSViv( RAND_status() ) ) );
}

 # Returns true if the PRNG has enough seed data

void
_random_status()
PPCODE:
{
    XPUSHs( sv_2mortal( newSViv( RAND_status() ) ) );
}

# Sign text. Returns the signature.

void
sign (rsa_HV_ref, text_SV, ...)
     SV *rsa_HV_ref;
     SV *text_SV;
PPCODE:
{
    unsigned char *signature;
    char *digest;
    int signature_length;
    int hash;
    RSA *rsa;
    HV *rsa_HV;

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );

    if( ! get_private_flag( rsa_HV ) )
    {
        croak("Public keys cannot sign messages.");
    }

    rsa = get_RSA_key( rsa_HV );

    if( New( 0, signature, RSA_size(rsa), char ) == NULL)
    {
        croak( "unable to allocate buffer for ciphertext in package "
               PACKAGE_NAME );
    }

    hash = get_hash( rsa_HV );
    digest = get_message_digest( text_SV, hash );
    if ( ! RSA_sign( get_hash_type( hash ),
                     digest, // get_message_digest( text_SV, hash ),
                     get_digest_length( hash ),
                     signature,
                     &signature_length,
                     rsa ) )
    {
        croak( "OpenSSL error: %s",
               ERR_reason_error_string( ERR_get_error() ) );
    }
    free(digest);
    XPUSHs( sv_2mortal( newSVpvn( signature, signature_length ) ) );
    Safefree( signature );
    XSRETURN(1);
}

# Verify signature. Returns 1 if correct, 0 otherwise.

void
verify (rsa_HV_ref, text_SV, sig_SV, ...)
    SV *rsa_HV_ref;
    SV *text_SV;
    SV *sig_SV;
PPCODE:
{
    unsigned char *sig;
    char *digest;
    RSA *rsa;
    HV *rsa_HV;
    int sig_length;
    int hash;
    int result;

    rsa_HV = get_HV_from_SV_ref( rsa_HV_ref );

    if( get_private_flag( rsa_HV ) )
    {
        croak("Secret keys should not check signatures.");
    }

    sig = SvPV( sig_SV, sig_length );
    rsa = get_RSA_key(rsa_HV);
    if (RSA_size(rsa) < sig_length)
    {
        croak( "Signature longer than key" );
    }

    hash = get_hash( rsa_HV );
    digest = get_message_digest( text_SV, hash );
    result = RSA_verify( get_hash_type( hash ),
                         digest,
                         get_digest_length( hash ),
                         sig,
                         sig_length,
                         rsa );
    free( digest );
    switch( result )
    {
        case 0:
            XSRETURN_NO;
            break;
        case 1:
            XSRETURN_YES;
            break;
        default:
            croak ( "something went wrong in " PACKAGE_NAME );
            break;
    }
}
