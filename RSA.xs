#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "rsaLib.h"

/* Key names for the rsa hash structure */

#define PUBLIC_KEY_STRING_KEY "public_key_string"
#define PRIVATE_KEY_STRING_KEY "private_string_key"
#define KEY_KEY "key"
#define PRIVATE_FLAG_KEY "private_flag"
#define PADDING_MODE_KEY "padding_mode"

#define PACKAGE_NAME "Crypt::OpenSSL::RSA"    

/* convenience hv routines - I'm lazy */

void hvStore(HV *hv, char *key, SV *value)
{
    hv_delete(hv, key, strlen(key), G_DISCARD);
        
    if( hv_store(hv, key, strlen(key), value, 0) != NULL)
        SvREFCNT_inc(value);
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
    if (rsa_ptr_SV_ptr == NULL)
        return;
    else
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
    if (rsa_ptr_SV_ptr == NULL)
        return NULL;
    else
        return (RSA*) SvIV (*rsa_ptr_SV_ptr);
}

void set_RSA_key(HV *rsa_HV, RSA *rsa, char private_flag)
{
    hvStore(rsa_HV, KEY_KEY, newSViv((I32)rsa));
}

SV** get_RSA_key_string_ptr(HV *rsa_HV, char private_flag)
{
    return
        hvFetch(rsa_HV, 
                private_flag ? PRIVATE_KEY_STRING_KEY : PUBLIC_KEY_STRING_KEY);
}

SV* set_RSA_key_string(HV *rsa_HV, SV *key_string_SV, char private_flag)
{
    hvStore(rsa_HV, 
             private_flag ? PRIVATE_KEY_STRING_KEY : PUBLIC_KEY_STRING_KEY,
             key_string_SV);
}

int get_padding_mode(HV *rsa_HV)
{
    SV **padding_mode;

    padding_mode = hvFetch(rsa_HV, PADDING_MODE_KEY);
    if (padding_mode == NULL)
        return -1;
    else
        return SvIV(*padding_mode);
}

void set_padding_mode(HV *rsa_HV, int padding_mode)
{
    hvStore(rsa_HV, PADDING_MODE_KEY, newSViv(padding_mode));
}
    

char get_private_flag(HV *rsa_HV)
{
    SV **private_flag;

    private_flag = hvFetch(rsa_HV, PRIVATE_FLAG_KEY);
    if (private_flag == NULL)
        return -1;
    else
        return SvTRUE(*private_flag);
}

void set_private_flag(HV *rsa_HV, char private_flag)
{
    hvStore(rsa_HV, PRIVATE_FLAG_KEY, newSViv(private_flag));
}
    

HV* get_HV_from_SV_ref(SV *hv_ref, char **error)
{
    HV *hv;
    if (! ( SvROK(hv_ref) && sv_isa(hv_ref, PACKAGE_NAME) ) )
    {
      *error = "scalar is not a " PACKAGE_NAME " object";
      return NULL;
    }
    if (SvTYPE((SV *)hv = SvRV(hv_ref)) != SVt_PVHV)
    {
      *error = "Passed scalar is not a hash reference";
      return NULL;
    }
    return hv;
}


MODULE = Crypt::OpenSSL::RSA		PACKAGE = Crypt::OpenSSL::RSA		

void
_load_key(rsa_HV_ref, private_flag_SV, key_string_SV)
     SV * rsa_HV_ref;
     SV * private_flag_SV;
     SV * key_string_SV;
PPCODE:
{
    int key_string_length;  /* Needed to pass to SvPV */
    char *key_string;
    char *error;
    char private_flag;
    RSA *rsa;
    HV *rsa_HV;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);

    /* First, remove any old rsa structures, to avoid leakage */
    free_RSA_key(rsa_HV);

    key_string = SvPV(key_string_SV, key_string_length);

    private_flag = SvTRUE(private_flag_SV);

    set_RSA_key_string(rsa_HV, key_string_SV, private_flag);
    set_private_flag(rsa_HV, private_flag);
    rsa = loadKey(private_flag, key_string);
    
    if (rsa == NULL)
        XSRETURN_NO;

    set_RSA_key(rsa_HV, rsa, private_flag);

    XSRETURN_YES;
}

void
_free_RSA_key(rsa_HV_ref)
     SV * rsa_HV_ref;
PPCODE:
{
    HV *rsa_HV;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) !=NULL )
        free_RSA_key(rsa_HV);

    XSRETURN_YES;
}

void
_get_key_string(rsa_HV_ref, private_flag_SV)
     SV * rsa_HV_ref;
     SV * private_flag_SV;
PPCODE:
{
    char *key_string;
    RSA *rsa;
    SV **key_string_SV;
    HV *rsa_HV;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);
    /* Let's see if we already have the string. */

    key_string_SV = get_RSA_key_string_ptr(rsa_HV, SvTRUE(private_flag_SV));

    if(key_string_SV != NULL)
    {
        XPUSHs(sv_2mortal(*key_string_SV));
        XSRETURN(1);
    }

    /* OK - time to generate it... */

    rsa = get_RSA_key(rsa_HV);

    if(rsa == NULL)
    {
        XSRETURN_NO;
    }
    
    key_string =  makeKeyString(SvTRUE(private_flag_SV), rsa);
    XPUSHs(sv_2mortal(newSVpv(key_string,0)));
    

    XSRETURN(1); 
}

 #
 # Generate a new RSA key.  The optional third argument is a prime.
 # It defaults to 65536
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
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);

    if (items > 3)
        croak("Usage: rsa->generate_key($bits [, $exponent])");

    if (items == 3)
        exponent = SvIV(ST(2));
    else
        exponent = 65535;
    
    rsa = RSA_generate_key(1024, 65535, NULL, NULL);

    if(rsa == NULL)
        XSRETURN_NO;

    set_private_flag(rsa_HV, 1);
    set_RSA_key(rsa_HV, rsa, 1);

    XSRETURN_YES;
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
    int padding_mode;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);

    plaintext = SvPV(plaintext_SV, plaintext_length);

    rsa = get_RSA_key(rsa_HV);
    if (rsa == NULL)
        croak("There is no key to encrypt with");

    size = RSA_size(rsa);
    if(New(0,ciphertext, size, char) == NULL)
    {
        croak ("unable to allocate buffer for ciphertext in package "
            PACKAGE_NAME);
    }

    padding_mode = get_padding_mode(rsa_HV);

    ciphertext_length = RSA_public_encrypt(plaintext_length,
                                      plaintext, ciphertext, rsa, 
                                      padding_mode);

    if (ciphertext_length < 0)
    {
        Safefree(ciphertext);
        XSRETURN_NO;
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
    int padding_mode;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);

    if(!get_private_flag(rsa_HV))
    {
      croak("Public keys cannot decrypt messages.");
    }

    ciphertext = SvPV(ciphertext_SV, ciphertext_length);

    rsa = get_RSA_key(rsa_HV);
    if (rsa == NULL)
    {
        XSRETURN_NO;
    }
    size = RSA_size(rsa);
    if(New(0,plaintext, size, char) == NULL)
    {
        croak ("unable to allocate buffer for plaintext in package "
            PACKAGE_NAME);
    }

    padding_mode = get_padding_mode(rsa_HV);

    plaintext_length = RSA_private_decrypt(size, ciphertext, plaintext, rsa,
                                           padding_mode);
    if (plaintext_length < 0)
    {
        Safefree(plaintext);
        XSRETURN_NO;
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
    HV *rsa_HV;
    RSA *rsa;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);
    if( (rsa = get_RSA_key(rsa_HV)) == NULL )
        croak ("Crypt::OpenSSL::RSA object contains no key");

    XPUSHs( sv_2mortal( newSViv( RSA_size(rsa) )));
    XSRETURN(1);
}

void
check_key(rsa_HV_ref)
     SV * rsa_HV_ref;
PPCODE:
{
    HV *rsa_HV;
    RSA *rsa;
    char *error;

    if( (rsa_HV = get_HV_from_SV_ref(rsa_HV_ref, &error)) == NULL )
        croak(error);
    if( (rsa = get_RSA_key(rsa_HV)) == NULL )
        croak ("Crypt::OpenSSL::RSA object contains no key");

    XPUSHs( sv_2mortal( newSViv( RSA_check_key(rsa) )));
    XSRETURN(1);
}
