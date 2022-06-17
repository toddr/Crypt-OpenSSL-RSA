package Crypt::OpenSSL::RSA::FFI;
use strict;
use warnings;
use Carp qw< croak >;
use FFI::Platypus 1.00;
use FFI::CheckLib 0.06 qw< find_lib_or_die >;
use FFI::Platypus::Memory qw< memset free malloc >;
use FFI::TinyCC;

use constant {
    'BIO_CTRL_INFO'        => 3,
    'BIO_CLOSE'            => 0x01,
    'BIO_CTRL_SET_CLOSE'   => 9,
    'BIO_CTRL_FLUSH'       => 11,
    'BIO_FLAGS_MEM_RDONLY' => 0x200,

    'OSSL_KEYMGMT_SELECT_PRIVATE_KEY'       => 0x01,
    'OSSL_KEYMGMT_SELECT_PUBLIC_KEY'        => 0x02,
    'OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS' => 0x04,
    'OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS'  => 0x80,
};

use constant 'OSSL_KEYMGMT_SELECT_ALL_PARAMETERS' => OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS()
                                                   | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS();

use constant 'OSSL_KEYMGMT_SELECT_KEYPAIR' => OSSL_KEYMGMT_SELECT_PRIVATE_KEY()
                                            | OSSL_KEYMGMT_SELECT_PUBLIC_KEY();

use constant 'OSSL_KEYMGMT_SELECT_ALL' => OSSL_KEYMGMT_SELECT_KEYPAIR()
                                        | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS();


use constant 'EVP_PKEY_KEY_PARAMETERS' => OSSL_KEYMGMT_SELECT_ALL_PARAMETERS();

use constant 'EVP_PKEY_PUBLIC_KEY' => EVP_PKEY_KEY_PARAMETERS()
                                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY();

use constant 'EVP_PKEY_KEYPAIR' => EVP_PKEY_PUBLIC_KEY()
                                 | OSSL_KEYMGMT_SELECT_PRIVATE_KEY();

#-----#
# TCC #
#-----#

my $tcc       = FFI::TinyCC->new();
my $crypto_so = './openssl/libcrypto.so'; # find_lib_or_die( 'lib' => 'crypto');
my $ssl_so    = './openssl/libssl.so'; # find_lib_or_die( 'lib' => 'ssl');
$tcc->detect_sysinclude_path();
$tcc->add_file($crypto_so);
$tcc->add_file($ssl_so);

# TODO: Support padding
# TODO: Should load_public_key be removed? (public get can be gotten after private key)

$tcc->compile_string(q@
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <stdio.h>

EVP_PKEY *load_private_key( const char *stringBIO, const char *passphrase )
{
    int rv                 = 0;
    EVP_PKEY *pkey         = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection          = 0;

    BIO* bio = BIO_new_mem_buf(stringBIO, -1);
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA",
                                         selection,
                                         NULL, NULL);
    if (dctx == NULL)
        goto cleanup;

    if (passphrase != NULL) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx,
                                            (const unsigned char *)passphrase,
                                            strlen(passphrase)) == 0)
            goto cleanup;
    }

    if ( OSSL_DECODER_from_bio(dctx, bio) == 0 )
        goto cleanup;

    if ( BIO_set_close(bio, BIO_CLOSE) != 1 )
        goto cleanup;

    rv = 1;
cleanup:
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);

    if (rv == 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}

EVP_PKEY *load_public_key( const char *stringBIO, const char *passphrase )
{
    int rv                 = 0;
    EVP_PKEY *pkey         = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection          = EVP_PKEY_PUBLIC_KEY;

    BIO* bio = BIO_new_mem_buf(stringBIO, -1);
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA",
                                         selection,
                                         NULL, NULL);
    if (dctx == NULL)
        goto cleanup;

    if (passphrase != NULL) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx,
                                            (const unsigned char *)passphrase,
                                            strlen(passphrase)) == 0)
            goto cleanup;
    }

    if ( OSSL_DECODER_from_bio(dctx, bio) == 0 )
        goto cleanup;

    if ( BIO_set_close(bio, BIO_CLOSE) != 1 )
        goto cleanup;

    rv = 1;
cleanup:
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);

    if (rv == 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}

char *load_private_key_string( EVP_PKEY *pkey, const char *passphrase, BIO *bio, OSSL_ENCODER_CTX *ectx )
{
    BIO **bio_p      = &bio;
    int rv           = 0;
    char *key_string = NULL;
    long length      = 0;

    if ( passphrase != NULL ) {
        OSSL_ENCODER_CTX_set_passphrase( ectx, passphrase, strlen(passphrase) );
    }


    BIO *p = BIO_new( BIO_s_mem() );
    int foo = BIO_up_ref(p);

    // *bio_p = BIO_new( BIO_s_mem() );
    if ( *bio_p == NULL )
        return NULL;

    if ( OSSL_ENCODER_to_bio( ectx, *bio_p ) == NULL )
        goto cleanup;

    if ( BIO_flush(*bio_p) <= 0 )
        goto cleanup;

    length = BIO_get_mem_data( *bio_p, &key_string );
    key_string[length] = '\0';

cleanup:
    OSSL_ENCODER_CTX_free(ectx);

    return key_string;
}

char *read_bio( BIO *bio )
{
    char *key_string = NULL;
    long length      = 0;

    if ( BIO_flush(bio) <= 0 )
        goto cleanup;

    length = BIO_get_mem_data( bio, &key_string );
    key_string[length] = '\0';

cleanup:
    BIO_set_flags( bio , BIO_FLAGS_MEM_RDONLY );
    BIO_free(bio);

    return key_string;
}

char *load_public_key_string( EVP_PKEY *pkey, const char *passphrase, BIO **bio_p )
{
    int rv                 = 0;
    OSSL_ENCODER_CTX *ectx = NULL;
    int selection          = EVP_PKEY_PUBLIC_KEY;
    char *key_string       = NULL;
    long length            = 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", NULL, NULL);

    if ( ectx == NULL )
        return NULL;

    if ( passphrase != NULL ) {
        OSSL_ENCODER_CTX_set_passphrase( ectx, passphrase, strlen(passphrase) );
    }

    *bio_p = BIO_new( BIO_s_mem() );
    if ( *bio_p == NULL )
        return NULL;

    if ( OSSL_ENCODER_to_bio( ectx, *bio_p ) == NULL )
        goto cleanup;

    if ( BIO_flush(*bio_p) <= 0 )
        goto cleanup;

    length = BIO_get_mem_data( *bio_p, &key_string );
    key_string[length] = '\0';

cleanup:
    OSSL_ENCODER_CTX_free(ectx);

    return key_string;
}

char *load_public_key_x509_string( EVP_PKEY *pkey, BIO **bio_p )
{
    int result          = 0;
    long length         = 0;
    char *key_string    = NULL;
    X509_PUBKEY *pubkey = NULL;

    *bio_p = BIO_new( BIO_s_mem() );
    if ( *bio_p == NULL )
        return NULL;

    result = PEM_write_bio_PUBKEY(*bio_p, pkey);
    if ( result != 1 )
        goto end;

    if ( BIO_flush(*bio_p) <= 0 )
        goto end;

    length = BIO_get_mem_data( *bio_p, &key_string );
    key_string[length] = '\0';

end:
    return key_string;
}
@);

#-----#
# FFI #
#-----#

my $ffi = FFI::Platypus->new();
$ffi->lib( $crypto_so, $ssl_so );

{
    my $address;
    $address = $tcc->get_symbol('load_private_key');
    $ffi->attach( [ $address => 'load_private_key' ] => [ 'string', 'string' ] => 'opaque' );

    $address = $tcc->get_symbol('load_public_key');
    $ffi->attach( [ $address => 'load_public_key' ] => [ 'string', 'string' ] => 'opaque' );

    $address = $tcc->get_symbol('load_private_key_string');
    $ffi->attach( [ $address => 'load_private_key_string' ] => [ 'opaque', 'string', 'opaque', 'opaque' ] => 'string' );

    $address = $tcc->get_symbol('load_public_key_string');
    $ffi->attach( [ $address => 'load_public_key_string' ] => [ 'opaque', 'string', 'opaque*' ] => 'string' );

    $address = $tcc->get_symbol('load_public_key_x509_string');
    $ffi->attach( [ $address => 'load_public_key_x509_string' ] => [ 'opaque', 'opaque*' ] => 'string' );

    $address = $tcc->get_symbol('read_bio');
    $ffi->attach( [ $address => 'read_bio' ] => [ 'opaque' ] => 'string' );
}

$ffi->attach( 'PEM_write_bio_PUBKEY' => [ 'opaque', 'opaque' ] => 'int' );

# BN: Bignum
$ffi->attach( 'BN_new' => [] => 'opaque' );
$ffi->attach( 'BN_hex2bn' => [ 'opaque*', 'string' ] => 'int' );

# RAND
$ffi->attach('RAND_status' => [] => 'int' );
$ffi->attach('RAND_seed' => [ 'opaque', 'int' ] => 'void' );

# OSSL_DECODER OSSL_ENCODER
$ffi->attach( 'OSSL_DECODER_CTX_new' => [] => 'opaque' );
$ffi->attach(
    'OSSL_DECODER_CTX_new_for_pkey',
    [ 'opaque', 'string', 'string', 'string', 'int', 'opaque', 'string' ],
    'opaque',
);
$ffi->attach(
    'OSSL_DECODER_CTX_set_passphrase',
    [ 'opaque', 'string', 'int' ],
    'int',
);
$ffi->attach( 'OSSL_DECODER_from_bio' => [ 'opaque', 'opaque' ] => 'int' );
$ffi->attach( 'OSSL_DECODER_CTX_free' => ['opaque'] => 'void' );

$ffi->attach( 'OSSL_ENCODER_CTX_new_for_pkey'   => [ 'opaque', 'int', 'string', 'string', 'string' ] => 'opaque' );
$ffi->attach( 'OSSL_ENCODER_CTX_set_passphrase' => [ 'opaque', 'string', 'int' ]                     => 'int' );
$ffi->attach( 'OSSL_ENCODER_to_bio'             => [ 'opaque', 'opaque' ]                            => 'int' );
$ffi->attach( 'OSSL_ENCODER_CTX_free'           => ['opaque']                                        => 'void' );

# OSSL_PROVIDER
$ffi->attach( 'OSSL_PROVIDER_load' => [ 'opaque', 'string' ] => 'opaque' );
$ffi->attach( 'OSSL_PROVIDER_unload' => [ 'opaque', 'string' ] => 'int' );
$ffi->attach( 'OSSL_PROVIDER_available' => [ 'opaque', 'string' ] => 'int' );

# OSSL_PARAM_BLD: Parameter Builder
$ffi->attach( 'OSSL_PARAM_BLD_new' => [] => 'opaque' );
$ffi->attach( 'OSSL_PARAM_BLD_push_BN' => [ 'opaque', 'string', 'opaque' ] => 'int' );
$ffi->attach( 'OSSL_PARAM_BLD_to_param' => ['opaque'] => 'opaque' );

# BIO: Basic I/O
$ffi->attach( 'BIO_new'   => ['opaque'] => 'opaque' );
$ffi->attach( 'BIO_s_mem' => [] => 'opaque' );
$ffi->attach( 'BIO_new_mem_buf' => [ 'string', 'int' ] => 'opaque' );
$ffi->attach( 'BIO_read' => [ 'opaque', 'opaque', 'int' ] => 'int' );
$ffi->attach( 'BIO_ctrl_pending' => ['opaque'] => 'size_t' );
$ffi->attach( 'BIO_get_line' => [ 'opaque', 'opaque', 'int' ] => 'int' );
$ffi->attach( 'BIO_set_flags' => [ 'opaque', 'int' ] => 'void' );

# BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))
# $ffi->attach( 'BIO_get_mem_data' => ['opaque', 'string*' ] => 'long' );

# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
# long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
#    (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
$ffi->attach( 'BIO_ctrl' => [ 'opaque', 'int', 'long', 'opaque' ] => 'long' );
$ffi->attach( 'BIO_free' => [ 'opaque' ] => 'int' );

# EVP_PKEY
$ffi->attach( 'EVP_PKEY_new'  => []         => 'opaque' );
$ffi->attach( 'EVP_PKEY_free' => ['opaque'] => 'void' );
$ffi->attach( 'EVP_PKEY_CTX_free' => ['opaque'] => 'void' );
$ffi->attach( 'EVP_PKEY_CTX_new_from_pkey' => [ 'opaque', 'opaque', 'opaque' ] => 'opaque' );
$ffi->attach( 'EVP_PKEY_encrypt_init' => ['opaque'] => 'int' );
$ffi->attach( 'EVP_PKEY_CTX_new_from_name' => [ 'opaque', 'string', 'string' ] => 'opaque' );
$ffi->attach( 'EVP_PKEY_fromdata_init' => ['opaque'] => 'int' );
$ffi->attach( 'EVP_PKEY_fromdata' => [ 'opaque', 'opaque*', 'int', 'opaque' ] => 'int' );
$ffi->attach( 'EVP_PKEY_fromdata_settable' => [ 'opaque', 'int' ] => 'opaque' );
$ffi->attach( 'EVP_PKEY_Q_keygen' => [ 'opaque', 'opaque', 'string', 'opaque'] => 'opaque' );

# ERR
$ffi->attach( 'ERR_get_error' => [] => 'unsigned long' );
$ffi->attach( 'ERR_reason_error_string' => [ 'unsigned long' ] => 'string' );
$ffi->attach( 'ERR_clear_error' => [] => 'void' );

#---------#
# Methods #
#---------#

sub croakSSL {
    my $err        = ERR_get_error();
    my $reason_str = ERR_reason_error_string($err);
    ERR_clear_error();
    $reason_str //= '(no error string from OpenSSL)';
    croak("OpenSSL error: $reason_str");
}

sub generate_key {
    my ( $class, $size ) = @_;
    my $key = EVP_PKEY_Q_keygen( undef, undef, 'RSA', $size );
    return $key;
}

sub import_random_seed {
    my $class = shift;

    until ( Crypt::OpenSSL::RSA::FFI::Crypto::RAND_status() ) {
        my $x;
        Crypt::OpenSSL::RSA::FFI::Crypto::RAND_seed( \$x, Crypt::OpenSSL::Random::random_bytes(20) );
    }
}

sub new_private_key {
    my ( $proto, $key_string, $passphrase ) = @_;

    my $success;
    my $pkey = malloc( $ffi->sizeof('opaque') );
    my $bio  = BIO_new_mem_buf( $key_string, -1 )
      or croakSSL();

    # Set to NULL
    memset( $pkey, 0, $ffi->sizeof('opaque') );

    my $dctx = OSSL_DECODER_CTX_new_for_pkey( $pkey, 'PEM', undef, 'RSA', 0, undef, undef );
    if (!$dctx) {
        free($pkey);
        croakSSL();
    }

    if ($passphrase) {
        OSSL_DECODER_CTX_set_passphrase(
            $dctx,
            $passphrase,
            length $passphrase
        );
    }

    $success = OSSL_DECODER_from_bio( $dctx, $bio );
    if (!$success) {
        free($pkey);
        croakSSL();
    }

    # dereference the double pointer and get the value of the inner pointer
    my $pkey_value = $ffi->cast( 'opaque', 'opaque*', $pkey )->$*;

    my $ctrl = BIO_ctrl( $bio, BIO_CTRL_SET_CLOSE(), BIO_CLOSE(), undef );
    $ctrl == 1
        or croakSSL();

    OSSL_DECODER_CTX_free($dctx);
    BIO_free($bio);
    free($pkey);

    if ( !$success ) {
        EVP_PKEY_free($pkey_value);
    }

    return bless { 'pkey' => $pkey_value }, $proto;
}

sub get_private_key_string {
    my $self = shift;
    my $pkey = $self->{'pkey'};

    my $ectx = OSSL_ENCODER_CTX_new_for_pkey( $pkey, EVP_PKEY_KEYPAIR(), "PEM", undef, undef )
        or croakSSL();

    my $passphrase;
    if ($passphrase) {
        OSSL_ENCODER_CTX_set_passphrase( $ectx, $passphrase, length $passphrase );
    }

    my $bio = BIO_new( BIO_s_mem() )
        or croakSSL();

    OSSL_ENCODER_to_bio( $ectx, $bio )
        or croakSSL();

    # TODO Calling to C here
    my $key_string = read_bio($bio);

    OSSL_ENCODER_CTX_free($ectx);
    return $key_string;
}

sub get_public_key_string {
    my $self      = shift;
    my $pkey      = $self->{'pkey'};
    my $selection = EVP_PKEY_PUBLIC_KEY();

    my $ectx = OSSL_ENCODER_CTX_new_for_pkey($pkey, $selection, 'PEM', undef, undef )
        or croakSSL();

    # TODO: passphrase not supported here?
    my $passphrase;
    if ($passphrase) {
        OSSL_ENCODER_CTX_set_passphrase( $ectx, $passphrase, length $passphrase );
    }

    my $bio = BIO_new( BIO_s_mem() )
        or croakSSL();

    if ( ! OSSL_ENCODER_to_bio( $ectx, $bio ) ) {
        OSSL_ENCODER_CTX_free($ectx);
        croakSSL();
    }

    if ( BIO_ctrl( $bio, BIO_CTRL_FLUSH(), 0, undef ) <= 0 ) {
        BIO_free($bio);
        OSSL_ENCODER_CTX_free($ectx);
        croakSSL();
    }

    # TODO Calling to C here
    my $key_string = read_bio($bio);

    OSSL_ENCODER_CTX_free($ectx);

    return $key_string;
}

sub get_public_key_x509_string {
    my $self = shift;
    my $pkey = $self->{'pkey'};

    my $bio = BIO_new( BIO_s_mem() )
        or croakSSL();

    my $result = PEM_write_bio_PUBKEY( $bio, $pkey );
    if ( $result == -1 ) {
        croakSSL();
    }

    if ( BIO_ctrl( $bio, BIO_CTRL_FLUSH(), 0, undef ) <= 0 ) {
        BIO_free($bio);
        croakSSL();
    }

    # TODO Calling to C here
    my $key_string = read_bio($bio);
    return $key_string;

}

sub new_public_key {
    my ( $proto, $key_string, $passphrase ) = @_;

    # Verifying we're reading a proper public key
    # XXX: This doesn't seem to happen for private key for some reason...
    $key_string =~ /^-----BEGIN \s (RSA \s )? PUBLIC \s KEY-----/xms
        or croak("unrecognized key format");

    my $success;
    my $pkey = malloc( $ffi->sizeof('opaque') );
    my $bio  = BIO_new_mem_buf( $key_string, -1 )
      or croakSSL();

    # Set to NULL
    memset( $pkey, 0, $ffi->sizeof('opaque') );

    my $dctx = OSSL_DECODER_CTX_new_for_pkey( $pkey, 'PEM', undef, 'RSA', EVP_PKEY_PUBLIC_KEY(), undef, undef );
    if (!$dctx) {
        free($pkey);
        croakSSL();
    }

    if ($passphrase) {
        OSSL_DECODER_CTX_set_passphrase(
            $dctx,
            $passphrase,
            length $passphrase
        );
    }

    $success = OSSL_DECODER_from_bio( $dctx, $bio );
    if (!$success) {
        free($pkey);
        croakSSL();
    }

    # dereference the double pointer and get the value of the inner pointer
    my $pkey_value = $ffi->cast( 'opaque', 'opaque*', $pkey )->$*;

    my $ctrl = BIO_ctrl( $bio, BIO_CTRL_SET_CLOSE(), BIO_CLOSE(), undef );
    $ctrl == 1
        or croakSSL();

    OSSL_DECODER_CTX_free($dctx);
    BIO_free($bio);
    free($pkey);

    if ( !$success ) {
        EVP_PKEY_free($pkey_value);
    }

    return bless { 'pkey' => $pkey_value }, $proto;
}

sub _load_key {
    my ( $type, $key_string ) = @_;
    my $key_string_length = length $key_string;

    my $stringBIO_ptr = BIO_new_mem_buf( $key_string, $key_string_length)
        or croakSSL();

    my $read_key_ptr =
      $type eq 'pkcs1'
      ? PEM_read_bio_RSAPublicKey( $stringBIO_ptr, undef, undef, undef )
      : die;

    $read_key_ptr
        or croakSSL();

    # define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
    my $ctrl = BIO_ctrl( $stringBIO_ptr, BIO_CTRL_SET_CLOSE(), BIO_CLOSE(), undef );
    $ctrl == 1
        or croakSSL();

    BIO_free($stringBIO_ptr);

    $read_key_ptr
        or croakSSL();

    return $read_key_ptr;
}

# Check it has been written into and read back
sub _check_bio_string {
    my ( $stringBIO, $len ) = @_;

    $ffi->attach( 'BIO_ctrl_pending' => ['opaque'] => 'size_t' );
    printf "Data pending to be read: %d\n", BIO_ctrl_pending($stringBIO);

    $ffi->attach( 'BIO_gets' => ['opaque', 'opaque', 'int' ] => 'int' );
    use FFI::Platypus::Memory qw( malloc free );
    my $buf = malloc( $ffi->sizeof("char[$len]") + 1 );
    while ( my $res = BIO_gets( $stringBIO, $buf, $len + 1 ) ) {
        print STDERR $ffi->cast( 'opaque', 'string', $buf );
    }
    print STDERR "\n";
    free($buf);
}

sub _read_from_bio {
    my $bio = shift;

    use FFI::Platypus::Memory qw( malloc free );

    $ffi->attach( 'BIO_ctrl_pending' => ['opaque'] => 'size_t' );
    my $len = BIO_ctrl_pending($bio);
    printf "Data pending to be read: %d\n", $len;

    my $buf = malloc( $ffi->sizeof("char[$len]") + 1 );

    $ffi->attach( 'BIO_gets' => ['opaque', 'opaque', 'int' ] => 'int' );
    while ( my $res = BIO_gets( $bio, $buf, $len + 1 ) ) {
        print STDERR $ffi->cast( 'opaque', 'string', $buf );
    }
    print STDERR "\n";
    free($buf);
}

sub DESTROY {
    my $self = shift
        or return;

    if ( my $pkey = $self->{'pkey'} ) {
        EVP_PKEY_free( $self->{'pkey'} );
    }
}

#-----------------#
# Pure C versions #
#-----------------#

sub get_public_key_x509_string_PURE_C {
    my $self = shift;
    my $pkey = $self->{'pkey'};

    my $bio;
    my $string = load_public_key_x509_string( $pkey, \$bio )
        or croakSSL();

    BIO_free($bio);

    return $string;
}

sub get_private_key_string_FAILING {
    my $self = shift;
    my $pkey = $self->{'pkey'};

    my $ectx = OSSL_ENCODER_CTX_new_for_pkey( $pkey, EVP_PKEY_KEYPAIR(), "PEM", undef, undef )
        or croakSSL();

    my $passphrase;
    if ($passphrase) {
        OSSL_ENCODER_CTX_set_passphrase( $ectx, $passphrase, length $passphrase );
    }

    my $bio = BIO_new( BIO_s_mem() )
        or croakSSL();

    OSSL_ENCODER_to_bio( $ectx, $bio )
        or croakSSL();

    if ( BIO_ctrl( $bio, BIO_CTRL_FLUSH(), 0, undef ) <= 0 ) {
        BIO_free($bio);
        croakSSL();
    }

    my $length       = BIO_ctrl_pending($bio);
    my $key_string_p = malloc( $ffi->sizeof('opaque') );
    memset( $key_string_p, 0, $ffi->sizeof('opaque') );

    BIO_read( $bio, $key_string_p, $length )
        or croakSSL();

    BIO_set_flags( $bio, BIO_FLAGS_MEM_RDONLY() );

    #OSSL_ENCODER_CTX_free($ectx);
    my $key_string = $ffi->cast( 'opaque' => 'string*', $key_string_p )->$*;
    #free($key_string_p);
    #BIO_free($bio);

    return $key_string;
}

sub get_public_key_string_PURE_C {
    my $self = shift;
    my $pkey = $self->{'pkey'};
    my $passphrase;
    my $bio;
    my $string = load_public_key_string( $pkey, $passphrase, \$bio )
        or croakSSL();

    BIO_free($bio);

    return $string;
}

sub new_public_key_PURE_C {
    my ( $proto, $p_key_string, $passphrase ) = @_;
    $p_key_string =~ /^-----BEGIN \s (RSA \s )? PUBLIC \s KEY-----/xms
        or croak("unrecognized key format");

    my $pkey = load_public_key( $p_key_string, $passphrase )
        or croakSSL();

    return bless { 'pkey' => $pkey }, $proto;
}

1;
