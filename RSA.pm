package Crypt::OpenSSL::RSA;

use strict;
use Carp;

use vars qw( $VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD
             $RSA_PKCS1_PADDING $RSA_SSLV23_PADDING $RSA_NO_PADDING
             $RSA_PKCS1_OAEP_PADDING );

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

@EXPORT = qw( $RSA_PKCS1_PADDING $RSA_SSLV23_PADDING $RSA_NO_PADDING
              $RSA_PKCS1_OAEP_PADDING );

$VERSION = '0.13';

bootstrap Crypt::OpenSSL::RSA $VERSION;

# taken from openssl/rsa.h

$RSA_PKCS1_PADDING = 1;
$RSA_SSLV23_PADDING = 2;
$RSA_NO_PADDING = 3;
$RSA_PKCS1_OAEP_PADDING = 4;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Crypt::OpenSSL::RSA - RSA encoding and decoding, using the openSSL libraries

=head1 SYNOPSIS

  use Crypt::OpenSSL::Random;
  use Crypt::OpenSSL::RSA;

  # not necessary if we have /dev/random:
  Crypt::OpenSSL::Random::random_seed($good_entropy);

  $rsa_pub = Crypt::OpenSSL::RSA->new();
  $rsa_pub->import_random_seed();
  # or just Crypt::OpenSSL::RSA::import_random_seed

  $rsa_pub->load_public_key($key_string);
  $ciphertext = $rsa->encrypt($plaintext);

  $rsa_priv = Crypt::OpenSSL::RSA->new();
  $rsa_priv->load_private_key($key_string);
  $plaintext = $rsa->encrypt($ciphertext);

  $rsa = Crypt::OpenSSL::RSA->new();
  $rsa->generate_key(1024); # or
  $rsa->generate_key(1024, $prime);

  print "private key is:\n", $rsa->get_private_key_string();
  print "public key is:\n", $rsa->get_public_key_string();

  $signature = $rsa_priv->sign($plaintext);
  print "Signed correctly\n" if ( $rsa->verify($plaintext, $signature) );

=head1 DESCRIPTION

Crypt::OpenSSL::RSA provides the ability to RSA encrypt strings which are
somewhat shorter than the block size of a key.  It also allows for decryption,
signatures and signature verification.

I<NOTE>: Many of the methods in this package can croak, so use eval, or
Error.pm's try/catch mechanism to capture errors.  Also, while some
methods from earlier versions of this package return true on success,
this (never documented) behavior is no longer the case.

=head1 Instance Methods

=over

=item new

The standard constructor for an RSA object takes no arguments; the key
should either be created by generate_key, or loaded in by load_public_key
or load_private_key.

=cut

sub new
{
    my ($package) = @_;
    my $self = bless {}, $package;
    $self->use_pkcs1_oaep_padding();
    $self->use_sha1_hash();
    return $self;
}

=item DESTROY

Clean up after ourselves.  In particular, erase and free the memory
occupied by the RSA key structure.

=cut

sub DESTROY
{
    my ($self) = @_;
    $self->_free_RSA_key();
}

=item load_public_key

Load a public key in from an X509 encoded string.  The string should
include the -----BEGIN...----- and -----END...----- lines.  The
padding is set to PKCS1_OAEP, but can be changed with set_padding.

=cut

sub load_public_key
{
    my($self, $key_string) = @_;
    $self->_load_key(0, $key_string);
}

=item load_private_key

Load a private key in from an X509 encoded string.  The string should
include the -----BEGIN...----- and -----END...----- lines.  The
padding is set to PKCS1_OAEP, but can be changed with use_xxx_padding.

=cut

sub load_private_key
{
    my($self, $key_string) = @_;
    $self->_load_key(1, $key_string);
}

=item get_public_key_string

Return the public portion of the key as an X509 encoded string.

=cut

sub get_public_key_string
{
    my ($self) = @_;
    return $self->_get_key_string(0);
}

=item get_private_key_string

Return the X509 encoding of the private key.

=cut

sub get_private_key_string
{
    my ($self) = @_;
    return $self->_get_key_string(1);
}


=item generate_key

Generate a private/public key pair.  The padding is set to PKCS1_OAEP,
but can be changed with set_padding.

=item encrypt

Encrypt a string using the public (portion of the) key

=item sign

Sign a string using the secret (portion of the) key

=item verify

Check the signature on a text.

=item decrypt

Decrypt a binary "string".  Croaks if the key is public only.

=item set_padding_mode

DEPRECATED.  Use the use_xxx_padding methods instead

=cut

sub set_padding_mode
{
    my ($self, $padding_mode) = @_;
    $self->{_Padding_Mode} = $padding_mode;
}

=item use_no_padding

Use raw RSA encryption. This mode should only be used to implement
cryptographically sound padding modes in the application code.
Encrypting user data directly with RSA is insecure.

=cut

sub use_no_padding
{
    shift->set_padding_mode( $RSA_NO_PADDING );
}

=item use_pkcs1_padding

Use PKCS #1 v1.5 padding. This currently is the most widely used mode
of padding.

=cut

sub use_pkcs1_padding
{
    shift->set_padding_mode( $RSA_PKCS1_PADDING );
}

=item use_pkcs1_oaep_padding

Use EME-OAEP padding as defined in PKCS #1 v2.0 with SHA-1, MGF1 and
an empty encoding parameter. This mode of padding is recommended for
all new applications.  It is the default mode used by
Crypt::OpenSSL::RSA.

=cut

sub use_pkcs1_oaep_padding
{
    shift->set_padding_mode( $RSA_PKCS1_OAEP_PADDING );
}

=item use_sslv23_padding

Use PKCS #1 v1.5 padding with an SSL-specific modification that
denotes that the server is SSL3 capable.

=cut

sub use_sslv23_padding
{
    shift->set_padding_mode( $RSA_SSLV23_PADDING );
}

=item get_padding_mode

DEPRECATED.

=cut

sub get_padding_mode
{
    return shift->{_Padding_Mode};
}

=item use_md5_hash

Use the RFC 1321 MD5 hashing algorithm by Ron Rivest when signing and
verifying messages.

=cut

sub use_md5_hash
{
    shift->_set_hash_mode( 1 );
}

=item use_sha1_hash

Use the RFC 3174 Secure Hashing Algorithm (FIPS 180-1) when signing
and verifying messages. This is the default.

=cut

sub use_sha1_hash
{
    shift->_set_hash_mode( 2 );
}

=item use_ripemd160_hash

Dobbertin, Bosselaers and Preneel's RIPEMD hashing algorithm when
signing and verifying messages.

=cut

sub use_ripemd160_hash
{
    shift->_set_hash_mode( 3 );
}

sub _set_hash_mode
{
    my ($self, $hash) = @_;
    $self->{_Hash_Mode} = $hash;
}

=item size

Returns the size, in bytes, of the key.  All encrypted text will be of
this size, and depending on the padding mode used, the length of
the text to be encrypted should be

=over

=item $RSA_PKCS1_OAEP_PADDING

at most 42 bytes less than this size.

=item $RSA_PKCS1_PADDING or $RSA_SSLV23_PADDING

at most 11 bytes less than this size.

=item $RSA_NO_PADDING

exactly this size.

=back

=item check_key

This function validates the RSA key, returning 1 if the key is valid,
0 otherwise.

=back

=head1 Class Methods

=over

=item import_random_seed

Import a random seed from Crypt::OpenSSL::Random, since the OpenSSL
libraries won't allow sharing of random structures across perl XS
modules.

=back

=cut

sub import_random_seed
{
    until ( _random_status() )
    {
        _random_seed( Crypt::OpenSSL::Random::random_bytes(20) );
    }
}

=head1 BUGS

There is a small memory leak when generating new keys of more than 512 bits.

=head1 AUTHOR

Ian Robertson, iroberts@cpan.org

=head1 SEE ALSO

perl(1), Crypt::OpenSSL::Random(3), rsa(3), RSA_new(3),
RSA_public_encrypt(3), RSA_size(3), RSA_generate_key(3),
RSA_check_key(3)

=cut
