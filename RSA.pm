package Crypt::OpenSSL::RSA;

use strict;
use Carp;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD
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

$VERSION = '0.12';

bootstrap Crypt::OpenSSL::RSA $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Crypt::OpenSSL::RSA - RSA encoding and decoding, using the openSSL libraries

=head1 SYNOPSIS

  use Crypt::OpenSSL::Random;
  use Crypt::OpenSSL::RSA;

  # not necessary if we have /dev/random:
  Crypt::OpenSSL::Random::random_seed($good_entropy);

  $rsa_pub = new Crypt::OpenSSL::RSA();
  $rsa_pub->import_random_seed();

  $rsa_pub->load_public_key($key_string);
  $ciphertext = $rsa->encrypt($plaintext);

  $rsa_priv = new Crypt::OpenSSL::RSA();

  $rsa_priv->load_private_key($key_string);
  $plaintext = $rsa->encrypt($ciphertext);

  $rsa = new Crypt::OpenSSL::RSA();

  $rsa->generate_key(1024); # or
  $rsa->generate_key(1024, $prime);

  print "private key is:\n", $rsa->get_private_key_string();
  print "public key is:\n", $rsa->get_public_key_string();

=head1 DESCRIPTION

Crypt::OpenSSL::RSA provides the ability to RSA encrypt strings which are
somewhat shorter than the block size of a key.  It also allows for decryption.

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
    my $self = {};
    bless $self, $package;
    $self->set_padding_mode($RSA_PKCS1_OAEP_PADDING);
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
padding is set to PKCS1_OAEP, but can be changed with set_padding.

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

=item decrypt

Decrypt a binary "string".  Croaks if the key is public only.

=cut

# taken from openssl/rsa.h

$RSA_PKCS1_PADDING = 1;
$RSA_SSLV23_PADDING = 2;
$RSA_NO_PADDING = 3;
$RSA_PKCS1_OAEP_PADDING = 4;

=item set_padding_mode

Set the padding mode.  The choices are

=over

=item $RSA_PKCS1_PADDING

PKCS #1 v1.5 padding. This currently is the most widely used mode.

=item $RSA_PKCS1_OAEP_PADDING

EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty
encoding parameter. This mode is recommended for all new applications.

=item $RSA_SSLV23_PADDING

PKCS #1 v1.5 padding with an SSL-specific modification that denotes
that the server is SSL3 capable.

=item $RSA_NO_PADDING

Raw RSA encryption. This mode should only be used to implement
cryptographically sound padding modes in the application code.
Encrypting user data directly with RSA is insecure.

=back

By default, $RSA_PKCS1_OAEP_PADDING is used.

=cut

sub set_padding_mode
{
    my ($self, $padding_mode) = @_;
    $self->{padding_mode} = $padding_mode;
}

=item get_padding_mode

Get the padding mode.

=cut

sub get_padding_mode
{
    my ($self) = @_;
    return $self->{padding_mode};
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

Currently many XS routines croak rather than trying to intelligently
signal an error.  This is mostly in cases where a routine is called
without adequate preparation, such as asking to encrypt before setting
a key.

There appears to be some small memory leaks in functions (notably
_load_key, probably others).  This is presumably due to failure to
decrement a reference count somewhere - I just haven't found out where
yet.

RSA_NO_PADDING_MODE does not work - I don't know yet if it's a problem with encryption, decryption, or both.

=head1 AUTHOR

Ian Robertson, iroberts@cpan.com

=head1 SEE ALSO

perl(1), Crypt::OpenSSL::Random(3), rsa(3), RSA_new(3),
RSA_public_encrypt(3), RSA_size(3), RSA_generate_key(3),
RSA_check_key(3)

=cut
