# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

use strict;
my $loaded;
BEGIN { $| = 1; print "1..19\n"; }
END {print "not ok 1\n" unless $loaded;}
use Crypt::OpenSSL::RSA;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

use Crypt::OpenSSL::Random;

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $test_number = 2;
sub my_test
{
    my($cond) = @_;
    my $number = $test_number++;
    if ($cond)
    {
        print "ok $number\n";
    }
    else
    {
        my ($pack, $file, $line) = caller;
        print "not ok $number - from $file:$line\n";
    }
}

sub _Test_Sign_And_Verify
{
    my( $plaintext, $rsa, $rsa_pub ) = @_;

    my $sig = $rsa->sign($plaintext);
    my_test( $rsa_pub->verify( $plaintext, $sig ) );

    my $false_sig = unpack "H*", $sig;
    $false_sig =~ tr/[a-f]/[0a-d]/;
    my_test(! $rsa_pub->verify( $plaintext, pack( "H*", $false_sig ) ) );
}

# On platforms without a /dev/random, we need to manually seed.  In
# real life, the following would stink, but for testing purposes, it
# suffices to seed with any old thing, even if it is not actually
# random.  We'll at least emulate seeding from Crypt::OpenSSL::Random,
# which is what we would have to do in "real life", since the private
# data used by the OpenSSL random library apparently does not span
# across perl XS modules.

Crypt::OpenSSL::Random::random_seed("Here are 20 bytes...");
Crypt::OpenSSL::RSA::import_random_seed();

# We should now be seeded, regardless.
# my_test(Crypt::OpenSSL::RSA::random_status());
my $rsa = Crypt::OpenSSL::RSA->new();

$rsa->generate_key(512);
my_test($rsa->size() * 8 == 512);

$rsa->generate_key(1024);
my_test($rsa->size() * 8 == 1024);
my_test($rsa->check_key());

# check if NO_PADDING works
$rsa->use_no_padding();
my ($ciphertext, $decoded_text);
my $plaintext = "X" x $rsa->size;
my_test($ciphertext = $rsa->encrypt($plaintext));
my_test($decoded_text = $rsa->decrypt($ciphertext));
my_test ($decoded_text eq $plaintext);

# check if OAEP_PADDING works
my $plaintext_length = $rsa->size() - 42;
my $plaintext = pack("C$plaintext_length",
                     (255,0,128,4, # Make sure these characters work
                      map {int(rand 256)} (1..$plaintext_length-4)));
$rsa->use_pkcs1_oaep_padding();
my_test($ciphertext = $rsa->encrypt($plaintext));
my_test($decoded_text = $rsa->decrypt($ciphertext));
my_test ($decoded_text eq $plaintext);

my $private_key_string = $rsa->get_private_key_string();
my $public_key_string = $rsa->get_public_key_string();

my_test( $private_key_string and $public_key_string );

my $rsa_priv = Crypt::OpenSSL::RSA->new();

$rsa_priv->load_private_key( $private_key_string );
$decoded_text = $rsa_priv->decrypt($ciphertext);

my_test( $decoded_text eq $plaintext );

my $rsa_pub = Crypt::OpenSSL::RSA->new();

$rsa_pub->load_public_key($public_key_string);

$ciphertext = $rsa_pub->encrypt($plaintext);
$decoded_text = $rsa->decrypt($ciphertext);
my_test ($decoded_text eq $plaintext);

$plaintext .= $plaintext x 5;
# check signature algorithms
$rsa->use_md5_hash();
$rsa_pub->use_md5_hash();
_Test_Sign_And_Verify( $plaintext, $rsa, $rsa_pub );

$rsa->use_sha1_hash();
$rsa_pub->use_sha1_hash();
_Test_Sign_And_Verify( $plaintext, $rsa, $rsa_pub );

$rsa->use_ripemd160_hash();
$rsa_pub->use_ripemd160_hash();
_Test_Sign_And_Verify( $plaintext, $rsa, $rsa_pub );
