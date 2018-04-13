use ExtUtils::MakeMaker;
use Crypt::OpenSSL::Guess qw(openssl_inc_paths);
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'	=> 'Crypt::OpenSSL::RSA',
    'DISTNAME' => 'Crypt-OpenSSL-RSA',
     AUTHOR  => 'Ian Robertson <iroberts@cpan.org>',
    'VERSION_FROM' => 'RSA.pm', # finds $VERSION
    'ABSTRACT_FROM' => 'RSA.pm',
    'PL_FILES' => {},
    ($ExtUtils::MakeMaker::VERSION >= 6.3002 ? ('LICENSE'        => 'perl', ) : ()),
    'PREREQ_PM' => {
        'Crypt::OpenSSL::Random' => 0,
        'Test' => 0,
    },
    'OBJECT' => 'RSA.o',
    'LIBS'    => ($^O eq 'MSWin32') ? ['-lssl32 -leay32'] : ['-lssl -lcrypto'],
    'DEFINE'	=> '-DPERL5 -DOPENSSL_NO_KRB5',
    # perl-5.8/gcc-3.2 needs -DPERL5, and redhat9 likes -DOPENSSL_NO_KRB5
    'INC'	=> openssl_inc_paths(),     # e.g., '-I/usr/include/other'

    'dist'  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    'clean' => { FILES => 'Crypt-OpenSSL-RSA-*' },
    'META_MERGE' => {
        recommends => {
            'Crypt::OpenSSL::Bignum' => 0,
        },
        build_requires => {
            'Test' => 0,  # For testing
            'Crypt::OpenSSL::Guess' => 0,
        },
        resources => {
            'license' => 'http://dev.perl.org/licenses/',
            'homepage' => 'http://github.com/toddr/Crypt-OpenSSL-RSA',
            'bugtracker' => 'https://github.com/toddr/Crypt-OpenSSL-RSA/issues',
            'repository' => 'http://github.com/toddr/Crypt-OpenSSL-RSA',
        }
    }
);

#Nice = Crypt::OpenSSL::Bignum
