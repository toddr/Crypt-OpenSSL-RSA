use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Crypt::OpenSSL::RSA',
    'DISTNAME' => 'Crypt-OpenSSL-RSA',
    'VERSION_FROM' => 'RSA.pm', # finds $VERSION
    'OBJECT' => 'RSA.o rsaLib.o',
    'LIBS'	=> ['-lssl -lcrypto'],   # e.g., '-lm' 
    'PREREQ_PM' => { 'Crypt::OpenSSL::Random' => 0 },
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
);
