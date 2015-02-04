use ExtUtils::MakeMaker;
use 5.006;

my $KERBEROS_INCLUDE = "/usr/kerberos/include";
my $include = -d $KERBEROS_INCLUDE ? "-I${KERBEROS_INCLUDE}" : "";

my $libdir;
my $args = join(" ", @ARGV);
if ($args =~ /INCDIR[ =](\S+)/) {
  $include = $include ? " -I$1" : $1;
}
if ($args =~ /LIBDIR[ =](\S+)/) {
  $libdir = $1;
}
my @libs = qw(-lssl -lcrypto);

WriteMakefile(
  'NAME'	  => 'Crypt::OpenSSL::RSA',
  'AUTHOR'        => 'Ian Robertson <iroberts@cpan.org>',
  'VERSION_FROM'  => 'RSA.pm',
  'ABSTRACT_FROM' => 'RSA.pm',
  'PREREQ_PM' => {
    'Crypt::OpenSSL::Random' => 0,
    'Test::More' => 0,
    'Test' => 0,
  },
  'DEFINE'	=> '-DPERL5 -DOPENSSL_NO_KRB5',
  # perl-5.8/gcc-3.2 needs -DPERL5, and redhat9 likes -DOPENSSL_NO_KRB5
  'LIBS'            => $libdir ? [ "-L$libdir", @libs ] : \@libs,
  'INC'             => $include,

  'clean' => { FILES => 'Crypt-OpenSSL-RSA-*' },
  ($ExtUtils::MakeMaker::VERSION >= 6.3002 ? (
     'LICENSE'  => 'perl', ) : ()),
  ($ExtUtils::MakeMaker::VERSION >= 6.46 ? (
    'META_MERGE' => {
        recommends => {
          'Crypt::OpenSSL::Bignum' => 0,
          'Crypt::OpenSSL::Random' => '0.09',
        },
        build_requires => {
          'Test'      => 0,
          'Pod::Text' => 0
        },
        resources => {
            'license'    => 'http://dev.perl.org/licenses/',
            'homepage'   => 'https://metacpan.org/release/Crypt-OpenSSL-RSA',
#            bugtracker  => 'http://code.google.com/p/Crypt-OpenSSL-RSA/issues/list',
            'repository' => 'http://github.com/monken/Crypt-OpenSSL-RSA',
#            MailingList => 'http://groups.google.com/group/Crypt-OpenSSL-RSA',
        }
     }) : ()),
);

package MY;
use Config;

sub top_targets {
  local $_ = shift->SUPER::top_targets(@_);
  s/\$\(FIRST_MAKEFILE\) blibdirs/\$(FIRST_MAKEFILE\) blibdirs README/;
  $_
}

sub depend {
  "
README : \$(VERSION_FROM)
	pod2text \$(VERSION_FROM) > README

release : dist
	git commit -a -m\"release \$(VERSION)\"
	git tag \$(VERSION)
	cpan-upload \$(DISTVNAME).tar\$(SUFFIX)
	git push
	git push --tags

gcov : \$(BASEEXT).c.gcov \$(BASEEXT).xs.gcov cover_db/\$(BASEEXT)-xs.html

\$(BASEEXT).c.gcov \$(BASEEXT).xs.gcov : \$(BASEEXT).xs
	\$(MAKE) CCFLAGS=\"\$(CCFLAGS) -fprofile-arcs -ftest-coverage\" LDDLFLAGS=\"\$(LDDLFLAGS) -fprofile-arcs -ftest-coverage\"
	gcov \$(BASEEXT).c \$(BASEEXT).xs

cover_db/\$(BASEEXT)-xs.html : \$(BASEEXT).xs.gcov
	PERL5OPT=-MDevel::Cover make test
	-$^X -S gcov2perl \$(BASEEXT).c.gcov \$(BASEEXT).xs.gcov
	$^X -S cover

gprof :
	\$(MAKE) CCFLAGS=\"\$(CCFLAGS) -pg\" LDDLFLAGS=\"\$(LDDLFLAGS) -pg\"
"
}
