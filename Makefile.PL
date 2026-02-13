use lib '.';
use strict;
use warnings;

use inc::Module::Install;

# Definition.
abstract 'Handle 9 protocol.';
author 'Michal Josef Spacek <skim@cpan.org>';
author_requires 'English' => 0;
author_requires 'File::Object' => 0;
author_requires 'Test::More' => 0;
author_requires 'Test::NoWarnings' => 0;
author_requires 'Test::Pod' => 0;
author_requires 'Test::Pod::Coverage' => 0;
license 'bsd';
name 'Net-9P';
perl_version 5.008;
readme_from '9P.pm';
recursive_author_tests('xt');
requires 'Class::Utils' => 0;
requires 'Data::9P::Message::Rerror' => 0;
requires 'Data::9P::Message::Rversion' => 0;
requires 'Data::9P::Message::Tread' => 0;
requires 'Data::9P::Message::Tversion' => 0;
requires 'Data::9P::Message::Twrite' => 0;
requires 'Data::9P::Message::Twalk' => 0;
requires 'Error::Pure' => 0;
requires 'Readonly' => 0;
requires 'Scalar::Util' => 0;
resources 'bugtracker' => 'https://github.com/michal-josef-spacek/Net-9P/issues';
resources 'homepage' => 'https://github.com/michal-josef-spacek/Net-9P';
resources 'repository' => 'git://github.com/michal-josef-spacek/Net-9P';
test_requires 'Data::9P::Message::Rerror' => 0;
test_requires 'Data::9P::Message::Rversion' => 0;
test_requires 'Data::9P::Message::Tread' => 0;
test_requires 'Data::9P::Message::Tversion' => 0;
test_requires 'Data::9P::Message::Twalk' => 0;
test_requires 'Data::9P::Message::Twrite' => 0;
test_requires 'Math::BigInt' => 0;
test_requires 'Test::More' => 0;
test_requires 'Test::NoWarnings' => 0;
tests_recursive;
version '0.01';

# Run.
WriteAll();
