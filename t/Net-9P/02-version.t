use strict;
use warnings;

use Net::9P;
use Test::More 'tests' => 2;
use Test::NoWarnings;

# Test.
is($Net::9P::VERSION, 0.01, 'Version.');
