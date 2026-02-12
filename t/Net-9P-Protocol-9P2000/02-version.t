use strict;
use warnings;

use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 2;
use Test::NoWarnings;

# Test.
is($Net::9P::Protocol::9P2000::VERSION, 0.01, 'Version.');
