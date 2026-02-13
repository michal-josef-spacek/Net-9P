use strict;
use warnings;

use Net::9P::Connection;
use Test::More 'tests' => 2;
use Test::NoWarnings;

# Test.
is($Net::9P::Connection::VERSION, 0.01, 'Version.');
