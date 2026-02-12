use strict;
use warnings;

use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 2;
use Test::NoWarnings;

# Test.
my $obj = Net::9P::Protocol::9P2000->new;
isa_ok($obj, 'Net::9P::Protocol::9P2000');
