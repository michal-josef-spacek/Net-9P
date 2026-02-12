use strict;
use warnings;

use Test::NoWarnings;
use Test::Pod::Coverage 'tests' => 2;

# Test.
pod_coverage_ok('Net::9P::Protocol::9P2000', 'Net::9P::Protocol::9P2000 is covered.');
