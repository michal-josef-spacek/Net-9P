use strict;
use warnings;

use Test::More 'tests' => 3;
use Test::NoWarnings;

BEGIN {

	# Test.
	use_ok('Net::9P::Protocol::9P2000');
}

# Test.
require_ok('Net::9P::Protocol::9P2000');
