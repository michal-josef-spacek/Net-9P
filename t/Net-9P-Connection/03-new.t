use strict;
use warnings;

use Check::Socket 0.03;
use English;
use Error::Pure::Utils qw(clean);
use IO::Socket;
use Net::9P::Connection;
use Test::MockObject;
use Test::More 'tests' => 4;
use Test::NoWarnings;

SKIP: {
	skip $Check::Socket::ERROR_MESSAGE, 2 unless Check::Socket::check_socket();

	# Test.
	my $obj = Net::9P::Connection->new(
		'socket' => IO::Socket->new('Domain' => AF_UNIX),
	);
	isa_ok($obj, 'Net::9P::Connection');

	# Test.
	eval {
		Net::9P::Connection->new(
			'protocol' => Test::MockObject->new,
			'socket' => IO::Socket->new('Domain' => AF_UNIX),
		);
	};
	is($EVAL_ERROR, "Parameter 'protocol' must be a 'Net::9P::Protocol::9P2000' object.\n",
		"Parameter 'protocol' must be a 'Net::9P::Protocol::9P2000' object (mock object).");
	clean();
};

# Test.
eval {
	Net::9P::Connection->new;
};
is($EVAL_ERROR, "Parameter 'socket' is required.\n",
	"Parameter 'socket' is required.");
clean();
