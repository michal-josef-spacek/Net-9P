use strict;
use warnings;

use Check::Socket 0.03;
use Data::9P::Message::Rerror;
use English;
use Error::Pure::Utils qw(clean);
use Net::9P::Connection;
use Net::9P::Protocol::9P2000;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test::More 'tests' => 7;
use Test::NoWarnings;

SKIP: {
	skip $Check::Socket::ERROR_MESSAGE, 1 unless Check::Socket::check_socket();

	# Test.
	my ($sock1, $sock2);
	skip "Cannot use socketpair: $ERRNO", 6
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	my $proto = Net::9P::Protocol::9P2000->new;
	my $obj = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	my $tag = 42;
	my $msg = Data::9P::Message::Rerror->new(
		'ename' => 'Permission denied',
	);
	my $raw = $proto->encode($tag, $msg);
	syswrite($sock2, substr($raw, 0, 3));
	syswrite($sock2, substr($raw, 3));
	my ($ret_tag, $recv) = $obj->recv;
	is($ret_tag, 42, 'Get tag (42).');
	isa_ok($recv, 'Data::9P::Message::Rerror');
	is($recv->ename, 'Permission denied', 'Get ename (Permission denied).');
	$sock1->close;
	$sock2->close;

	# Test.
	skip "Cannot use socketpair: $ERRNO", 3
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	$proto = Net::9P::Protocol::9P2000->new;
	$obj = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	syswrite($sock2, pack('V', 3));
	eval {
		$obj->recv;
	};
	is($EVAL_ERROR, "Invalid size.\n",
		"Invalid size.");
	clean();
	$sock1->close;
	$sock2->close;

	# Test.
	skip "Cannot use socketpair: $ERRNO", 2
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	$proto = Net::9P::Protocol::9P2000->new;
	$obj = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	$obj->close;
	eval {
		$obj->recv;
	};
	is($EVAL_ERROR, "Socket handle is closed.\n",
		"Socket handle is closed (object called close() before recv()).");
	clean();
	$sock1->close;
	$sock2->close;

	# Test.
	skip "Cannot use socketpair: $ERRNO", 1
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	$proto = Net::9P::Protocol::9P2000->new;
	$obj = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	$sock1->close;
	eval {
		$obj->recv;
	};
	is($EVAL_ERROR, "Socket handle is closed.\n",
		"Socket handle is closed (socket called close() before object recv()).");
	clean();
	$sock1->close;
	$sock2->close;
};
