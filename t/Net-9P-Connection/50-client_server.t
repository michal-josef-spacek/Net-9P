use strict;
use warnings;

use Check::Socket;
use Data::9P::Message::Rerror;
use English;
use Error::Pure::Utils qw(clean);
use IO::Handle;
use Net::9P::Connection;
use Net::9P::Protocol::9P2000;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test::More 'tests' => 5;
use Test::NoWarnings;

SKIP: {
	skip $Check::Socket::ERROR_MESSAGE, 1 unless Check::Socket::check_socket();

	# Test.
	my ($sock1, $sock2);
	skip "Cannot use socketpair: $ERRNO", 2
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	$sock1->autoflush(1);
	$sock2->autoflush(1);
	my $proto = Net::9P::Protocol::9P2000->new;
	my $c1 = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	my $c2 = Net::9P::Connection->new(
		'socket' => $sock2,
		'protocol' => $proto,
	);
	my $msg = Data::9P::Message::Rerror->new(
		'ename' => 'Permission denied',
		'tag' => 42,
	);
	$c1->send($msg);
	my $recv = $c2->recv;
	isa_ok($recv, 'Data::9P::Message::Rerror');
	is($recv->tag, 42, 'Get tag (42).');
	is($recv->ename, 'Permission denied', 'Get ename (Permission denied).');
	$sock1->close;
	$sock2->close;

	# Test.
	skip "Cannot use socketpair: $ERRNO", 2
		unless socketpair($sock1, $sock2, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	$sock1->autoflush(1);
	$sock2->autoflush(1);
	$proto = Net::9P::Protocol::9P2000->new;
	$c1 = Net::9P::Connection->new(
		'socket' => $sock1,
		'protocol' => $proto,
	);
	$c2 = Net::9P::Connection->new(
		'socket' => $sock2,
		'protocol' => $proto,
	);
	$msg = Data::9P::Message::Rerror->new(
		'ename' => 'Permission denied',
		'tag' => 42,
	);
	$c1->send($msg);
	$c1->close;
	$recv = $c2->recv;
	eval {
		$c2->recv;
	};
	is($EVAL_ERROR, "Unexpected end of file.\n",
		"Unexpected end of file.");
	clean();
};
