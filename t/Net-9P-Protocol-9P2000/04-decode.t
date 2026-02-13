use strict;
use warnings;

use Math::BigInt;
use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 27;
use Test::NoWarnings;

# Test.
my $obj = Net::9P::Protocol::9P2000->new;
my $input = pack('H*',
	'1a000000'.  # size = 26
	'6b'.        # type = 107
	'2a00'.      # tag = 42
	'1100'.      # string length = 17
	'5065726d697373696f6e2064656e696564'
);
my ($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rerror');
is($ret->ename, 'Permission denied', 'Get ename (Permission denied).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'13000000'.  # size = 19
	'65'.        # type = 101
	'0100'.      # tag = 1
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'  # "9P2000"
);
($tag, $ret) = $obj->decode($input);
is($tag, 1, 'Get tag (1).');
isa_ok($ret, 'Data::9P::Message::Rversion');
is($ret->msize, 8192, 'Get msize (8192).');
is($ret->version, '9P2000', 'Get version (9P2000).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'13000000'.  # size = 19
	'64'.        # type = 100
	'0200'.      # tag = 2
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'
);
($tag, $ret) = $obj->decode($input);
is($tag, 2, 'Get tag (2).');
isa_ok($ret, 'Data::9P::Message::Tversion');
is($ret->msize, 8192, 'Get msize (8192).');
is($ret->version, '9P2000', 'Get version (9P2000).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'17000000'.      # size = 23
	'74'.            # type = 116
	'0300'.          # tag = 3
	'0a000000'.      # fid = 10
	'8877665544332211'.  # offset
	'00100000'       # count = 4096
);
($tag, $ret) = $obj->decode($input);
is($tag, 3, 'Get tag (3).');
isa_ok($ret, 'Data::9P::Message::Tread');
is($ret->count, 4096, 'Get count (4096).');
is($ret->fid, 10, 'Get fid (10).');
is($ret->offset, Math::BigInt->new('0x1122334455667788'),
	'Get offset (0x1122334455667788).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'1e000000'.      # size = 30
	'6e'.            # type = 110
	'0500'.          # tag
	'01000000'.      # fid
	'02000000'.      # newfid
	'0200'.          # nwname = 2
	'0300'.          # len("etc")
	'657463'.        # etc
	'0600'.          # len("passwd")
	'706173737764'   # passwd
);
($tag, $ret) = $obj->decode($input);
is($tag, 5, 'Get tag (5).');
isa_ok($ret, 'Data::9P::Message::Twalk');
is($ret->fid, 1, 'Get fid (1).');
is($ret->newfid, 2, 'Get newfid (2).');
is_deeply(
	$ret->wnames,
	[
		'etc',
		'passwd',
	],
	'Get wnames (etc, passwd).',
);

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'1c000000'.      # size = 28
	'76'.            # type = 118
	'0400'.          # tag = 4
	'0a000000'.      # fid
	'0000000000000000'.  # offset
	'05000000'.      # count
	'68656c6c6f'     # data
);
($tag, $ret) = $obj->decode($input);
is($tag, 4, 'Get tag (4).');
isa_ok($ret, 'Data::9P::Message::Twrite');
is($ret->data, 'hello', 'Get data (hello).');
is($ret->fid, 10, 'Get fid (10).');
is($ret->offset, 0, 'Get offset (0).');
