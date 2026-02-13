use strict;
use warnings;

use Data::9P::Message::Rerror;
use Data::9P::Message::Rversion;
use Data::9P::Message::Tread;
use Data::9P::Message::Tversion;
use Data::9P::Message::Twrite;
use Data::9P::Message::Twalk;
use Math::BigInt;
use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 7;
use Test::NoWarnings;

# Test.
my $obj = Net::9P::Protocol::9P2000->new;
my $msg = Data::9P::Message::Rerror->new(
	'ename' => 'Permission denied',
	'tag' => 42,
);
my $ret = $obj->encode($msg);
my $expected = pack('H*',
	'1a000000'.  # size = 26
	'6b'.        # type = 107
	'2a00'.      # tag = 42
	'1100'.      # string length = 17
	'5065726d697373696f6e2064656e696564'
);
is($ret, $expected, 'Rerror encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$msg = Data::9P::Message::Rversion->new(
	'msize' => 8192,
	'version' => '9P2000',
	'tag' => 1,
);
$ret = $obj->encode($msg);
$expected = pack('H*',
	'13000000'.  # size = 19
	'65'.        # type = 101
	'0100'.      # tag = 1
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'  # "9P2000"
);
is($ret, $expected, 'Rversion encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$msg = Data::9P::Message::Tversion->new(
	'msize' => 8192,
	'version' => '9P2000',
	'tag' => 2,
);
$ret = $obj->encode($msg);
$expected = pack('H*',
	'13000000'.  # size = 19
	'64'.        # type = 100
	'0200'.      # tag = 2
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'
);
is($ret, $expected, 'Tversion encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$msg = Data::9P::Message::Tread->new(
	'count' => 4096,
	'fid' => 10,
	'offset' => Math::BigInt->new('0x1122334455667788'),
	'tag' => 3,
);
$ret = $obj->encode($msg);
$expected = pack('H*',
	'17000000'.      # size = 23
	'74'.            # type = 116
	'0300'.          # tag = 3
	'0a000000'.      # fid = 10
	'8877665544332211'.  # offset
	'00100000'       # count = 4096
);
is($ret, $expected, 'Tread encoded correctly.');

# Test./
$obj = Net::9P::Protocol::9P2000->new;
$msg = Data::9P::Message::Twrite->new(
	'data' => 'hello',
	'fid' => 10,
	'offset' => 0,
	'tag' => 4,
);
$ret = $obj->encode($msg);
$expected = pack('H*',
	'1c000000'.      # size = 28
	'76'.            # type = 118
	'0400'.          # tag = 4
	'0a000000'.      # fid
	'0000000000000000'.  # offset
	'05000000'.      # count
	'68656c6c6f'     # data
);
is($ret, $expected, 'Twrite encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$msg = Data::9P::Message::Twalk->new(
	'fid' => 1,
	'newfid' => 2,
	'tag' => 5,
	'wnames' => ['etc', 'passwd'],
);
$ret = $obj->encode($msg);
$expected = pack('H*',
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
is($ret, $expected, 'Twalk encoded correctly.');
