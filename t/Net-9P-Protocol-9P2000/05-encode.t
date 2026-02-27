use strict;
use warnings;

use Data::9P::Const qw($NOFID $OREAD $OWRITE);
use Data::9P::Message::Rattach;
use Data::9P::Message::Rauth;
use Data::9P::Message::Rclunk;
use Data::9P::Message::Rcreate;
use Data::9P::Message::Rerror;
use Data::9P::Message::Rversion;
use Data::9P::Message::Tattach;
use Data::9P::Message::Tauth;
use Data::9P::Message::Tclunk;
use Data::9P::Message::Tcreate;
use Data::9P::Message::Tflush;
use Data::9P::Message::Topen;
use Data::9P::Message::Tread;
use Data::9P::Message::Tremove;
use Data::9P::Message::Tversion;
use Data::9P::Message::Twalk;
use Data::9P::Message::Twrite;
use Data::9P::Message::Twstat;
use Data::9P::Qid;
use Data::9P::Stat;
use Math::BigInt;
use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 21;
use Test::NoWarnings;

# Test.
my $obj = Net::9P::Protocol::9P2000->new;
my $tag = 42;
my $msg = Data::9P::Message::Rattach->new(
	'qid' => Data::9P::Qid->new(
		'type' => 0x00,
		'version' => 0,
		'path' => 1,
	),
);
my $ret = $obj->encode($tag, $msg);
my $expected = pack('H*',
	'14000000'.  # size = 20
	'69'.        # type = 105 (Rattach)
	'2a00'.      # tag = 42
	'00'.        # qid.type = 0x00
	'00000000'.  # qid.version = 0
	'0100000000000000'  # qid.path = 1
);
is($ret, $expected, 'Rattach encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Rauth->new(
	'aqid' => Data::9P::Qid->new(
		'type' => 0x80,
		'version' => 1,
		'path' => 2,
	),
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'14000000'.  # size = 20
	'67'.        # type = 103 (Rauth)
	'2a00'.      # tag = 42
	'80'.        # qid.type = 0x80
	'01000000'.  # qid.version = 1
	'0200000000000000'  # qid.path = 2
);
is($ret, $expected, 'Rauth encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Rclunk->new;
$expected = pack('H*',
	'07000000'.  # size = 7
	'79'.        # type = 121 (Rclunk)
	'2a00'       # tag = 42
);
$ret = $obj->encode($tag, $msg);
is($ret, $expected, 'Rclunk encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Rcreate->new(
	'qid' => Data::9P::Qid->new(
		'type' => 0x00,
		'version' => 0,
		'path' => 3,
	),
	'iounit' => 8192,
);
$expected = pack('H*',
	'18000000'.  # size = 24
	'73'.        # type = 115 (Rcreate)
	'2a00'.      # tag = 42
	'00'.        # qid.type = 0x00
	'00000000'.  # qid.version = 0
	'0300000000000000'. # qid.path = 3
	'00200000'   # iounit = 8192 (little-endian)
);
$ret = $obj->encode($tag, $msg);
is($ret, $expected, 'Rcreate encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Rerror->new(
	'ename' => 'Permission denied',
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'1a000000'.  # size = 26
	'6b'.        # type = 107
	'2a00'.      # tag = 42
	'1100'.      # string length = 17
	'5065726d697373696f6e2064656e696564'
);
is($ret, $expected, 'Rerror encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 1;
$msg = Data::9P::Message::Rversion->new(
	'msize' => 8192,
	'version' => '9P2000',
);
$ret = $obj->encode($tag, $msg);
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
$tag = 42;
$msg = Data::9P::Message::Tattach->new(
	'afid' => $NOFID,
	'aname' => '',
	'fid' => 1,
	'uname' => 'nobody',
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'19000000'.  # size = 25 (7 header + 18 payload)
	'68'.        # type = 104 (Tattach)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'ffffffff'.  # afid = 0xFFFFFFFF (NOFID)
	'0600'.      # uname length = 6
	'6e6f626f6479'.  # "nobody"
	'0000'       # aname length = 0
);
is($ret, $expected, 'Tattach encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tauth->new(
	'afid' => 1,
	'aname' => '',
	'uname' => 'nobody',
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'15000000'.  # size = 21 (7 header + 14 payload)
	'66'.        # type = 102 (Tauth)
	'2a00'.      # tag = 42
	'01000000'.  # afid = 1
	'0600'.      # uname length = 6
	'6e6f626f6479'.  # "nobody"
	'0000'       # aname length = 0
);
is($ret, $expected, 'Tauth encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tclunk->new(
	'fid' => 1,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'78'.        # type = 120 (Tclunk)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
is($ret, $expected, 'Tclunk encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tcreate->new(
	'fid' => 1,
	'mode' => $OWRITE,
	'name' => 'a',
	'perm' => 0644,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'13000000'.  # size = 19 (7 header + 12 payload)
	'72'.        # type = 114 (Tcreate)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'0100'.      # name length = 1
	'61'.        # "a"
	'a4010000'.  # perm = 0644
	'01'         # mode = 1 (OWRITE)
);
is($ret, $expected, 'Tcreate encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tflush->new(
	'oldtag' => 7,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'09000000'.  # size = 9 (7 header + 2 payload)
	'6c'.        # type = 108 (Tflush)
	'2a00'.      # tag = 42
	'0700'       # oldtag = 7
);
is($ret, $expected, 'Tflush encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Topen->new(
	'fid' => 1,
	'mode' => $OREAD,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'0c000000'.  # size = 12 (7 header + 5 payload)
	'70'.        # type = 112 (Topen)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'00'         # mode = 0 (OREAD)
);
is($ret, $expected, 'Topen encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 3;
$msg = Data::9P::Message::Tread->new(
	'count' => 4096,
	'fid' => 10,
	'offset' => Math::BigInt->new('0x1122334455667788'),
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'17000000'.      # size = 23
	'74'.            # type = 116
	'0300'.          # tag = 3
	'0a000000'.      # fid = 10
	'8877665544332211'.  # offset
	'00100000'       # count = 4096
);
is($ret, $expected, 'Tread encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tremove->new(
	'fid' => 1,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'7a'.        # type = 122 (Tremove)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
is($ret, $expected, 'Tremove encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 42;
$msg = Data::9P::Message::Tstat->new(
	'fid' => 1,
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'7c'.        # type = 124 (Tstat)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
is($ret, $expected, 'Tstat encoded correctly.');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 2;
$msg = Data::9P::Message::Tversion->new(
	'msize' => 8192,
	'version' => '9P2000',
);
$ret = $obj->encode($tag, $msg);
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
$tag = 0xFFFF;
$msg = Data::9P::Message::Tversion->new(
	'msize' => 8192,
	'version' => '9P2000',
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'13000000'.  # size = 19
	'64'.        # type = 100
	'FFFF'.      # tag = 0xFFFF (NOTAG)
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'
);
is($ret, $expected, 'Tversion encoded correctly (with NOTAG).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 5;
$msg = Data::9P::Message::Twalk->new(
	'fid' => 1,
	'newfid' => 2,
	'wnames' => ['etc', 'passwd'],
);
$ret = $obj->encode($tag, $msg);
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

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$tag = 4;
$msg = Data::9P::Message::Twrite->new(
	'data' => 'hello',
	'fid' => 10,
	'offset' => 0,
);
$ret = $obj->encode($tag, $msg);
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
$tag = 42;
$msg = Data::9P::Message::Twstat->new(
	'fid' => 1,
	'stat' => Data::9P::Stat->new(
		'atime' => 0,
		'dev' => 0,
		'gid' => 'g',
		'length' => 0,
		'mode' => 0644,
		'mtime' => 0,
		'muid' => 'm',
		'name' => 'a',
		'qid' => Data::9P::Qid->new(
			'path' => 1,
			'type' => 0,
			'version' => 0,
		),
		'type' => 0,
		'uid' => 'u',
	),
);
$ret = $obj->encode($tag, $msg);
$expected = pack('H*',
	'42000000'.  # size = 66 (7 header + 59 payload)
	'7e'.        # type = 126 (Twstat)
	'2a00'.      # tag = 42

	'01000000'.  # fid = 1

	'3500'.      # stat[n] length = 53 bytes (0x35)

	# --- stat blob (53 bytes) ---
	'3300'.      # stat.size = 51 bytes follow (0x33)  [= bloblen-2]
	'0000'.      # stat.type (legacy) = 0
	'00000000'.  # stat.dev = 0

	# qid (13 bytes)
	'00'.        # qid.type = 0
	'00000000'.  # qid.version = 0
	'0100000000000000'. # qid.path = 1 (u64 LE)

	'a4010000'.  # mode = 0644 (0x000001a4) LE
	'00000000'.  # atime = 0
	'00000000'.  # mtime = 0
	'0000000000000000'. # length = 0 (u64 LE)

	# name, uid, gid, muid (each: u16 len + bytes)
	'0100'. '61'.  # name = "a"
	'0100'. '75'.  # uid  = "u"
	'0100'. '67'.  # gid  = "g"
	'0100'. '6d'   # muid = "m"
);
is($ret, $expected, 'Twstat encoded correctly.');
