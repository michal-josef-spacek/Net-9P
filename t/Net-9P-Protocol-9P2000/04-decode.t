use strict;
use warnings;

use Data::9P::Const qw($NOFID $OREAD $OWRITE);
use Math::BigInt;
use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 78;
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
	'15000000'.  # size = 21 (7 header + 14 payload)
	'66'.        # type = 102 (Tauth)
	'2a00'.      # tag = 42
	'01000000'.  # afid = 1
	'0600'.      # uname length = 6
	'6e6f626f6479'.  # "nobody"
	'0000'       # aname length = 0
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tauth');
is($ret->afid, 1, 'Get afid (1).');
is($ret->uname, 'nobody', 'Get uname (nobody).');
is($ret->aname, '', 'Get aname (empty).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'19000000'.  # size = 25 (7 header + 18 payload)
	'68'.        # type = 104 (Tattach)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'ffffffff'.  # afid = 0xFFFFFFFF (NOFID)
	'0600'.      # uname length = 6
	'6e6f626f6479'.  # "nobody"
	'0000'       # aname length = 0
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tattach');
is($ret->fid, 1, 'Get fid (1).');
is($ret->afid, $NOFID, 'Get afid (NOFID).');
is($ret->uname, 'nobody', 'Get uname (nobody).');
is($ret->aname, '', 'Get aname (empty).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'78'.        # type = 120 (Tclunk)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tclunk');
is($ret->fid, 1, 'Get fid (1).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'13000000'.  # size = 19 (7 header + 12 payload)
	'72'.        # type = 114 (Tcreate)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'0100'.      # name length = 1
	'61'.        # "a"
	'a4010000'.  # perm = 0644
	'01'         # mode = 1 (OWRITE)
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tcreate');
is($ret->fid, 1, 'Get fid (1).');
is($ret->name, 'a', 'Get name (a).');
is($ret->perm, 0644, 'Get perm (0644).');
is($ret->mode, $OWRITE, 'Get mode (OWRITE=1).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'09000000'.  # size = 9 (7 header + 2 payload)
	'6c'.        # type = 108 (Tflush)
	'2a00'.      # tag = 42
	'0700'       # oldtag = 7
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tflush');
is($ret->oldtag, 7, 'Get oldtag (7).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'0c000000'.  # size = 12 (7 header + 5 payload)
	'70'.        # type = 112 (Topen)
	'2a00'.      # tag = 42
	'01000000'.  # fid = 1
	'00'         # mode = 0 (OREAD)
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Topen');
is($ret->fid, 1, 'Get fid (1).');
is($ret->mode, $OREAD, 'Get mode (OREAD=0).');

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
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'7a'.        # type = 122 (Tremove)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tremove');
is($ret->fid, 1, 'Get fid (1).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'0b000000'.  # size = 11 (7 header + 4 payload)
	'7c'.        # type = 124 (Tstat)
	'2a00'.      # tag = 42
	'01000000'   # fid = 1
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Tstat');
is($ret->fid, 1, 'Get fid (1).');

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

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
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
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Twstat');
is($ret->fid, 1, 'Get fid (1).');
my $st = $ret->stat;
isa_ok($st, 'Data::9P::Stat');
is($st->atime, 0, 'Stat atime (0).');
is($st->mtime, 0, 'Stat mtime (0).');
is($st->length, 0, 'Stat length (0).');
is($st->dev, 0, 'Stat dev (0).');
is($st->name, 'a', 'Stat name (a).');
is($st->uid, 'u', 'Stat uid (u).');
is($st->gid, 'g', 'Stat gid (g).');
is($st->muid, 'm', 'Stat muid (m).');
is($st->mode, 0644, 'Stat mode (0644).');
is($st->type, 0, 'Stat type (0).');
my $qid = $st->qid;
isa_ok($qid, 'Data::9P::Qid');
is($qid->type, 0, 'Qid type (0).');
is($qid->version, 0, 'Qid version (0).');
is($qid->path, 1, 'Qid path (1).');
