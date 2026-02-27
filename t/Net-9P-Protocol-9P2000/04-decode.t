use strict;
use warnings;

use Data::9P::Const qw($NOFID $NOTAG $OREAD $OWRITE);
use Math::BigInt;
use Net::9P::Protocol::9P2000;
use Test::More 'tests' => 138;
use Test::NoWarnings;

# Test.
my $obj = Net::9P::Protocol::9P2000->new;
my $input = pack('H*',
	'14000000'.  # size = 20
	'69'.        # type = 105 (Rattach)
	'2a00'.      # tag = 42
	'00'.        # qid.type = 0x00
	'00000000'.  # qid.version = 0
	'0100000000000000'  # qid.path = 1
);
my ($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rattach');
is($ret->qid->type, 0x00, 'Get qid.type (0x00).');
is($ret->qid->version, 0, 'Get qid.version (0).');
is($ret->qid->path, 1, 'Get qid.path (1).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'14000000'.  # size = 20
	'67'.        # type = 103 (Rauth)
	'2a00'.      # tag = 42
	'80'.        # qid.type = 0x80
	'01000000'.  # qid.version = 1
	'0200000000000000'  # qid.path = 2
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rauth');
is($ret->aqid->type, 0x80, 'Get aqid.type (0x80).');
is($ret->aqid->version, 1, 'Get aqid.version (1).');
is($ret->aqid->path, 2, 'Get aqid.path (2).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'07000000'.  # size = 7
	'79'.        # type = 121 (Rclunk)
	'2a00'       # tag = 42
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rclunk');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'18000000'.  # size = 24
	'73'.        # type = 115 (Rcreate)
	'2a00'.      # tag = 42
	'00'.        # qid.type = 0x00
	'00000000'.  # qid.version = 0
	'0300000000000000'. # qid.path = 3
	'00200000'   # iounit = 8192 (little-endian)
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rcreate');
is($ret->qid->type, 0x00, 'Get qid.type (0x00).');
is($ret->qid->version, 0, 'Get qid.version (0).');
is($ret->qid->path, 3, 'Get qid.path (3).');
is($ret->iounit, 8192, 'Get iounit (8192).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'1a000000'.  # size = 26
	'6b'.        # type = 107 (Rerror)
	'2a00'.      # tag = 42
	'1100'.      # string length = 17
	'5065726d697373696f6e2064656e696564'
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rerror');
is($ret->ename, 'Permission denied', 'Get ename (Permission denied).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'07000000'.  # size = 7
	'6d'.        # type = 109 (Rflush)
	'2a00'       # tag = 42
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rflush');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'18000000'.  # size = 24
	'71'.        # type = 113 (Ropen)
	'2a00'.      # tag = 42
	'00'.        # qid.type = 0x00
	'01000000'.  # qid.version = 1
	'0400000000000000'. # qid.path = 4
	'00100000'   # iounit = 4096
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Ropen');
is($ret->qid->type, 0x00, 'Get qid.type (0x00).');
is($ret->qid->version, 1, 'Get qid.version (1).');
is($ret->qid->path, 4, 'Get qid.path (4).');
is($ret->iounit, 4096, 'Get iounit (4096).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'07000000'.  # size = 7
	'7b'.        # type = 123 (Rremove)
	'2a00'       # tag = 42
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rremove');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'3a000000'.  # size = 58
	'7d'.        # type = 125 (Rstat)
	'2a00'.      # tag = 42
	'3100'.      # statlen = 49

	# stat block (49 bytes total):
	'2f00'.      # inner size = 47
	'0000'.      # type (u16)
	'00000000'.  # dev  (u32)
	'00'.        # qid.type
	'00000000'.  # qid.version
	'0100000000000000'. # qid.path = 1
	'ff010000'.  # mode = 511 (0x1ff)
	'01000000'.  # atime = 1
	'02000000'.  # mtime = 2
	'0000000000000000'. # length = 0
	'0000'.      # name = ""
	'0000'.      # uid  = ""
	'0000'.      # gid  = ""
	'0000'       # muid = ""
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rstat');
is($ret->stat->qid->type, 0, 'Get stat.type (0).');
is($ret->stat->qid->version, 0, 'Get stat.version (0).');
is($ret->stat->qid->path, 1, 'Get stat.qid.path (1).');
is($ret->stat->mode, 511, 'Get stat.mode (511).');
is($ret->stat->name, '', 'Get stat.name ("").');
is($ret->stat->uid, '', 'Get stat.uid ("").');
is($ret->stat->muid, '', 'Get stat.muid ("").');
is($ret->stat->gid, '', 'Get stat.gid ("").');
is($ret->stat->atime, 1, 'Get stat.atime (1).');
is($ret->stat->mtime, 2, 'Get stat.mtime (2).');
is($ret->stat->type, 0, 'Get stat.type (0).');
is($ret->stat->dev, 0, 'Get stat.dev (0).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'13000000'.  # size = 19
	'65'.        # type = 101 (Rversion)
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
	'23000000'.  # size = 35
	'6f'.        # type = 111 (Rwalk)
	'2a00'.      # tag = 42
	'0200'.      # nwqid = 2

	# qid[0]
	'00'.        # qid.type = 0x00
	'01000000'.  # qid.version = 1
	'0100000000000000'. # qid.path = 1

	# qid[1]
	'80'.        # qid.type = 0x80
	'02000000'.  # qid.version = 2
	'0200000000000000'  # qid.path = 2
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rwalk');
is(scalar(@{$ret->wqid}), 2, 'Get nwqid (2).');
is($ret->wqid->[0]->type, 0x00, 'Get wqid[0].type (0x00).');
is($ret->wqid->[0]->version, 1, 'Get wqid[0].version (1).');
is($ret->wqid->[0]->path, 1, 'Get wqid[0].path (1).');
is($ret->wqid->[1]->type, 0x80, 'Get wqid[1].type (0x80).');
is($ret->wqid->[1]->version, 2, 'Get wqid[1].version (2).');
is($ret->wqid->[1]->path, 2, 'Get wqid[1].path (2).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'0b000000'.  # size = 11
	'77'.        # type = 119 (Rwrite)
	'2a00'.      # tag = 42
	'05000000'   # count = 5
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rwrite');
is($ret->count, 5, 'Get count (5).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'07000000'.  # size = 7
	'7f'.        # type = 127 (Rwstat)
	'2a00'       # tag = 42
);
($tag, $ret) = $obj->decode($input);
is($tag, 42, 'Get tag (42).');
isa_ok($ret, 'Data::9P::Message::Rwstat');

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
	'74'.            # type = 116 (Tread)
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
	'64'.        # type = 100 (Tversion)
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
	'13000000'.  # size = 19
	'64'.        # type = 100 (Tversion)
	'FFFF'.      # tag = 0xFFFF - NOTAG
	'00200000'.  # msize = 8192
	'0600'.      # string length = 6
	'395032303030'
);
($tag, $ret) = $obj->decode($input);
is($tag, $NOTAG, 'Get tag ('.$NOTAG.').');
isa_ok($ret, 'Data::9P::Message::Tversion');
is($ret->msize, 8192, 'Get msize (8192).');
is($ret->version, '9P2000', 'Get version (9P2000).');

# Test.
$obj = Net::9P::Protocol::9P2000->new;
$input = pack('H*',
	'1e000000'.      # size = 30
	'6e'.            # type = 110 (Twalk)
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
	'76'.            # type = 118 (Twrite)
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
