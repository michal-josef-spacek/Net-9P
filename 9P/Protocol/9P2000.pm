package Net::9P::Protocol::9P2000;

use strict;
use warnings;

use Class::Utils qw(set_params);
use Data::9P::Message::Rauth;
use Data::9P::Message::Rattach;
use Data::9P::Message::Rclunk;
use Data::9P::Message::Rcreate;
use Data::9P::Message::Rerror;
use Data::9P::Message::Rflush;
use Data::9P::Message::Ropen;
use Data::9P::Message::Rread;
use Data::9P::Message::Rremove;
use Data::9P::Message::Rstat;
use Data::9P::Message::Rversion;
use Data::9P::Message::Rwalk;
use Data::9P::Message::Rwrite;
use Data::9P::Message::Rwstat;
use Data::9P::Message::Tattach;
use Data::9P::Message::Tauth;
use Data::9P::Message::Tclunk;
use Data::9P::Message::Tcreate;
use Data::9P::Message::Tflush;
use Data::9P::Message::Topen;
use Data::9P::Message::Tread;
use Data::9P::Message::Tremove;
use Data::9P::Message::Tstat;
use Data::9P::Message::Tversion;
use Data::9P::Message::Twalk;
use Data::9P::Message::Twrite;
use Data::9P::Message::Twstat;
use Data::9P::Qid;
use Data::9P::Stat;
use Error::Pure qw(err);
use Math::BigInt ();
use Readonly;
use Scalar::Util qw(blessed);

Readonly::Hash our %TYPE => (
	100 => 'Data::9P::Message::Tversion',
	101 => 'Data::9P::Message::Rversion',

	102 => 'Data::9P::Message::Tauth',
	103 => 'Data::9P::Message::Rauth',

	104 => 'Data::9P::Message::Tattach',
	105 => 'Data::9P::Message::Rattach',

#	106 => 'Data::9P::Message::Terror', # historical, not used
	107 => 'Data::9P::Message::Rerror',

	108 => 'Data::9P::Message::Tflush',
	109 => 'Data::9P::Message::Rflush',

	110 => 'Data::9P::Message::Twalk',
	111 => 'Data::9P::Message::Rwalk',

	112 => 'Data::9P::Message::Topen',
	113 => 'Data::9P::Message::Ropen',

	114 => 'Data::9P::Message::Tcreate',
	115 => 'Data::9P::Message::Rcreate',

	116 => 'Data::9P::Message::Tread',
	117 => 'Data::9P::Message::Rread',

	118 => 'Data::9P::Message::Twrite',
	119 => 'Data::9P::Message::Rwrite',

	120 => 'Data::9P::Message::Tclunk',
	121 => 'Data::9P::Message::Rclunk',

	122 => 'Data::9P::Message::Tremove',
	123 => 'Data::9P::Message::Rremove',

	124 => 'Data::9P::Message::Tstat',
	125 => 'Data::9P::Message::Rstat',

	126 => 'Data::9P::Message::Twstat',
	127 => 'Data::9P::Message::Rwstat',
);
Readonly::Hash our %REV_TYPE => reverse %TYPE;

our $VERSION = 0.01;

# Constructor.
sub new {
	my ($class, @params) = @_;

	# Create object.
	my $self = bless {}, $class;

	# Verbose.
#	$self->{'verbose'} = undef;

	# Process parameters.
	set_params($self, @params);

	return $self;
}

sub decode {
	my ($self, $bytes) = @_;

	my ($size, $type, $tag) = unpack('V C v', substr($bytes, 0, 7));

	if (! exists $TYPE{$type}) {
		err "Unknown message type '$type'.";
	}

	my $payload = substr($bytes, 7);

	my $msg_ref = $TYPE{$type};
	my $msg_class = lc((split m/:/ms, $msg_ref)[-1]);
	my $method = '_decode_'.$msg_class;

	my $msg = $self->$method($payload);

	return ($tag, $msg);
}

sub encode {
	my ($self, $tag, $msg) = @_;

	if (! blessed($msg)
		|| ! $msg->isa('Data::9P::Message')) {

		err 'Bad Data::9P::Message object.';
	}
	my $msg_ref = ref $msg;
	if (! exists $REV_TYPE{$msg_ref}) {
		err "Message '$msg_ref' isn't supported.";
	}

	my $msg_class = lc((split m/:/ms, $msg_ref)[-1]);
	my $method = '_encode_'.$msg_class;
	my ($type, $payload) = $self->$method($msg);
	my $size = 7 + length $payload;

	return pack('V C v', $size, $type, $tag).$payload;
}

sub _dec_stat {
	my ($self, $bytes_sr) = @_;

	if (length(${$bytes_sr}) < 45) {
		err 'Stat blob too short.';
	}
	my ($inner_size) = unpack('v', substr(${$bytes_sr}, 0, 2, ''));
	if ($inner_size != length(${$bytes_sr})) {
		err 'Stat size mismatch.';
	}
	my ($type) = unpack('v', substr(${$bytes_sr}, 0, 2, ''));
	my ($dev) = unpack('V', substr(${$bytes_sr}, 0, 4, ''));
	my $qid = $self->_dec_qid($bytes_sr);
	if (length(${$bytes_sr}) < 4+4+4+8) {
		err 'Stat blob too short for fixed fields.';
	}
	my ($mode) = unpack('V', substr(${$bytes_sr}, 0, 4, ''));
	my ($atime) = unpack('V', substr(${$bytes_sr}, 0, 4, ''));
	my ($mtime) = unpack('V', substr(${$bytes_sr}, 0, 4, ''));
	my ($length) = unpack('Q<', substr(${$bytes_sr}, 0, 8, ''));
	my $name = $self->_dec_str($bytes_sr);
	my $uid = $self->_dec_str($bytes_sr);
	my $gid = $self->_dec_str($bytes_sr);
	my $muid = $self->_dec_str($bytes_sr);
	if (length(${$bytes_sr})) {
		err 'Trailing bytes in stat.';
	}

	return Data::9P::Stat->new(
		'atime' => $atime,
		'dev' => $dev,
		'gid' => $gid,
		'length' => $length,
		'mode' => $mode,
		'mtime' => $mtime,
		'muid' => $muid,
		'name' => $name,
		'qid' => $qid,
		'type' => $type,
		'uid' => $uid,
	);
}

sub _dec_qid {
	my ($self, $bytes_sr) = @_;

	if (length(${$bytes_sr}) < 13) {
		err 'Payload too short for qid.';
	}
	my ($type) = unpack('C', substr(${$bytes_sr}, 0, 1, ''));
	my ($version) = unpack('V', substr(${$bytes_sr}, 0, 4, ''));
	my ($path) = unpack('Q<', substr(${$bytes_sr}, 0, 8, ''));

	return Data::9P::Qid->new(
		'path' => $path,
		'type' => $type,
		'version' => $version,
	);
}

sub _dec_str {
	my ($self, $bytes_sr) = @_;

	if (length(${$bytes_sr}) < 2) {
		err 'Payload too short for string length.';
	}
	my ($len) = unpack('v', substr(${$bytes_sr}, 0, 2, ''));
	if (length(${$bytes_sr}) < $len) {
		err 'Payload too short for string content.';
	}
	my $str = substr(${$bytes_sr}, 0, $len, '');

	return $str;
}

sub _decode_rauth {
	my ($self, $payload) = @_;

	my $buf = $payload;
	my $aqid = $self->_dec_qid(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Rauth.';
	}

	return Data::9P::Message::Rauth->new(
		'aqid' => $aqid,
	);
}

sub _decode_rattach {
	my ($self, $payload) = @_;

	my $buf = $payload;
	my $qid = $self->_dec_qid(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Rattach.';
	}

	return Data::9P::Message::Rattach->new(
		'qid' => $qid,
	);
}

sub _decode_rclunk {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf)) {
		err 'Trailing bytes in Rclunk.';
	}

	return Data::9P::Message::Rclunk->new;
}

sub _decode_rcreate {
	my ($self, $payload) = @_;

	my $buf = $payload;
	my $qid = $self->_dec_qid(\$buf);
	if (length($buf) < 4) {
		err 'Payload too short for iounit.';
	}
	my ($iounit) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Rcreate.';
	}

	return Data::9P::Message::Rcreate->new(
		'iounit' => $iounit,
		'qid' => $qid,
	);
}

sub _decode_rerror {
	my ($self, $payload) = @_;

	my $buf = $payload;
	my $ename = $self->_dec_str(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Rerror.';
	}

	return Data::9P::Message::Rerror->new(
		'ename' => $ename,
	);
}

sub _decode_rflush {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf)) {
		err 'Trailing bytes in Rflush.';
	}

	return Data::9P::Message::Rflush->new;
}

sub _decode_ropen {
	my ($self, $payload) = @_;

	my $buf = $payload;
	my $qid = $self->_dec_qid(\$buf);
	if (length($buf) < 4) {
		err 'Payload too short for iounit.';
	}
	my ($iounit) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Ropen.';
	}

	return Data::9P::Message::Ropen->new(
		'iounit' => $iounit,
		'qid' => $qid,
        );
}

sub _decode_rread {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for count.';
	}
	my ($count) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf) < $count) {
		err 'Payload too short for data.';
	}
	my $data = substr($buf, 0, $count, '');
	if (length($buf)) {
		err 'Trailing bytes in Rread.';
	}

	return Data::9P::Message::Rread->new(
		'data' => $data,
	);
}

sub _decode_rremove {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf)) {
		err 'Trailing bytes in Rremove.';
	}

	return Data::9P::Message::Rremove->new;
}

sub _decode_rstat {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 2) {
		err 'Payload too short for stat size.';
	}
	my ($statsz) = unpack('v', substr($buf, 0, 2, ''));
	if (length($buf) < $statsz) {
		err 'Payload too short for stat data.';
	}
	my $stat_blob = substr($buf, 0, $statsz, '');
	if (length($buf)) {
		err 'Trailing bytes in Rstat.';
	}
	my $stat = $self->_dec_stat(\$stat_blob);

	return Data::9P::Message::Rstat->new(
		'stat' => $stat,
	);
}

sub _decode_rversion {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for msize.';
	}
	my ($msize) = unpack('V', substr($buf, 0, 4, ''));
	my $version = $self->_dec_str(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Rversion.';
	}

	return Data::9P::Message::Rversion->new(
		'msize' => $msize,
		'version' => $version,
	);
}

sub _decode_rwalk {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 2) {
		err 'Payload too short for nwqid.';
	}
	my ($nwqid) = unpack('v', substr($buf, 0, 2, ''));
	my @wqid;
	foreach (1 .. $nwqid) {
		push @wqid, $self->_dec_qid(\$buf);
	}
	if (length($buf)) {
		err 'Trailing bytes in Rwalk.';
	}

	return Data::9P::Message::Rwalk->new(
		'wqid' => \@wqid,
	);
}

sub _decode_rwrite {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for count.';
	}
	my ($count) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Rwrite.';
	}

	return Data::9P::Message::Rwrite->new(
		'count' => $count,
	);
}

sub _decode_rwstat {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf)) {
		err 'Trailing bytes in Rwstat.';
	}

	return Data::9P::Message::Rwstat->new;
}

sub _decode_tattach {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 8) {
		err 'Payload too short for Tattach header.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($afid) = unpack('V', substr($buf, 0, 4, ''));
	my $uname = $self->_dec_str(\$buf);
	my $aname = $self->_dec_str(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Tattach.';
	}

	return Data::9P::Message::Tattach->new(
		'afid' => $afid,
		'aname' => $aname,
		'fid' => $fid,
		'uname' => $uname,
	);
}

sub _decode_tauth {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for afid.';
	}
	my ($afid) = unpack('V', substr($buf, 0, 4, ''));
	my $uname = $self->_dec_str(\$buf);
	my $aname = $self->_dec_str(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Tauth.';
	}

	return Data::9P::Message::Tauth->new(
		'afid' => $afid,
		'aname' => $aname,
		'uname' => $uname,
	);
}

sub _decode_tclunk {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for fid.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tclunk.';
	}

	return Data::9P::Message::Tclunk->new(
		'fid' => $fid,
	);
}

sub _decode_tcreate {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 5) {
		err 'Payload too short for Tcreate header.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my $name = $self->_dec_str(\$buf);
	if (length($buf) < 5) {
		err 'Payload too short for perm/mode.';
	}
	my ($perm) = unpack('V', substr($buf, 0, 4, ''));
	my ($mode) = unpack('C', substr($buf, 0, 1, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tcreate.';
	}

	return Data::9P::Message::Tcreate->new(
		'fid' => $fid,
		'mode' => $mode,
		'name' => $name,
		'perm' => $perm,
	);
}

sub _decode_tflush {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 2) {
		err 'Payload too short for oldtag.';
	}
	my ($oldtag) = unpack('v', substr($buf, 0, 2, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tflush.';
	}

	return Data::9P::Message::Tflush->new(
		'oldtag' => $oldtag,
	);
}

sub _decode_topen {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 5) {
		err 'Payload too short for Topen.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($mode) = unpack('C', substr($buf, 0, 1, ''));
	if (length($buf)) {
		 err 'Trailing bytes in Topen.';
	}

	return Data::9P::Message::Topen->new(
		'fid' => $fid,
		'mode' => $mode,
	);
}

sub _decode_tread {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 16) {
		err 'Payload too short for Tread.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($offset) = unpack('Q<', substr($buf, 0, 8, ''));
	my ($count) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tread.';
	}
	return Data::9P::Message::Tread->new(
		'count' => $count,
		'fid' => $fid,
		'offset' => $offset,
	);
}

sub _decode_tremove {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		 err 'Payload too short for fid.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tremove.';
	}

	return Data::9P::Message::Tremove->new(
		'fid' => $fid,
	);
}

sub _decode_tstat {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for fid.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf)) {
		err 'Trailing bytes in Tstat.';
	}

	return Data::9P::Message::Tstat->new(
		'fid' => $fid,
	);
}

sub _decode_tversion {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 4) {
		err 'Payload too short for msize.';
	}
	my ($msize) = unpack('V', substr($buf, 0, 4, ''));
	my $version = $self->_dec_str(\$buf);
	if (length($buf)) {
		err 'Trailing bytes in Tversion.';
	}

	return Data::9P::Message::Tversion->new(
		'msize' => $msize,
		'version' => $version,
	);
}

sub _decode_twalk {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 10) {
		err 'Payload too short for Twalk header.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($newfid) = unpack('V', substr($buf, 0, 4, ''));
	my ($nwname) = unpack('v', substr($buf, 0, 2, ''));
	my @wnames;
	foreach (1 .. $nwname) {
		push @wnames, $self->_dec_str(\$buf);
	}
	if (length($buf)) {
		err 'Trailing bytes in Twalk.';
	}

	return Data::9P::Message::Twalk->new(
		'fid' => $fid,
		'newfid' => $newfid,
		'wnames' => \@wnames,
	);
}

sub _decode_twrite {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 16) {
		err 'Payload too short for Twrite header.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($offset) = unpack('Q<', substr($buf, 0, 8, ''));
	my ($count) = unpack('V', substr($buf, 0, 4, ''));
	if (length($buf) < $count) {
		err 'Payload too short for Twrite data.';
	}
	my $data = substr($buf, 0, $count, '');
	if (length($buf)) {
		err 'Trailing bytes in Twrite.';
	}

	return Data::9P::Message::Twrite->new(
		'data' => $data,
		'fid' => $fid,
		'offset' => $offset,
	);
}

sub _decode_twstat {
	my ($self, $payload) = @_;

	my $buf = $payload;
	if (length($buf) < 6) {
		err 'Payload too short for Twstat header.';
	}
	my ($fid) = unpack('V', substr($buf, 0, 4, ''));
	my ($statsz) = unpack('v', substr($buf, 0, 2, ''));
	if (length($buf) < $statsz) {
		err 'Payload too short for Twstat stat data.';
	}
	my $stat_blob = substr($buf, 0, $statsz, '');
	if (length($buf)) {
		err 'Trailing bytes in Twstat.';
	}

	my $stat = $self->_dec_stat(\$stat_blob);

	return Data::9P::Message::Twstat->new(
		'fid' => $fid,
		'stat' => $stat,
	);
}

sub _pack_u64_le {
	my ($self, $v) = @_;

	if ($v =~ /^\d+\z/) {
		my $uv = 0 + $v;
		if ("$uv" eq $v) {
			return pack('Q<', $uv);
		}
	}

	my $bi = Math::BigInt->new($v);
	my @bytes;
	foreach (1 .. 8) {
		push @bytes, ($bi & 255)->numify;
		$bi >>= 8;
	}

	return pack('C*', @bytes);
}

sub _enc_qid {
	my ($self, $qid) = @_;

	return pack('C', $qid->type).
		pack('V', $qid->version).
		$self->_pack_u64_le($qid->path);
}

sub _enc_stat {
	my ($self, $stat) = @_;

	my $body = pack('v', $stat->type).
		pack('V', $stat->dev).
		$self->_enc_qid($stat->qid).
		pack('V', $stat->mode).
		pack('V', $stat->atime).
		pack('V', $stat->mtime).
		$self->_pack_u64_le($stat->length).
		$self->_enc_str($stat->name).
		$self->_enc_str($stat->uid).
		$self->_enc_str($stat->gid).
		$self->_enc_str($stat->muid);
	my $size = length($body);
	if ($size > 0xFFFF) {
		err 'Stat too large.';
	}

	return pack('v', $size).$body;
}

sub _enc_str {
	my ($self, $s) = @_;

	return pack('v', length($s)).$s;
}

sub _encode_rauth {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_qid($msg->aqid);

	return (103, $payload);
}

sub _encode_rattach {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_qid($msg->qid);

	return (105, $payload);
}

sub _encode_rclunk {
	my ($self, $msg) = @_;

	return (121, '');
}

sub _encode_rcreate {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_qid($msg->qid).
		pack('V', $msg->iounit);

	return (115, $payload);
}

sub _encode_rerror {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_str($msg->ename);

	return (107, $payload);
}

sub _encode_rflush {
	my ($self, $msg) = @_;

	return (109, '');
}

sub _encode_ropen {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_qid($msg->qid).
		pack('V', $msg->iounit);

	return (113, $payload);
}

sub _encode_rread {
	my ($self, $msg) = @_;

	my $data  = $msg->data;
	my $count = length($data);
	my $payload = pack('V', $count).$data;

	return (117, $payload);
}

sub _encode_rremove {
	my ($self, $msg) = @_;

	return (123, '');
}

sub _encode_rstat {
	my ($self, $msg) = @_;

	my $stat_blob = $self->_enc_stat($msg->stat);
	my $payload = pack('v', length($stat_blob)).
		$stat_blob;

	return (125, $payload);
}

sub _encode_rversion {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->msize).
		$self->_enc_str($msg->version);

	return (101, $payload);
}

sub _encode_rwalk {
	my ($self, $msg) = @_;

	my $wqid_ar = $msg->wqid;
	my $nwqid = scalar @{$wqid_ar};
	my $payload = pack('v', $nwqid);
	foreach my $qid (@{$wqid_ar}) {
		$payload .= $self->_enc_qid($qid);
	}

	return (111, $payload);
}

sub _encode_rwrite {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->count);

	return (119, $payload);
}

sub _encode_rwstat {
	my ($self, $msg) = @_;

	return (127, '');
}

sub _encode_tauth {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->afid).
		$self->_enc_str($msg->uname).
		$self->_enc_str($msg->aname);

	return (102, $payload);
}

sub _encode_tattach {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid).
		pack('V', $msg->afid).
		$self->_enc_str($msg->uname).
		$self->_enc_str($msg->aname);

	return (104, $payload);
}

sub _encode_tclunk {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid);

	return (120, $payload);
}

sub _encode_tcreate {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid).
		$self->_enc_str($msg->name).
		pack('V', $msg->perm).
		pack('C', $msg->mode);

	return (114, $payload);
}

sub _encode_tflush {
	my ($self, $msg) = @_;

	my $payload = pack('v', $msg->oldtag);

	return (108, $payload);
}

sub _encode_topen {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid).
		pack('C', $msg->mode);

	return (112, $payload);
}

sub _encode_tread {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid).
		pack('Q<', $msg->offset).
		pack('V', $msg->count);

	return (116, $payload);
}

sub _encode_tremove {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid);

	return (122, $payload);
}

sub _encode_tstat {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid);

	return (124, $payload);
}

sub _encode_tversion {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->msize).
		$self->_enc_str($msg->version);

	return (100, $payload);
}

sub _encode_twalk {
	my ($self, $msg) = @_;

	my $names_ar = $msg->wnames;
	my $nw = scalar @{$names_ar};

	my $payload = pack('V', $msg->fid).
		pack('V', $msg->newfid).
		pack('v', $nw);

	foreach my $name (@{$names_ar}) {
		$payload .= $self->_enc_str($name);
	}

	return (110, $payload);
}

sub _encode_twrite {
	my ($self, $msg) = @_;

	my $data = $msg->data;
	my $count = length($data);

	my $payload = pack('V', $msg->fid).
		pack('Q<', $msg->offset).
		pack('V', $count).
		$data;

	return (118, $payload);
}

sub _encode_twstat {
	my ($self, $msg) = @_;

	my $stat_blob = $self->_enc_stat($msg->stat);
	my $payload = pack('V', $msg->fid).
		pack('v', length($stat_blob)).
		$stat_blob;

	return (126, $payload);
}

1;

__END__
