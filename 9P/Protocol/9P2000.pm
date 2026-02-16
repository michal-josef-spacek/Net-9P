package Net::9P::Protocol::9P2000;

use strict;
use warnings;

use Class::Utils qw(set_params);
use Data::9P::Message::Rerror;
use Data::9P::Message::Rversion;
use Data::9P::Message::Tread;
use Data::9P::Message::Tversion;
use Data::9P::Message::Twalk;
use Data::9P::Message::Twrite;
use Error::Pure qw(err);
use Readonly;
use Scalar::Util qw(blessed);

Readonly::Hash our %TYPE => (
	100 => 'Data::9P::Message::Tversion',
	101 => 'Data::9P::Message::Rversion',

#	102 => 'Data::9P::Message::Tauth',
#	103 => 'Data::9P::Message::Rauth',

#	104 => 'Data::9P::Message::Tattach',
#	105 => 'Data::9P::Message::Rattach',

#	106 => 'Data::9P::Message::Terror', # historical, not used
	107 => 'Data::9P::Message::Rerror',

#	108 => 'Data::9P::Message::Tflush',
#	109 => 'Data::9P::Message::Rflush',

	110 => 'Data::9P::Message::Twalk',
#	111 => 'Data::9P::Message::Rwalk',

#	112 => 'Data::9P::Message::Topen',
#	113 => 'Data::9P::Message::Ropen',

#	114 => 'Data::9P::Message::Tcreate',
#	115 => 'Data::9P::Message::Rcreate',

	116 => 'Data::9P::Message::Tread',
#	117 => 'Data::9P::Message::Rread',

	118 => 'Data::9P::Message::Twrite',
#	119 => 'Data::9P::Message::Rwrite',

#	120 => 'Data::9P::Message::Tclunk',
#	121 => 'Data::9P::Message::Rclunk',

#	122 => 'Data::9P::Message::Tremove',
#	123 => 'Data::9P::Message::Rremove',

#	124 => 'Data::9P::Message::Tstat',
#	125 => 'Data::9P::Message::Rstat',

#	126 => 'Data::9P::Message::Twstat',
#	127 => 'Data::9P::Message::Rwstat',
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

sub _dec_str {
	my ($self, $bytes_sr) = @_;

	# TODO Check.

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
		err 'Trailing bytes in Tversion.';
	}
	return Data::9P::Message::Tread->new(
		'count' => $count,
		'fid' => $fid,
		'offset' => $offset,
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

sub _enc_str {
	my ($self, $s) = @_;

	return pack('v', length($s)).$s;
}

sub _encode_rerror {
	my ($self, $msg) = @_;

	my $payload = $self->_enc_str($msg->ename);

	return (107, $payload);
}

sub _encode_rversion {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->msize).
		$self->_enc_str($msg->version);

	return (101, $payload);
}

sub _encode_tread {
	my ($self, $msg) = @_;

	my $payload = pack('V', $msg->fid).
		pack('Q<', $msg->offset).
		pack('V', $msg->count);

	return (116, $payload);
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

1;

__END__
