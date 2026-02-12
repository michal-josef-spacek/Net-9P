package Net::9P::Protocol::9P2000;

use strict;
use warnings;

use Class::Utils qw(set_params);
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

	# TODO
}

sub encode {
	my ($self, $msg) = @_;

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

	return pack('V C v', $size, $type, $msg->tag).$payload;
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

	my $payload = pack('V',  $msg->fid).
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
