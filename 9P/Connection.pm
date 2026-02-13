package Net::9P::Connection;

use strict;
use warnings;

use Class::Utils qw(set_params);
use English;
use Error::Pure qw(err);
use Mo::utils 0.08 qw(check_bool check_isa check_required);
use Mo::utils::Socket qw(check_socket);
use Net::9P::Protocol::9P2000;

our $VERSION = 0.01;

# Constructor.
sub new {
	my ($class, @params) = @_;

	# Create object.
	my $self = bless {}, $class;

	# Autoflush.
	$self->{'autoflush'} = 1;

	# Protocol.
	$self->{'protocol'} = Net::9P::Protocol::9P2000->new;

	# Socket.
	$self->{'socket'} = undef;

	# Process parameters.
	set_params($self, @params);

	# Check 'autoflush'.
	check_bool($self, 'autoflush');

	# Check 'protocol'.
	check_isa($self, 'protocol', 'Net::9P::Protocol::9P2000');

	# Check 'socket',
	check_required($self, 'socket');
	check_socket($self, 'socket');

	return $self;
}

sub close {
	my $self = shift;

	if (! $self->fileno) {
		return 0;
	}

	$self->{'socket'}->close;

	return 1;
}

sub fileno {
	my $self = shift;

	return CORE::fileno($self->{'socket'});
}

sub recv {
	my $self = shift;

	$self->_check_open;

	my $hdr;
	$self->_read_exact(\$hdr, 4);
	my ($size) = unpack('V', $hdr);
	if ($size < 7) {
		err 'Invalid size.';
	}
	my $rest;
	$self->_read_exact(\$rest, $size - 4);

	return $self->{'protocol'}->decode($hdr.$rest);
}

sub send {
	my ($self, $msg) = @_;

	$self->_check_open;

	if (! defined $msg) {
		err 'The message is required.';
	}
	my $bytes = $self->{'protocol'}->encode($msg);
	my $bytes_len = length($bytes);
	if (! defined $bytes || ! $bytes_len) {
		err 'Could not encode message.';
	}
	$self->_write_all($bytes);

	return $bytes_len;
}

sub socket {
	my $self = shift;

	return $self->{'socket'};
}

sub _check_open {
	my $self = shift;

	if (! $self->fileno) {
		err 'Socket handle is closed.';
	}

	return;
}

sub _read_exact {
	my ($self, $out_sr, $len) = @_;

	${$out_sr} = '';
	my $sock = $self->{'socket'};
	while (length(${$out_sr}) < $len) {
		my $remaining = $len - length(${$out_sr});
		$self->_check_open;
		my $read = sysread($sock, my $chunk, $remaining);
		if (! defined $read) {
			if ($ERRNO{'EINTR'}) {
				next;
			}
			err 'Read error.',
				'Error', $ERRNO,
			;
		}
		if ($read == 0) {
			err 'Unexpected end of file.';
		}
		${$out_sr} .= $chunk;
	}

	return 1;
}

sub _write_all {
	 my ($self, $data) = @_;

	my $sock = $self->{'socket'};
	my $offset = 0;
	my $len = length($data);
	while ($offset < $len) {
		my $written = syswrite($sock, $data, $len - $offset, $offset);
		if (! defined $written) {
			if ($ERRNO{'EINTR'}) {
				err 'Write error.',
					'Error', $ERRNO,
				;
			}
		}
		if ($written == 0) {
			err 'Socket closed during write.';
		}
		$offset += $written;
	}

	return 1;
}

1;
