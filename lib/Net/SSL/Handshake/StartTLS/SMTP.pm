package Net::SSL::Handshake::StartTLS::SMTP;

use Moose;

extends 'Net::SSL::Handshake';

use IO::Socket::Timeout;
use Net::Cmd;                                      # need constants
use Net::SMTP;

use English qw( -no_match_vars );

use 5.010;

=encoding utf8

=head1 NAME

Net::SSL::Handshake::StartTLS::SMTP - SSL Handshake via SMTP+StartTLS

=head1 VERSION

Version 0.1.x, $Revision: 640 $


=cut


=head1 SYNOPSIS

  use Net::SSL::Handshake::StartTLS::SMTP;
  
  # the same API as Net::SSL::Handshake
  my $handshake = $self->Net::SSL::Handshake::StartTLS::SMTP->new
      (
      host        => $self->host,
      ssl_version => $ssl_version,
      ciphers     => $self->ciphers_to_check
      );
  $handshake->hello;
  

=head1 DESCRIPTION

This module simulates an SSL/TLS-Handshake like Net::SSL::Handshake, but encapsulated in a 
SMTP dialog with STARTSSL.

This module derives everything from Net::SSL::Handshake, but adds SMTP and STARTTLS. For this, 
it overrides _build_socket to start an SMTP session and STARTTLS. After SSL/TLS connections ends, 
an SMTP quit command is sent.

When no host (but a socket) is given, this code does not work and is nearly obsolete and 
the socket is used unaltered by Net::SSL::Handshake.


New Parameters:

=over 4

=item *

max_retries: when a temporary error (421/450) occured, the connection may be retried. 
Set max_retries to 0 to disable retry; or any other value to enable. Default: 2 retries.

=item *

throttle_time: time (in seconds) to wait when retrying. This time is multiplicated with the 
retry number. Default: 65 seconds (which means, that the 2nd retry waits 130 seconds, ...)

=back



=cut


has '+port'       => ( default => 25, );
has max_retries   => ( is      => "ro", isa => "Int", default => 0, );
has throttle_time => ( is      => "ro", isa => "Int", default => 65, );
has my_hostname   => ( is      => "ro", isa => "Str", default => "tls-check.localhost", );


# when SSL/TLS closed: send SMTP QUIT!
after close_notify => sub {
   my $self = shift;
   $self->socket->quit;
   return;
};


sub _build_socket
   {
   my $self = shift;

   die __PACKAGE__ . ": need parameter socket or host!\n" unless $self->host;

   my $mx = $self->host;

   my $smtp;
   for my $retry ( 0 .. $self->max_retries )
      {
      my $state = "";
      $self->_wait( $retry, $state ) if $retry;

      # Step 1: connect, die on error; but if 421 or 450: wait and retry
      $smtp = Net::SMTP->new( Hello => $self->my_hostname, Host => $mx, Timeout => $self->timeout, );
      unless ($smtp)
         {

         if ( $@ =~ m{: \s* 4(?:21|50) }x )
            {
            # no, can't quit on not defined obj ... $smtp->quit;
            $state = "SMTP Connection";
            next;
            }
         else
            {
            die "Can't connect to SMTP Server $mx: $@";
            }
         }

      IO::Socket::Timeout->enable_timeouts_on($smtp);
      $smtp->read_timeout( $self->timeout );
      $smtp->write_timeout( $self->timeout );


      # Step 2: die, when no STARTTLS supported
      die "SMTP-Server $mx does not support STARTTLS\n" unless defined $smtp->supports("STARTTLS");

      # Step 3: do STARTTLS; when error code 421/450: wait and retry
      unless ( $smtp->command("STARTTLS")->response() == CMD_OK )
         {
         if ( $smtp->code == 421 or $smtp->code == 450 )
            {
            $smtp->quit;
            $state = "SMTP STARTTLS";
            next;
            }
         else
            {
            die "SMTP STARTTLS failed: " . $smtp->code . " " . $smtp->message . "\n";
            }
         }

      # All fine? exit retry loop
      last;

      } ## end for my $retry ( 0 .. $self...)


   # die "NIX DA im smtp" unless defined $smtp;
      
   binmode($smtp);

   return $smtp;
   } ## end sub _build_socket

sub _wait
   {
   my $self    = shift;
   my $retry   = shift // 1;
   my $message = shift // __PACKAGE__;

   warn "$message: Wait for retry, $retry: " . $self->throttle_time . " Seconds";

   sleep $retry * $self->throttle_time;
   return $self;
   }

=head2 send, recv

We have to override send and recv, because we use Net::SMTP instead ob IO::Socket object.

=cut

sub send
   {
   my $self = shift;
   my $data   = shift;

   return $self->socket->rawdatasend($data);
   }

sub recv
   {
   my $self   = shift;
   
   my $ret = $self->socket->recv($ARG[0], $ARG[1], $ARG[2]);
   
   return $ret;
   }


1;
