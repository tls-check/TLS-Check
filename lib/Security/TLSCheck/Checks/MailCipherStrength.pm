package Security::TLSCheck::Checks::MailCipherStrength;

use Moose;
extends 'Security::TLSCheck::Checks::CipherStrength';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;

use Net::SSL::GetServerProperties;
use Net::SSL::Handshake::StartTLS::SMTP;


=head1 NAME

Security::TLSCheck::Checks::MailCipherStrength - Checks mailservers for supported CipherSuites 

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 640 $ =~ /(\d+)/xg;

has '+description' => ( default => "Strength of CipherSuites and SSL/TLS Version of Mailservers (MX)" );


=head1 SYNOPSIS

...


=head1 DESCRIPTION

Gets list of MX to check from Mail check.

Inherits all values from CipherStrength (Web).



=cut

=head2 run_check

As always: runs the check ...

But this one maybe return more then one result: one for each MX!

=cut

sub run_check
   {
   my $self = shift;

   TRACE "Checking Cipher Strength of Mailservers for " . $self->domain;

   my @mx = $self->other_check("Security::TLSCheck::Checks::Mail")->all_supports_starttls;

   TRACE "Have MX: @mx";

   my @result;

   foreach my $mx (@mx)
      {
      TRACE "Get SSL/TLS properties for MX $mx";

      my $prop = Net::SSL::GetServerProperties->new(
                                                     host            => $mx,
                                                     port            => 25,
                                                     handshake_class => "Net::SSL::Handshake::StartTLS::SMTP",
                                                     throttle_time   => 2,
                                                     timeout         => $self->timeout,
                                                   );

      $self->properties( $prop->get_properties );

      push @result, $self->result;

      TRACE "Finished properties for MX $mx";

      }


   return @result;

   } ## end sub run_check



1;

