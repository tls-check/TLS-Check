package Security::TLSCheck::Checks::CipherStrengthOnlyValidCerts;


use Moose;
extends 'Security::TLSCheck::Checks::CipherStrength';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;

=head1 NAME

Security::TLSCheck::Checks::CipherStrengthOnlyValidCerts - Check Strength of CipherSuites and SSL/TLS Version, but only for domains with valid certficates

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 640 $ =~ /(\d+)/xg;


has '+description' => ( default => "Strength of CipherSuites and SSL/TLS Version, but only for valid and verified certificates" );


=head1 SYNOPSIS

The same as Security::TLSCheck::Checks::CipherStrength


=head1 DESCRIPTION

Returns the values of Security::TLSCheck::Checks::CipherStrength, but only if HTTPS Certificate is OK and matches the domain.


=cut


=head1 METHODS

=head2 run_check

Retuns the result from Security::TLSCheck::Checks::CipherStrength, when Certificate is verified etc.



=cut

sub run_check
   {
   my $self = shift;

   return $self->other_check("Security::TLSCheck::Checks::CipherStrength-result")
      if $self->other_check("Security::TLSCheck::Checks::Web")->https_all_verified;

   my $www = $self->www;
   DEBUG "Skipped CipherStrengthOnlyValidCerts tests for $www because no valid certificate";
   return;


   }

__PACKAGE__->meta->make_immutable;

1;
