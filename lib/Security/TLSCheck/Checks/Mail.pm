package Security::TLSCheck::Checks::Mail;

use 5.010;

use Carp;
use English qw( -no_match_vars );
use Net::SMTP 3.02;

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';
with 'Security::TLSCheck::Checks::Helper::MX';

use Log::Log4perl::EasyCatch;



=head1 NAME

Security::TLSCheck::Checks::Mail - Checks mailservers for TLS capability

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 658 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION





=cut

#<<<

{
my $key_figures = 
   [
   { name => "#MX unique",            type => "int", source => "count_mx_unique",        description => "Number of unique MX Servers", }, 
   { name => "#MX active",            type => "int", source => "count_mx_active",        description => "Number of connectable servers", }, 
   { name => "#MX Supports STARTTLS", type => "int", source => "count_support_starttls", description => "Number of servers supporting STARTTLS", },
   { name => "#MX STARTTLS OK",       type => "int", source => "count_starttls_ok",      description => "Number of servers with successful STARTTLS", },  
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "Mail checks" );

has mx_unique           => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_mx_unique        => 'count', add_mx_unique            => 'push', all_unique            => 'elements', }, default => sub {[]}, );
has mx_active           => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_mx_active        => 'count', add_mx_active            => 'push', all_active            => 'elements', }, default => sub {[]}, );
has mx_support_starttls => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_support_starttls => 'count', add_mx_supports_starttls => 'push', all_supports_starttls => 'elements', }, default => sub {[]}, );
has mx_starttls_ok      => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_starttls_ok      => 'count', add_mx_starttls_ok       => 'push', all_starttls_ok       => 'elements', }, default => sub {[]}, );

# For Internal use, for forwarding it to CipherStrength check
# has mx_for_cipher       => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_for_cipher       => 'count', add_mx_for_cipher        => 'push', all_for_cipher        => 'elements', }, default => sub {[]}, );

#>>>



=head1 METHODS

=head2 run_checks
Run all the checks and store the results internally

=cut

sub run_check
   {
   my $self = shift;

   TRACE "Checking Mailservers for " . $self->domain;

   my @mx = $self->other_check("Security::TLSCheck::Checks::DNS")->all_mx;

   foreach my $mx (@mx)
      {
      TRACE "Check MX $mx";
      next if $self->mx_is_checked($mx);

      $self->add_mx_unique($mx);

      my $smtp = Net::SMTP->new( Hello => $self->my_hostname, Host => $mx );
      if ($smtp)
         {
         TRACE "SMTP-Connect to MX $mx OK, SMTP-Banner: " . $smtp->banner;
         $self->add_mx_active($mx);
         eval {

            if ( defined $smtp->supports("STARTTLS") )
               {
               TRACE "MX $mx supports STARTTLS";
               $self->add_mx_supports_starttls($mx);

               # $self->add_mx_for_cipher($mx);

               #               if ( $smtp->starttls(SSL_verifycn_scheme => 'http', ) )
               if ( $smtp->starttls )
                  {
                  TRACE "MX $mx works with STARTTLS";
                  $self->add_mx_starttls_ok($mx);
                  }
               else
                  {
                  TRACE "MX $mx: FAILED STARTTLS: $IO::Socket::SSL::SSL_ERROR";
                  }
               }
            else
               {
               TRACE "MX $mx does NOT support STARTTLS";
               }


            $smtp->quit;
            return 1;
         } or ERROR "Unexpected SMTP Error (MX: $mx): $EVAL_ERROR";

         } ## end if ($smtp)
      else
         {
         DEBUG "SMTP-Connect to MX $mx failed: $EVAL_ERROR";    # Net::SMTP sets EVAL_ERROR!
         }

      } ## end foreach my $mx (@mx)

   return $self->result;
   } ## end sub run_check



__PACKAGE__->meta->make_immutable;

1;

