package Security::TLSCheck::Checks::Heartbleed;

use 5.010;
use strict;
use warnings;

use Carp;
use English qw( -no_match_vars );
use FindBin qw($Bin);
use Readonly;

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';
with 'Security::TLSCheck::Checks::Helper::MX';

use Log::Log4perl::EasyCatch;



=head1 NAME

Security::TLSCheck::Checks::Heartbleed - Heartbleed checks

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 657 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION


At the moment this calls Steffen Ullrichs check-ssl-heartbleed.pl

Later some parts of this should be integratet into this module


=cut

#<<<

{
my $key_figures = 
   [
   { name => "HTTPS supported",             type => "flag",  source => "https_supported",      description => "Is HTTPS supported?", }, 
   { name => "HTTPS Heartbleed vulnerable", type => "flag",  source => "https_vulnerable",     description => "Is HTTPS vulnerable for Heartbleed?", }, 
   { name => "HTTPS Other Error",           type => "flag",  source => "https_other_error",    description => "Other Error in Heartbleed check?", }, 
   { name => "# MX total",                  type => "count", source => "count_mx",             description => "Number of all MX server" }, 
   { name => "# MX with TLS",               type => "count", source => "count_mx_tls",         description => "Number of all MX supporting STARTTLS" }, 
   { name => "# MX Heartbleed vulnerable",  type => "count", source => "count_mx_vulnerable",  description => "Number of MX server, which are vulnerable for Heartbleed", }, 
   { name => "# MX Heartbleed Other Error", type => "count", source => "count_mx_other_error", description => "Number of MX server, which had other errors while checking Heartbleed", }, 
   
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

#>>>


has '+description' => ( default => "Checks for the Heartbleed vulnerability" );

has https_supported      => ( is => "rw", isa => "Bool", );
has https_vulnerable     => ( is => "rw", isa => "Bool", );
has https_other_error    => ( is => "rw", isa => "Bool", );
has count_mx             => ( is => "rw", isa => "Int", );
has count_mx_tls         => ( is => "rw", isa => "Int", );
has count_mx_vulnerable  => ( is => "rw", isa => "Int", );
has count_mx_other_error => ( is => "rw", isa => "Int", );

Readonly my $RC_OK         => 0;
Readonly my $RC_VULNERABLE => 256;



=head1 METHODS

=head2 run_check

Do all the work for heartbleed.
This method stores the result in attributes. 

For web: currently only test with www.

=cut

sub run_check
   {
   my $self = shift;

   $self->_check_www;
   $self->_check_mail;

   return $self->result;
   }


sub _check_www
   {
   my $self = shift;

   my $www = $self->www;

   # check web only if there is some HTTPS
   unless ( $self->other_check("Security::TLSCheck::Checks::Web")->https_active )
      {
      DEBUG "Skipped WWW Heartbleed for $www because no https active";
      return;
      }

   my ( $result_ref, $rc ) = $self->_check_heartbleed($www);

   if ( $rc == $RC_OK )
      {
      #TRACE "Webserver $www is OK";
      $self->https_supported(1);
      $self->https_vulnerable(0);
      $self->https_other_error(0);
      }
   elsif ( $rc == $RC_VULNERABLE )
      {
      # Not allowed for privacy reasons!
      # TRACE "UUPS! Webserver $www is VULNERABLE!!!";
      $self->https_supported(1);
      $self->https_vulnerable(1);
      $self->https_other_error(0);
      }
   elsif ( $result_ref->[-1] =~ m{^failed.to.connect:}msx )
      {
      DEBUG "No Connection to Webserver $www: $result_ref->[-1]";
      $self->https_supported(0);
      $self->https_vulnerable(0);
      $self->https_other_error(0);
      }
   else
      {
      DEBUG "Webserver $www has other Error: $result_ref->[-1]";
      $self->https_supported(1);
      $self->https_vulnerable(0);
      $self->https_other_error(1);
      }

   return;

   } ## end sub _check_www

# MX Checks
sub _check_mail
   {
   my $self                 = shift;
   my $count_mx             = 0;
   my $count_mx_tls         = 0;
   my $count_mx_vulnerable  = 0;
   my $count_mx_other_error = 0;

   foreach my $mx ( $self->get_mx )
      {
      next if $self->mx_is_checked($mx);

      $count_mx++;

      my ( $result_ref, $rc ) = $self->_check_heartbleed( $mx, "smtp" );

      if ( $rc == $RC_OK )
         {
         #DEBUG "MX $mx is OK";
         $count_mx_tls++;
         }
      elsif ( $rc == $RC_VULNERABLE )
         {
         # Not allowed for privacy reasons!
         #DEBUG "UUPS! MX $mx is VULNERABLE!!!";
         $count_mx_tls++;
         $count_mx_vulnerable++;
         }
      elsif ( $result_ref->[-1] =~ m{^failed.to.connect:}msx )
         {
         DEBUG "No Connection to MX $mx: $result_ref->[-1]";
         }
      else
         {
         DEBUG "MX $mx has other Error: $result_ref->[-1]";
         $count_mx_tls++;
         $count_mx_other_error++;
         }

      } ## end foreach my $mx ( $self->get_mx...)

   $self->count_mx($count_mx);
   $self->count_mx_tls($count_mx_tls);
   $self->count_mx_vulnerable($count_mx_vulnerable);
   $self->count_mx_other_error($count_mx_other_error);

   return;

   } ## end sub _check_mail


# TODO: don't call external program, include the code here => much faster!
sub _check_heartbleed
   {
   my $self     = shift;
   my $host     = shift;
   my $tls_type = shift;

   my $cli_params;

   if   ($tls_type) { $cli_params = "--starttls $tls_type $host"; }
   else             { $cli_params = "$host:https"; }
   
   my $EXTBIN_DIR = eval { return File::ShareDir::module_dir("Security::TLSCheck") } // "$Bin/ext";
   
   die "check-ssl-heartbleed.pl not found" unless -x "$EXTBIN_DIR/check-ssl-heartbleed.pl";

   DEBUG "Run heartbleed-Check with '$cli_params'";
   my @result = qx($EXTBIN_DIR/check-ssl-heartbleed.pl $cli_params 2>&1);    ## no critic (InputOutput::ProhibitBacktickOperators)
   my $rc     = $CHILD_ERROR;
   chomp @result;
   DEBUG "Heartbleed check finished";

   # Not allowed in production:
   #TRACE "Heartbleed-Response: $ARG" foreach @result;
   #TRACE "Return Code: $rc";

   return \@result, $rc;
   } ## end sub _check_heartbleed


__PACKAGE__->meta->make_immutable;

1;
