package Log::Log4perl::EasyCatch;

=head1 NAME

Log::Log4perl::EasyCatch - Easy Logging with Log4perl, catching errors and warnings, using configfile

=cut


use strict;
use warnings;

use FindBin qw($Bin);
use English qw( -no_match_vars );
use Readonly;

use Log::Log4perl qw(:easy);

use base qw(Exporter);

Readonly our $LOG_TRESHOLD_VERBOSE => -3;
Readonly our $LOG_TRESHOLD_SILENT  => 3;



## it's here OK to export them all.
## no critic (Modules::ProhibitAutomaticExportation)
our @EXPORT = qw(
   TRACE DEBUG INFO WARN ERROR FATAL ALWAYS
   LOGCROAK LOGCLUCK LOGCARP LOGCONFESS
   LOGDIE LOGWARN
   LOGEXIT
   $DEFAULT_LOG_CONFIG
   $LOG_TRESHOLD_VERBOSE
   $LOG_TRESHOLD_SILENT
   );



#<<<
my $BASE_VERSION = "0.1"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 499 $ =~ /(\d+)/xg );
#>>>

=head1 VERSION

Version 0.1.x

=head1 SYNOPSIS

  use Log::Log4perl::EasyCatch;
  
  INFO "Startup!";
  
  ERROR "There is an error: $error" if $error;
  
  DEBUG "Internal state: $status";

  ...

=head1 DESCRIPTION

Everything from Log::Log4perl in easy mode, plus: Logging of warnings and Exceptions; default config file.


=head1 TODO:

Automatic logging of data structures via Data::Dumper!

Configure default log_dir via import.

Include a default log config and optionally write it?

=cut

my $initialised;

if ( not $initialised and not $COMPILING )
   {

   Readonly our $DEFAULT_LOG_CONFIG => $ENV{LOG_CONFIG} || "$Bin/../conf/logging.properties";

   # log dir should be created by appender!
   # -d "$Bin/../logs" or mkdir "$Bin/../logs" or die "Kann fehlendes logs-Verzeichnis nicht anlegen: $OS_ERROR\n";

   Log::Log4perl->init_once($DEFAULT_LOG_CONFIG);  # allows logging before reading config
   Log::Log4perl->appender_thresholds_adjust( $LOG_TRESHOLD_SILENT, ['SCREEN'] )
      if $ENV{HARNESS_ACTIVE};

   # catch and log all exceptions
   $SIG{__DIE__} = sub {                           ## no critic (Variables::RequireLocalizedPunctuationVars)
      my @messages = @_;
      chomp $messages[-1];

      if ($EXCEPTIONS_BEING_CAUGHT)
         {
         TRACE "Exception caught (executing eval): ", @messages;
         }
      elsif ( not defined $EXCEPTIONS_BEING_CAUGHT )
         {
         TRACE "Exception in Parsing module, eval, or main program: ", @messages;
         }
      else                                         # when $EXCEPTIONS_BEING_CAUGHT == 0
         {
         local $Log::Log4perl::caller_depth = $Log::Log4perl::caller_depth + 1;
         LOGDIE "Uncaught exception! ", @messages;
         }

      return;
   };

   # Log all warnings as errors in the log!
   $SIG{__WARN__} = sub {                          ## no critic (Variables::RequireLocalizedPunctuationVars)
      my @messages = @_;
      local $Log::Log4perl::caller_depth = $Log::Log4perl::caller_depth + 1;
      chomp $messages[-1];
      ERROR "Perl warning: ", @messages;
      return;
   };

   $initialised = 1;

   } ## end if ( not $initialised ...)



1;

