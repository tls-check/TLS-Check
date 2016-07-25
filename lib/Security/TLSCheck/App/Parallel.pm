package Security::TLSCheck::App::Parallel;

use Moose;
use 5.010;

=head1 NAME

Security::TLSCheck::App::Parallel -- run everything in parallel

=head1 VERSION

Version 0.2.x

=cut

#<<<
my $BASE_VERSION = "1.0"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 658 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8

  use Security::TLSCheck::App (extends => 'Security::TLSCheck::Result');
  
  my $app = Security::TLSCheck::App->new_with_options();
  $app->run;



=head1 DESCRIPTION


=cut

BEGIN { extends "Security::TLSCheck::App"; }

use English qw( -no_match_vars );
use FindBin qw($Bin);

use Log::Log4perl::EasyCatch;
use Security::TLSCheck;

use Parallel::ForkManager;
use Storable;                                      # => used internally by PFM; => use Sereal instead?

use Time::HiRes qw(time);
use Readonly;

Readonly my $HARD_TIMEOUT => 1200;                 # stop after 20 minutes ...


# Attributes and default values.
has jobs => ( is => "ro", isa => "Int", default => 20, documentation => "Number of max. parallel worker jobs" );


=head2 init_domain_loop

initialises ForkManager...

=cut

my $pm;

sub init_domain_loop
   {
   my $self = shift;

   die "ForkManager can only be initialised ONCE!\n" if $pm;

   $pm = Parallel::ForkManager->new( $self->jobs );

   $pm->run_on_finish(
      sub {
         my ( $pid, $exit_code, $domain, $exit_signal, $core_dump, $return ) = @ARG;

         if ($core_dump)
            {
            ERROR "Child for $domain (pid: $pid) core dumped. Exit-Code: $exit_code; Exit-Signal: $exit_signal";
            return;
            }

         if ($exit_code)
            {
            ERROR "Child for $domain (pid: $pid) exited with Exit-Code: $exit_code; Exit-Signal: $exit_signal";
            return;
            }

         unless ($return)
            {
            ERROR "Child for $domain (pid: $pid) returned no data; Exit-Code: $exit_code; Exit-Signal: $exit_signal";
            return;
            }

         my ( $return_domain, $category, $result ) = @$return;

         if ( $return_domain ne $domain )
            {
            ERROR "Really strange error: Domain in return value ($return_domain) differs from ident ($domain)";
            return;
            }

         DEBUG "Master process got result for $domain";

         # Replace copy of info-element with a reference to the original
         # saves a lot of memory when running with thousands of domains
         foreach my $check (@$result)
            {
            my $class = $check->{check}{class};
            foreach my $single_result ( @{ $check->{result} } )
               {
               my $pos = $single_result->{info}{pos};
               $single_result->{info} = $class->new( instance => $self )->key_figures->[$pos];
               }
            }

         $self->add_result_for_category( $category => $result );

      }
   );


   return;
   } ## end sub init_domain_loop



=head2 analyse($domain, $category)

Runs all checks for one domain in background!

=cut

sub analyse
   {
   my $self        = shift;
   my $domain      = shift;
   my $category    = shift;
   my $read_domain = shift;
   my $counter     = shift;

   DEBUG "Schedule $domain in fork pool";

   no warnings qw(once);                           ## no critic (TestingAndDebugging::ProhibitNoWarnings)
   local $Storable::Eval    = 1;                   ## no critic (Variables::ProhibitPackageVars)
   local $Storable::Deparse = 1;                   ## no critic (Variables::ProhibitPackageVars)

   # returns if in parent process, otherwise the code below continues in new process
   $pm->start($domain) and return;

   # here IN FORK!
   local $SIG{ALRM} = sub {
      ERROR "Fatal Error, should never happen: HARD TIMEOUT for $domain reached!";
      die "FATAL: HARD TIMEOUT for $domain reached!\n";
   };                                              # NB: \n required
   alarm $HARD_TIMEOUT;                            # Hard timeout ...

   my $starttime = time;
   INFO "Start analyse $domain (via $read_domain, category $category) (domain # $counter)";
   my $tc = Security::TLSCheck->new( domain => $domain, category => $category, app => $self );
   my $result = $tc->run_all_checks;

   my $runtime = sprintf( "%.3f", time - $starttime );
   INFO "DONE analyse $domain (category $category) (domain # $counter) in $runtime Seconds";

   $pm->finish( 0, [ $domain, $category, $result ] );

   alarm 0;

   return;
   } ## end sub analyse



=head2 finish_domain_loop

Finish ForkManager: wait for all children

=cut

sub finish_domain_loop
   {
   my $self = shift;

   DEBUG "Now waiting for the last jobs.";
   $pm->wait_all_children;
   undef $pm;
   DEBUG "All jobs finished.";

   return;
   }

1;                                                 # End of TLS::Check
