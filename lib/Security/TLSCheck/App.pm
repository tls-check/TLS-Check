package Security::TLSCheck::App;

use Moose;
use 5.010;


=head1 NAME

Security::TLSCheck::App -- CLI part of TLS check application

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

For a project overview, see the README.md of the Distribution.


=cut

use English qw( -no_match_vars );
use FindBin qw($Bin);
use Data::Dumper;
use Module::Loaded;
use File::HomeDir;
use Text::CSV_XS;
use File::ShareDir;

# use IO::All -utf8;
use IO::All;                                       # -utf8;



use Security::TLSCheck;
use Log::Log4perl::EasyCatch;



=head2 import

Has a simple import method for importing "extends => 'My::BAse::Class'"

=cut

sub import
   {
   my $class  = shift;
   my %params = @ARG;

   if   ( $params{extends} ) { with $params{extends}; }
   else                      { with "Security::TLSCheck::Result"; }

   # TODO: call make_immutable but where?
   # here looks ok
   # But there is an error with t/00-load.t, so don't immutable if Test::More loaded
   __PACKAGE__->meta->make_immutable unless is_loaded("Test::More");

   return;
   }

=begin temp

was kann denn konfigurierbar sein?

Logging-Config
checks
eingabe-file
ausgabe-file
flags

=end temp

=cut

my @default_checks
   = qw(DNS Web Mail Dummy CipherStrength MailCipherStrength AgeDE Heartbleed CipherStrengthOnlyValidCerts FinalScore);



# Attributes and default values.
#<<< 
has configfile        => (is => "ro", isa => "Str",           default => $Security::TLSCheck::CONFIG_FILE,                                 documentation => "Configuration file");
has log_config        => (is => "ro", isa => "Str",           default => $DEFAULT_LOG_CONFIG,                          documentation => "Alternative logging config" );
has checks            => (is => "rw", isa => "ArrayRef[Str]", default => sub { \@default_checks },    auto_deref => 1, documentation => "List of checks to run" );
has user_agent_name   => (is => "ro", isa => "Str",           default => "TLS-Check/$VERSION",                         documentation => "UserAgent string for web checks" ) ;
has my_hostname       => (is => "ro", isa => "Str",           lazy_build => 1,                                         documentation => "Hostname for SMTP EHLO etc." ); 
has timeout           => (is => "ro", isa => "Int",           default => 60,                                           documentation => "Timeout for networking" );
has separator         => (is => "ro", isa => "Str",           default => q{;},                                         documentation => "CSV Separator char(s)" );
has files             => (is => "ro", isa => "ArrayRef[Str]", lazy_build => 1,                        auto_deref => 1, documentation => "List of files with domain names to check" );
has verbose           => (is => "ro", isa => "Bool",          default => 0,                                            documentation => "Verbose Output/Logging" );
has temp_out_interval => (is => "ro", isa => "Int",           default => 250,                                          documentation => "Produce temporary output every # Domains");

#>>>

with 'MooseX::SimpleConfig';
with 'MooseX::Getopt';
with 'MooseX::ListAttributes';

sub _build_files
   {
   my $self = shift;

   my @files = @{ $self->extra_argv };

   @files = qw(-) unless @files;

   return \@files;
   }

sub _build_my_hostname
   {
   my $self = shift;
   return "tls-check.stuttgart.ihk.de"
      if $ENV{HOST} // "" eq "tls-check";          # TODO: Change this hack to other defaults ...
   return "tls-check.test";
   }


=head1 METHODS


=head2 BUILD

Initializing stuff

=cut

sub BUILD
   {
   my $self = shift;

   # Re-Init loggig, if there is an alternative log config
   if ( $self->log_config ne $DEFAULT_LOG_CONFIG )
      {
      Log::Log4perl->init( $self->log_config );
      DEBUG "Logging initialised with non-default config " . $self->log_config;
      }
   else
      {
      DEBUG "Logging initialised with default config: $DEFAULT_LOG_CONFIG.";
      }

   # split check names
   my @checks = map { split( m{ [:\s] }x, $ARG ); } $self->checks;
   $self->checks( \@checks );

   #
   # Pre-Load all Check Modules
   #

   foreach my $check_name ( $self->checks )
      {
      $check_name =~ s{ [^\w\d:] }{}gx;            # remove all not allowed chars for eval!
      TRACE "Load Module Security::TLSCheck::Checks::$check_name";
      eval "require Security::TLSCheck::Checks::$check_name;"    ## no critic (BuiltinFunctions::ProhibitStringyEval)
         or die "Can't use check $check_name: $EVAL_ERROR\n";
      }

   return $self;
   } ## end sub BUILD

=head2 run

Runs the application ...

=cut

my %domains_analysed;

sub run
   {
   my $self = shift;

   my $starttime = time;

   return $self->list_attributes if $self->show_options;

   Log::Log4perl->appender_thresholds_adjust( $LOG_TRESHOLD_VERBOSE, ['SCREEN'] )
      if $self->verbose;

   my $csv = Text::CSV_XS->new( { binary => 1, sep_char => $self->separator, } );
   my $counter = 0;

   $self->init_domain_loop;

   foreach my $file ( $self->files )
      {
      INFO "Read domain names from STDIN" if $file eq q{-};
      my $io = io $file;
      while ( my $row = $csv->getline($io) )
         {
         my ( $read_domain, $category ) = @$row;
         next unless $read_domain;
         next if $read_domain =~ m{^[#]}x;
         next if $read_domain eq "INTERNET_NR";    # skip header line

         $category //= "<no category>";

         DEBUG "Next Domain: $read_domain in category $category";

         my $domain = $self->filter_domain($read_domain);

         unless ($domain)
            {
            INFO "Skipping $read_domain (#$counter), because filtered.";
            next;
            }

         if ( $domains_analysed{$domain} )
            {
            INFO "Skipping $domain (via $read_domain) (category $category), because already analysed.";
            next;
            }

         $domains_analysed{$domain} = 1;
         $counter++;

         eval {
            $self->analyse( $domain, $category, $read_domain, $counter );
            return 1;
         } or WARN "Error with domain $domain: $EVAL_ERROR";

         if ( $self->temp_out_interval and ( $counter % $self->temp_out_interval ) == 0 )
            {
            INFO "New Temp output!";
            $self->output;
            }

         } ## end while ( my $row = $csv->getline...)
      } ## end foreach my $file ( $self->files...)

   DEBUG "All domains finished.";

   $self->finish_domain_loop;

   $self->output;

   INFO "Final message: Everything finished. THE END.";

   my $endtime  = time;
   my $duration = $endtime - $starttime;
   my $minutes  = int( $duration / 60 );           ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
   my $rest_sec = sprintf( "%02d", $duration % 60 );    ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
   my $hours    = int( $minutes / 60 );            ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
   my $rest_min = sprintf( "%02d", $minutes % 60 );     ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)

   INFO localtime . " Total Runtime: $duration seconds -- $hours:$rest_min:$rest_sec hours";

   return;
   } ## end sub run


=head2 filter_domain

Filters the domain name; here in the base class: only lower case.


=cut

#sub filter_domain
#   {
#   my $self   = shift;
#   my $domain = shift;
#
#   return lc($domain);
#   }

# Filter/modify bogus domains
# Maybe this can be configured via parameter ...
with 'Security::TLSCheck::App::DomainFilter';


=head2 analyse($domain, $category)

Runs all checks for one domain.

Here single-treaded, override this for parallel processing.

=cut

sub analyse
   {
   my $self        = shift;
   my $domain      = shift;
   my $category    = shift;
   my $read_domain = shift;
   my $counter     = shift;

   INFO "Start analyse $domain (via $read_domain, category $category) (domain # $counter)";
   my $tc = Security::TLSCheck->new(
                                     domain   => $domain,
                                     category => $category,
                                     app      => $self
                                   );
   $self->add_result_for_category( $category => scalar $tc->run_all_checks );
   INFO "DONE analyse $domain (category $category) (domain # $counter)";

   return;
   }

=head2 init_domain_loop, finish_domain_loop

empty init and finish subs for the domain loop; for overridung ...

=cut

sub init_domain_loop   { return; }
sub finish_domain_loop { return; }


1;                                                 # End of TLS::Check
