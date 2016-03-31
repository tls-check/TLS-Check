package Security::TLSCheck::Checks::Helper::MX;

use Moose::Role;

use English qw( -no_match_vars );

use Time::HiRes qw(time);
use Net::DNS ();
use File::Temp qw(tempdir);
use IO::All;
use Carp;

use Log::Log4perl::EasyCatch;

=head1 NAME

Security::TLSCheck::Checks::Helper::MX - Get all MX, cache if already checked, ...

=encoding utf8

=cut

use version; our $VERSION = qv( "v0.2." . ( sprintf "%d", q$Revision: 527 $ =~ /(\d+)/xg ) );


=head1 SYNOPSIS

In a check:

 with 'Security::TLSCheck::Helper::GetMX';

 # ...
 
 my @mx = $self->get_mx;


=head1 DESCRIPTION

Adds a method for getting mx records -- including caching.


=cut

my %mx_cache;


has _resolver => ( is => 'ro', isa => 'Object', lazy_build => 1, );

sub _build__resolver
   {
   my $self = shift;

   return Net::DNS::Resolver->new;
   }


=head2 get_mx

returns the list of MX records for this Domain

=cut

sub get_mx
   {
   my $self   = shift;
   my $domain = $self->domain;

   if ( $mx_cache{$domain} )
      {
      DEBUG "Found cached values for MX of $domain";
      return @{ $mx_cache{$domain} };
      }

   DEBUG "Start DNS Query for MX for $domain";
   my $reply = $self->_resolver->query( $domain, "MX" );
   DEBUG "DNS MX Query for $domain finished";

   unless ($reply)
      {
      DEBUG "No MX found for $domain";
      return;
      }

   my @mx = map { $ARG->exchange }
      sort { $a->preference <=> $b->preference }
      grep { $ARG->type eq 'MX' } $reply->answer;

   DEBUG "found MX for $domain: @mx";

   $mx_cache{$domain} = \@mx;

   return @mx;
   } ## end sub get_mx



=head2 mx_is_checked

Cache temporary, if MX is already analysed for this check (each check has his own cache)

cache on disk, so this also works with multiprocessing

=cut

my $TEMPDIR = tempdir( CLEANUP => 1 );

sub mx_is_checked
   {
   my $self = shift;
   my $mx = shift || croak "No MX given!\n";

   # Build Filename: "mx.domain.tld__CheckName_DomainCategory"
   $mx .= "__" . $self->name . "_" . $self->category;

   DEBUG "Test, if MX $mx is already checked";

   my $lock = io("$TEMPDIR/$mx.lock")->lock;
   $lock->println( "locked " . localtime() );

   my $is_checked = eval { my $content < io("$TEMPDIR/$mx"); return $content; };

   if ($is_checked)
      {
      chomp $is_checked;
      DEBUG "MX $mx is checked: '$is_checked'";
      return 1;
      }

   DEBUG "MX $mx is not yet checked.";
   "Checked $mx at " . localtime() > io("$TEMPDIR/$mx");

   return 0;
   } ## end sub mx_is_checked


1;

