package Security::TLSCheck::App::DomainFilter;

use Moose::Role;

use Log::Log4perl::EasyCatch;

use English qw( -no_match_vars );
use FindBin qw($Bin);

use IO::All;

=head1 NAME

Security::TLSCheck::App::DomainFilter -- change wrong domain names into correct ones, if possible

=head1 VERSION

Version 0.2.x

=cut

#<<<
my $BASE_VERSION = "1.0"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 649 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8

  with "Security::TLSCheck::App::DomainFilter";
  
  ...
  
  my $filtered_domain = $self->filter_domain($domain) or next;
  


=head1 DESCRIPTION

Helps to change wrong domain names into correct ones, if possible

There are a lot of really strange inputs; see also tests (221-domain_filter.t) ...


=head2 filter_domain


=cut

my %map = (
   "replace-all"               => "everything-replaced.tld",
   "www.omaschmidts.masche.de" => "omaschmidtsmasche.de",
   "EGT Eppinger Gears"        => "eppinger-gears.com",
   "www.Autohaus.Ford/Nuding"  => "ford-nuding-remshalden.de",
   "http://www.medic-con.cde"  => "medic-con.de",

          );

my $DATADIR = eval { return File::ShareDir::module_dir(__PACKAGE__); } or DEBUG "Share-Dir-Eval-Error: $EVAL_ERROR";
$DATADIR = "$FindBin::Bin/../files/DomainFilter" if not defined $DATADIR;    # or not -d $DATADIR;

# Source: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
my %valid_tlds = map { lc($ARG) => 1 } grep { not m{ ^ \s* [#] }x } io("$DATADIR/tlds-alpha-by-domain.txt")->chomp->slurp;
my $tlds_regex_or = join( q(|), keys %valid_tlds );
my $FORBIDDEN_DOMAINS = qr{ (t[-\s]?online|arcor|web|gmx|hotmail|yahoo) }x;


sub filter_domain
   {
   my $self = shift;
   my $in   = shift;

   if ( $map{$in} )
      {
      TRACE "Direct mapping $in to $map{$in}";
      return $map{$in};
      }

   my $domain = lc($in);

   $domain =~ s{,}{.}gx;

   return if $domain =~ m{ ( ^ | [.@] ) $FORBIDDEN_DOMAINS [.] (de|com) }ox;

   $domain =~ s{^www\s}{}x;                        # "www test.de"
   $domain =~ s{[-\s:]($tlds_regex_or)$}{.$1}ox;   # "test de" "test:de", "test-de", com, (all TLDs)
   if ( $domain =~ m{\s}x and $domain !~ m{[.]}x )
      {
      WARN "Domain with space and no dot: $in";
      return;
      }

   $domain =~ s{\\}{/}gx;                          # Some Windows users use Backslashes ... ;)
   $domain =~ s{.*\@}{}gx;                         # remove everything before a @
   $domain =~ s{^/+}{}gx;                          # remove leading /

   $domain =~ s{[.]+}{.}gx;                        # remove too much .
   $domain =~ s{^http:/?/?www./}{}x;               # Remove http ...
   $domain =~ s{ ^( hk?t{1,3}[opt]p?s?[.:]? //? :? )+ }{}x
      ;                                            # remove http:// and http:/ and http//: and more then one of them, and one, two or three t ...
   $domain =~ s{^htt?pp?s?:}{}x;                   # http: without //
   $domain =~ s{^https?:/?/?}{}x;                  # still some http
   $domain =~ s{^www?[.]}{}x if $domain =~ m{[.].*?[.]}x;    # Remove beginning www when there are at least 2 dots
   $domain =~ s{\s}{}gx;                           # remove spaces
   $domain =~ s{[/;].*}{}gx;                       # remove everything after a / or ;
   $domain =~ s{:\d+}{}gx;                         # Remove port numbers
   $domain =~ s{[.]$}{}x;                          # Remove trailing .

   $domain =~ s{(ourworld[.]compuserve[.]com)[.]homepages}{$1}gx;

   $domain =~ s{ [.] ([de]|dee|deu) $}{.de}x;      # .de typos

   # at some domains, the last dot before de or com got lost; but not for all TLDs! ...
   if ( $domain !~ m{[.]}x )
      {

      unless ( $domain =~ s{(de|com)$}{.$1}x )     # replace "blablacom" => "blabla.com" etc.
         {
         WARN "No . in domain";
         return;
         }
      }

   my ($tld) = $domain =~ m{ ([^.]+) $ }x;

   unless ( $valid_tlds{$tld} )
      {
      unless ( $domain =~ s{(de|com)$}{.$1}x )     # replace "blablacom" => "blabla.com" etc.
         {
         if ( $domain =~ s{^www[.]}{}x )           #if www.somedomain without TLD, add .de
            {
            $domain .= ".de";
            TRACE "Added a fix .de for domain without TLD";
            }
         else
            {
            WARN "Invalid TLD $tld for domain $domain (in: $in)";
            return;
            }
         }
      $domain =~ s{^www[.]}{}x;
      }


   TRACE "IN: $in; OUT: $domain";

   return $domain;

   } ## end sub filter_domain


1;
