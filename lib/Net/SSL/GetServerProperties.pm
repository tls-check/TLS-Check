package Net::SSL::GetServerProperties;


use Moose;
use 5.010;

use English qw( -no_match_vars );

use Net::SSL::CipherSuites;
use Net::SSL::Handshake qw(:all);

use Log::Log4perl::EasyCatch;

use List::Util qw(any all max min);
use Carp qw(croak);
use Time::HiRes qw(sleep);

use Readonly;

=head1 NAME

 Net::SSL::GetServerProperties - get properties from SSL/TLS servers

=head1 VERSION

Version 0.8, $Revision: 640 $

=cut

#<<<
my $BASE_VERSION = "0.8"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 640 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8

   my $prop = Net::SSL::GetServerProperties->new( host => $host, );
   $prop->get_properties;
   
   say "Supported Cipher Suites at Host $host: " . $prop->accepted_ciphers->names;
   say "Supports SSLv2"   if $prop->supports_sslv2;
   say "Supports SSLv3"   if $prop->supports_sslv3;
   say "Supports TLSv1"   if $prop->supports_tlsv1;
   say "Supports TLSv1.1" if $prop->supports_tlsv11;
   say "Supports TLSv1.2" if $prop->supports_tlsv12;

   say "Supports at least one Bettercrypto A Cipher Suite"             if $prop->supports_any_bc_a;
   say "Supports at least one Bettercrypto B Cipher Suite"             if $prop->supports_any_bc_b;
   say "Supports at least one BSI TR-02102-2 Cipher Suite with PFS"    if $prop->supports_any_bsi_pfs;
   say "Supports at least one BSI TR-02102-2 Cipher Suite without PFS" if $prop->supports_any_bsi_nopfs;

   say "Supports only Bettercrypto A Cipher Suites"             if $prop->supports_any_bc_a;
   say "Supports only Bettercrypto B Cipher Suites"             if $prop->supports_any_bc_b;
   say "Supports only BSI TR-02102-2 Cipher Suites with PFS"    if $prop->supports_any_bsi_pfs;
   say "Supports only BSI TR-02102-2 Cipher Suites without PFS" if $prop->supports_any_bsi_nopfs;

   say "Supports weak Cipher Suites"                                    if $prop->supports_weak;
   say "Supports medium Cipher Suites"                                  if $prop->supports_medium;
   say "Supports no weak or medium Cipher Suites, only high or unknown" if $prop->supports_no_weakmedium;
   say "Supports ancient SSL Versions 2.0 or 3.0"                       if $prop->supports_ancient_ssl_versions;

   say "Cipher Suite used by Firefox:        " . $prop->firefox_cipher;
   say "Cipher Suite used by Safari:         " . $prop->safari_cipher;
   say "Cipher Suite used by Chrome:         " . $prop->chrome_cipher;
   say "Cipher Suite used by Win 7 (IE 8):   " . $prop->ie8win7_cipher;
   say "Cipher Suite used by Win 10 (IE 11): " . $prop->ie11win10_cipher;
   
   say "Supports only SSL/TLS versions recommended by BSI TR-02102-2"                            if $prop->supports_only_bsi_versions;
   say "Supports only SSL/TLS versions and cipher suites with PFS recommended by BSI TR-02102-2" if $prop->supports_only_bsi_versions_ciphers;
   say "Supports only TLS 1.2 "                                                                  if $prop->supports_only_tlsv12;
   
   # supports_sslv3_or_newer, supports_tlsv1_or_newer, supports_tlsv11_or_newer, supports_tlsv12_or_newer
   # supports_max_tls11, supports_max_tlsv1, supports_max_sslv3, supports_only_sslv2
   
   
   say "Ciphersuites used:";
   say "  * $_->{name}" foreach @{ $prop->accepted_ciphers }
   
   say "Overall Score for this Host: " . $prop->score;


   # or: use it with method delegation
   
   

=head1 DESCRIPTION

TODO: Description


=head2 Scores

see below

=cut



#<<<

has host                    => ( is => "ro", isa => "Str", );
has port                    => ( is => "ro", isa => "Int", default => 443, );
has handshake_class         => ( is => "ro", isa => "Str", default => "Net::SSL::Handshake", );
has throttle_time           => ( is => "ro", isa => "Num", default => 0.1, ); # default because some block to fast reconnect
has timeout                 => ( is => "ro", isa => "Int", default => 60, );

has declined_ciphers        => ( is => "rw", isa => "Net::SSL::CipherSuites",  );
has accepted_ciphers        => ( is => "ro", isa => "Net::SSL::CipherSuites", default => sub { Net::SSL::CipherSuites->new }, handles => { count_accepted_ciphers => "count" },  );
has ciphers_to_check        => ( is => "rw", isa => "Net::SSL::CipherSuites", default => sub { Net::SSL::CipherSuites->new_by_tag("sslv3_or_later")->order_by_code }, );
has very_weak_ciphers       => ( is => "rw", isa => "Net::SSL::CipherSuites",  );
has weak_ciphers            => ( is => "rw", isa => "Net::SSL::CipherSuites",  );
has medium_ciphers          => ( is => "rw", isa => "Net::SSL::CipherSuites",  );
# has good_ciphers            => ( is => "rw", isa => "Net::SSL::CipherSuites",  );

has supports_sslv2          => ( is => "rw", isa => "Bool", );
has supports_sslv3          => ( is => "rw", isa => "Bool", );
has supports_tlsv1          => ( is => "rw", isa => "Bool", );
has supports_tlsv11         => ( is => "rw", isa => "Bool", );
has supports_tlsv12         => ( is => "rw", isa => "Bool", );

has supports_any_bc_a       => ( is => "rw", isa => "Bool", );
has supports_any_bc_b       => ( is => "rw", isa => "Bool", );
has supports_any_bsi_pfs    => ( is => "rw", isa => "Bool", );
has supports_any_bsi_nopfs  => ( is => "rw", isa => "Bool", );

has supports_only_bc_a      => ( is => "rw", isa => "Bool", );
has supports_only_bc_b      => ( is => "rw", isa => "Bool", );
has supports_only_bsi_pfs   => ( is => "rw", isa => "Bool", );
has supports_only_bsi_nopfs => ( is => "rw", isa => "Bool", );

#has supports_weak           => ( is => "rw", isa => "Bool", );
#has supports_medium         => ( is => "rw", isa => "Bool", );
#has supports_no_weakmedium  => ( is => "rw", isa => "Bool", );

has supports_ec_keys        => ( is => "rw", isa => "Bool", );
has supports_only_ec_keys   => ( is => "rw", isa => "Bool", );
has supports_pfs            => ( is => "rw", isa => "Bool", );
has supports_only_pfs       => ( is => "rw", isa => "Bool", );

has firefox_cipher          => ( is => "rw", isa => "Str",); 
has safari_cipher           => ( is => "rw", isa => "Str",); 
has chrome_cipher           => ( is => "rw", isa => "Str",); 
has ie8win7_cipher          => ( is => "rw", isa => "Str",); 
has ie11win10_cipher        => ( is => "rw", isa => "Str",); 

has score                   => ( is => "rw", isa => "Int",  default => 0, );
has score_tlsversion        => ( is => "rw", isa => "Int",  default => 0, );
has score_ciphersuites      => ( is => "rw", isa => "Int",  default => 0, );
has named_score             => ( is => "rw", isa => "Str", );

# + supported_cipher_names

#>>>

# TODO: Documentation of all attributes!


=head2 ->get_properties

runs all tests, gets all properties.

=cut

# define some regexes for cipher suite checks
my $CHECK_PFS    = qr{ (?: (?:EC)? DHE | EDH ) }x;
my $CHECK_EC_KEY = qr{ ECDSA }x;


sub get_properties
   {
   my $self = shift;

   # the default of ciphers_to_check is: all Cipher-Suites from SSLv3 or above!
   $self->ciphers_to_check->unique;

   # First check, if there are supported cipher suites for
   # each SSL/TLS version in the remaining cipher suites
   # When not, then check if there is some in the already accepted ciphers
   # => if yes: there is support for this version.

   # in each run, ciphers_to_check is reduced by found/accepted cipher suites.

   eval {
      if ( $self->check_all_ciphers($TLSv12) ) { $self->supports_tlsv12(1); }
      return 1;
   } or DEBUG "TLSv12 check for ${ \$self->host }:${ \$self->port } : Error: $EVAL_ERROR";

   # Not listening? Finish! -- Reminder: ONLY ABORT WITH THIS ERROR!
   return $self if $EVAL_ERROR =~ m{Can't connect};

   eval {
      if   ( $self->check_all_ciphers($TLSv11) ) { $self->supports_tlsv11(1); }
      else                                       { $self->supports_tlsv11(1) if $self->check_supported_version($TLSv11); }
      return 1;
   } or DEBUG "TLSv11 check for ${ \$self->host }:${ \$self->port } : Error: $EVAL_ERROR";

   eval {
      if   ( $self->check_all_ciphers($TLSv1) ) { $self->supports_tlsv1(1); }
      else                                      { $self->supports_tlsv1(1) if $self->check_supported_version($TLSv1); }
      return 1;
   } or DEBUG "TLSv1 check for ${ \$self->host }:${ \$self->port } : Error: $EVAL_ERROR";

   eval {
      if   ( $self->check_all_ciphers($SSLv3) ) { $self->supports_sslv3(1); }
      else                                      { $self->supports_sslv3(1) if $self->check_supported_version($SSLv3); }
      return 1;
   } or DEBUG "SSLv3 check for ${ \$self->host }:${ \$self->port } : Error: $EVAL_ERROR";


   $self->declined_ciphers( $self->ciphers_to_check );
   $self->ciphers_to_check( Net::SSL::CipherSuites->new_by_tag("SSLv2") );

   eval {
      if ( $self->check_all_ciphers($SSLv2) ) { $self->supports_sslv2(1); }
   } or DEBUG "SSLv2 check for ${ \$self->host }:${ \$self->port } : Error: $EVAL_ERROR";

   $self->declined_ciphers->add( $self->ciphers_to_check );


   #
   # browser checks
   # eval for sslv2 server!
   #

   my $browser_version
      = $self->supports_tlsv12 ? $TLSv12
      : $self->supports_tlsv11 ? $TLSv11
      : $self->supports_tlsv1  ? $TLSv1
      : $self->supports_sslv3  ? $SSLv3
      : $self->supports_sslv2  ? $SSLv2
      :                          $TLSv1;           # If NO SSL/TLS Version supported (BUG!), then set it here to TLS1.0

   eval {
      my $ciphers = $self->check_ciphers_by_tag( $browser_version, "firefox" );
      $self->firefox_cipher( ( $ciphers->names )[0] ) if $ciphers;

      $ciphers = $self->check_ciphers_by_tag( $browser_version, "safari" );
      $self->safari_cipher( ( $ciphers->names )[0] ) if $ciphers;

      $ciphers = $self->check_ciphers_by_tag( $browser_version, "chrome" );
      $self->chrome_cipher( ( $ciphers->names )[0] ) if $ciphers;

      $ciphers = $self->check_ciphers_by_tag( $browser_version, "ie8_win7" );
      $self->ie8win7_cipher( ( $ciphers->names )[0] ) if $ciphers;

      $ciphers = $self->check_ciphers_by_tag( $browser_version, "ie11_win10" );
      $self->ie11win10_cipher( ( $ciphers->names )[0] ) if $ciphers;

      return 1;
   } or DEBUG "Browser checks failed: $EVAL_ERROR";


   # get very weak, weak and medium ciphers via OpenSSL- and O-Saft score
   # TODO: ALL Export should be already in the weak ones!
   # TODO: write a grep sub in Ciphersuites Module

   my @very_weak_ciphers = grep { $ARG->{name} =~ m{EXPORT|NULL} } @{ $self->accepted_ciphers->ciphers };

   # TODO!
   # "weak_ciphers" include o-saft score 11;
   # o-saft scores CBC cipher suites, which are knwon to be affected by the BEAST attack, with 11
   # so, a lot of CBC cipher-suites are rated as "weak"
   # This includes e.g. ECDHE_RSA_WITH_AES_256_CBC_SHA and ECDHE_RSA_WITH_AES_128_CBC_SHA
   # TODO: re-check if this rating is still OK
   # => see https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat
   # => maybe change this cipher suites from weak to medium
   
   my @weak_ciphers = grep {
      $ARG->{name} !~ m{EXPORT|NULL}
         and (    ( ( $ARG->{scores}{osaft_openssl} // "" ) =~ m{^ (?: weak | low )}ix )
               or ( ( $ARG->{scores}{osaft} // 100 ) < 40 ) )
   } @{ $self->accepted_ciphers->ciphers };

   my @medium_ciphers = grep {
            ( ( $ARG->{scores}{osaft_openssl} // "" ) =~ m{^medium}ix )
         or ( ( $ARG->{scores}{osaft} // 100 ) < 80 and ( $ARG->{scores}{osaft} // 100 ) >= 40 )
   } @{ $self->accepted_ciphers->ciphers };



   # TODO:
   # really make objects here? this may be
   $self->very_weak_ciphers( Net::SSL::CipherSuites->new( ciphers => \@very_weak_ciphers, ) );
   $self->weak_ciphers( Net::SSL::CipherSuites->new( ciphers => \@weak_ciphers, ) );
   $self->medium_ciphers( Net::SSL::CipherSuites->new( ciphers => \@medium_ciphers, ) );

   # Not allowed for privacy reasons!
   #   TRACE "INTERNALDEBUG: ${ \$self->host } supports very weak ciphers: " . $self->very_weak_ciphers->names
   #      if $self->very_weak_ciphers->count;
   #   TRACE "INTERNALDEBUG: ${ \$self->host } supports weak ciphers: " . $self->weak_ciphers->names
   #      if $self->weak_ciphers->count;
   #   TRACE "INTERNALDEBUG: ${ \$self->host } supports medium ciphers: " . $self->medium_ciphers->names
   #      if $self->medium_ciphers->count;

   # TODO: performance penalty is obvious ... ;-)
   #<<<
   $self->supports_ec_keys(1)      if any { $ARG =~ $CHECK_EC_KEY } $self->accepted_ciphers->names;
   $self->supports_only_ec_keys(1) if all { $ARG =~ $CHECK_EC_KEY } $self->accepted_ciphers->names;
   $self->supports_pfs(1)          if any { $ARG =~ $CHECK_PFS; } $self->accepted_ciphers->names;
   $self->supports_only_pfs(1)     if all { $ARG =~ $CHECK_PFS; } $self->accepted_ciphers->names;
   #>>>

   $self->_calculate_score;

   return $self;
   } ## end sub get_properties



=head2 ->_calculate_score

Internal method (but may be overridden or changed by method modifyer):
Calculates the server's score, based on the accepted cipher suites and 
SSL/TLS Versions

TODO: Description

=begin german_temp

Scoring:

Es sind verschiedene Möglichkeiten für die Berechnung des Scores 
denkbar. 

An dieser Stelle hier wird NICHT ausgewertet, ob ein SSL/TLS_Zertifikat 
gültig ist bzw. dem Aussteller von den gängigen Browsern vertraut wird, 
ob der Host übereinstimmt oder ob überhaupt Verschlüsselung angeboten 
wird. Auch Elemente wie Umleitung von oder nach HTTPS, Unterstützung 
für HSTS oder HPKP fließen hier nicht ein, ebensowenig wie die 
Anfälligkeit für Bugs wie Heartbleed.

In die Gesamtwertung kann dies alles aber sehr wohl einfließen: 
unterschiedlicher Score für den CipherStrength Check (der auf den
Werten von hier basiert) und für einen OverallScore Check, der 
Angaben auch aus allen anderen Checks (inkl. DNS, ...) mit aufnimmt.

Die hier beschriebene Berechnung bezieht sich ausschließlich auf die 
vom Server unterstützten Cipher-Suiten, SSL/TLS-Versionen sowie 
ähnliche Parameter der SSL/TLS-Verbindung. Daraus wird ein Score 
berechnet, der wiederum zur Bildung eines Durchschnitts über alle 
Domains herangezogen wird.

Es werden alle vom Schwestermodul Net::SSL::CipherSuites unterstützten 
CipherSuites getestet.

Die vorliegende Score-Berechnung orientiert sich an den Empfehlungen 
des BSI bzgl. Cipher-Suiten und SSL/TLS-Versionen und den Empfehlungen 
des Bettercrypto-Projekts bzgl. Cipher-Suiten. Würde nur streng nach den 
BSI-Empfehlungen aus TR-02102-2 berechnet, dann wäre das sehr einfach: 
5% der Server haben volle Punktzahl für die unterstützten Cipher-
Suiten, alle anderen null. Daher ist die Berechnung differenzierter.


Geplant -- aber nur teilweise implementiert -- ist, für jede bekannte 
Cipher-Suite einen eigenen Score zu berechnen, u.a. aufgrund der 
if(is)-Empfehlungen, der Einstufung von OpenSSL, des Scores von OWASP 
O-Saft, des Scores von sslaudit, des BSI-Scores, des Bettercrypto-Scores 
usw. Das Modul Net::SSL::CipherSuites hat einige dieser Scrores schon 
erfasst, aber noch nicht alle.

Das Schwestermodul Net::SSL::CipherSuites kennt derzeit 362 verschiedene 
Cipher Suites, mit Doppelungen 455 (doppelte Namen usw). Darunter sind 
alle 319 von der IANA standardisierten Cipher Suites, sowie alle 183 von 
OpenSSL in der speziellen ChaCha-Version unterstützten Cipher Suites. Eine 
Schwierigkeit besteht darin, für alle einen brauchbaren und überprüfbaren 
Score zu ermitteln -- beispielsweise auch für die ARIA oder ChaCha-Poly- 
Cipher Suiten. Für die meisten genutzten und auch von den Browsern 
angeboteten Cipher Suiten liegen allerdings Scrores vor. 


Das Scoring basiert derzeit vor allem auf der Auswertung, ob 
ausschließlich oder mindestens eine Cipher Suite aus der BSI TR-02102-2 
(mit Abwertung, wenn nicht PFS) sowie aus den Empfehlungen des 
Bettercrypto-Projekts (Liste A und B incl. A) vom Server unterstützt 
werden.

Abwertungen gibt es für alte oder veraltete SSL/TLS-Versionen oder wenn 
sehr Schwache Cipher-Suites unterstützt werden.


Der Score geht derzeit von 0 bis 100.


Im Detail:

 Score = 100, wenn ALLE unterstützten Cipher Suites BSI TR-02102-2 mit PFS entsprechen
       =  60, wenn mind. EINE BSI TR-02102-2 mit PFS unterstützt wird
       =  85, wenn ALLE unterstützten Cipher Suites BSI TR-02102-2 ohne PFS entsprechen
       =  50, wenn mind. EINE BSI TR-02102-2 ohne PFS unterstützt wird

 Score = 100, wenn ALLE unterstützten Cipher-Suiten in Bettercrypto A enthalten sind.
       =  60, wenn mind. EINE aus Bettercrypto A unterstützt wird
       =  80, wenn ALLE unterstützten Cipher-Suiten in Bettercrypto B (incl. A) enthalten sind.
       =  40, wenn mind. EINE aus Bettercrypto B unterstützt wird
       
Gibt es mehrere Treffer, gilt der höchste Wert.


Oder als Tabelle:

  max score of:

      Type of Cipher |           Scrore for    
                     | at least one  | all are in 
    -----------------+---------------+--------------
     bettercrypto A  |     60        |  100
     bettercrypto B  |     40        |   80
     BSI pfs         |     60        |  100
     BSI nopfs       |     50        |   85


Anschließend wird wie folgt abgewertet:

 -25, wenn mind. eine schwache Cipher Suite unterstützt wird (z.B. Export, RC4, NULL, ...)
 -10, wenn mind. eine medium Cipher Suite unterstützt wird 

 Score = 0, wenn SSLv2 unterstützt wird. 

 -35, wenn SSL 3 unterstützt wird
 -15, wenn TLS 1.0 unterstützt wird
  -5, wenn TLS 1.1 unterstützt wird
  -5, wenn KEIN TLS 1.2 unterstützt wird 
      (nur -5, weil ja eine der anderen Bedingungen erfüllt sein muss)

Wenn der Score nun unter 0 liegt, wird er auf 0 gesetzt.

Insgesamt ist es also relativ simpel; dennoch bildet sich unter dem Strich 
ein brauchbarer Durchschnittswert ab, weil dieser ja über viele Domains 
errechnet wird.


Weitere Möglichkeiten:

Es wird zwar ausgewertet, welche Cipher Suite mit verschiedenen Browsern 
(Firefox, Safari, Chrome, IE 8 / Win7, IE 11 / Win 10) zum Zug kommt, 
dies hat aber u.a. aufgrund der oben geschilderten Situation keine 
Auswirkung auf den Score.
Weitere Browser können problemlos integriert werden (evtl. noch altes 
Android, ...)

Es ist denkbar und wahrscheinlich auch sinnvoll, den Score damit 
entsprechend anzupassen. Sinnvollerweise vor dem Abzug für veraltete 
SSL/TLS-Versionen.
Aber wie stark? z.B. Durchschnittswert über 
alle Browser und dann davon den Mittelwert mit dem bis dahin ermittelten 
Score? Nur Ab- oder auch Aufwertung?
Am häufigsten werden gute Cipher-Suiten gewählt, man könnte dies natürlich 
auch anders (positiv) bewerten.

Es könnte auch noch der Durchschnittswert über alle unterstützten 
Cipher-Suiten in den Gesamt-Score einfließen.


Voraussetzung für beides ist allerdings saubere und verlässliche Scores 
für (möglichst) alle Cipher Suiten (siehe oben).


Auch weitere Elemente könnten einfließen: Welche Elliptischen Kurven 
werden unterstützt, Größe des Public Key, wird TLS_FALLBACK_SCSV 
unterstützt, DHE Große, usw.
Diese müssten aber noch extra getestet werden und sind bisher nicht 
Bestandteil der Tests.




TODO: Stufen:

Absolut gefährdet, 

  Sehr sicher
  Vertretbar
  Relativ unsicher
  Sehr unsicher



=end german_temp

=cut

sub _calculate_score
   {
   my $self = shift;

   # exit, when no cipher suites accepted
   unless ( $self->accepted_ciphers->count )
      {
      WARN "UPS, there are NO accepted cipher suites; can't calculate score.";
      return $self;
      }

   #
   # Bettercrypto and BSI flags
   #

   # TODO: make only one loop, this here has bad performance because multiple loops (any/all)
   #       but as long as under work in progress, it is probably better readable ...


   my $cipher_score = 0;
   if ( all { $ARG->{is}{bettercrypto_a} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_only_bc_a(1);
      $self->supports_any_bc_a(1);
      $cipher_score = 100;
      }
   elsif ( any { $ARG->{is}{bettercrypto_a} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_any_bc_a(1);
      $cipher_score = 60;
      }

   if ( all { $ARG->{is}{bettercrypto_b} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_only_bc_b(1);
      $self->supports_any_bc_b(1);
      $cipher_score = max( $cipher_score, 80 );
      }
   elsif ( any { $ARG->{is}{bettercrypto_b} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_any_bc_b(1);
      $cipher_score = 40 unless $cipher_score;
      }

   #
   # BSI
   #

   if ( all { $ARG->{is}{bsi_pfs} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_only_bsi_pfs(1);
      $self->supports_any_bsi_pfs(1);
      $cipher_score = max( $cipher_score, 100 );
      }
   elsif ( any { $ARG->{is}{bsi_pfs} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_any_bsi_pfs(1);
      $cipher_score = max( $cipher_score, 60 );
      }

   if ( all { $ARG->{is}{bsi_nopfs} or $ARG->{is}{bsi_pfs} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_only_bsi_nopfs(1);
      $self->supports_any_bsi_nopfs(1);
      $cipher_score = max( $cipher_score, 85 );
      }

   # TODO: missing test case in t/120-ssl-handshake.t for ->{is}{bsi_nopfs}!
   elsif ( any { $ARG->{is}{bsi_nopfs} or $ARG->{is}{bsi_pfs} } @{ $self->accepted_ciphers->ciphers } )
      {
      $self->supports_any_bsi_nopfs(1);
      $cipher_score = max( $cipher_score, 50 );
      }

   # reduce score, if export or low ciphers are supported
   # or when medium ciphers are supported
   # The reason is: there are "high" ciphers beside BC B, so they get a bonus

   if    ( $self->supports_very_weak ) { $cipher_score -= 30; }
   elsif ( $self->supports_weak )      { $cipher_score -= 20; }
   elsif ( $self->supports_medium )    { $cipher_score -= 10; }


   #
   # Reduce score, if old SSL/TLS versions used
   # extra code for keeping this value as version_score
   #

   my $version_negative_score = 0;


   # reduce score, if old protocols are supported
   if    ( $self->supports_sslv2 )  { $version_negative_score = 100; }
   elsif ( $self->supports_sslv3 )  { $version_negative_score = 35; }
   elsif ( $self->supports_tlsv1 )  { $version_negative_score = 15; }
   elsif ( $self->supports_tlsv11 ) { $version_negative_score = 5; }
   else                             { $version_negative_score = 0; }
   $version_negative_score += 10 unless $self->supports_tlsv12;


   #   if ( $self->supports_sslv2 )
   #      {
   #      $version_negative_score = 100;
   #      }
   #   else
   #      {
   #      $version_negative_score += 35 if $self->supports_sslv3;
   #      $version_negative_score += 15 if $self->supports_tlsv1;
   #      $version_negative_score += 5  if $self->supports_tlsv11;
   #
   #      # reduce score, if TLS 1.2 is NOT supported, but only slightly because already low
   #      $version_negative_score += 5 unless $self->supports_tlsv12;
   #      }

   WARN "UUPS? NO SSL/TLS Version for "
      . $self->host
      . "?!? Cipher-Score: $cipher_score; Ciphers: "
      . $self->accepted_ciphers->names
      if (     !$self->supports_sslv2
           and !$self->supports_sslv3
           and !$self->supports_tlsv1
           and !$self->supports_tlsv11
           and !$self->supports_tlsv12 );

   # WARN "Version-Neg-Score is 5 for " . $self->host if $version_negative_score == 5;

   # my $score = max( 0, $cipher_score - $version_negative_score );
   #$self->score($score);
   # change: don't cut negative!
   my $score = $cipher_score - $version_negative_score + 200;
   $self->score($score);


   my $version_score = 110 - $version_negative_score;
   $self->named_score("cipher$cipher_score-version$version_score");

   $self->score_ciphersuites($cipher_score);
   $self->score_tlsversion($version_score);

   # Not allowed for privacy reasons!
   # TRACE "INTERNALDEBUG: Score for ${ \$self->host }: $score (C: $cipher_score; V: $version_score)";


   return $self;
   } ## end sub _calculate_score


=head2 supports_very_weak, supports_weak, supports_medium, supports_no_weakmedium

...

=cut

sub supports_very_weak
   {
   my $self = shift;
   return $self->very_weak_ciphers->count;
   }

sub supports_weak
   {
   my $self = shift;
   return $self->weak_ciphers->count;
   }

sub supports_medium
   {
   my $self = shift;
   return $self->medium_ciphers->count;
   }

sub supports_no_weakmedium
   {
   my $self = shift;
   return 1 if !$self->supports_very_weak and !$self->supports_weak and !$self->supports_medium;
   return 0;
   }


=head2 check_all_ciphers($ssl_version)

Tests which CipherSuite a server supports

Returns true, if the server version matches $ssl_version

=cut

sub check_all_ciphers
   {
   my $self        = shift;
   my $ssl_version = shift;

   TRACE "Start check_all_ciphers with Version; $ssl_version";

   my $count = 0;

   foreach my $ciphers_part ( $self->ciphers_to_check->split_into_parts )
      {
      while (1)
         {
         if ( $self->accepted_ciphers->count > 360 )
            {
            ERROR "Ups, >360 Accepted Ciphers for ${ \$self->host }! FAIL!";
            DEBUG "Too long cipher list: ${ \$self->accepted_ciphers->names }";
            die "Exiting too long loop for ${ \$self->host }\n";
            }

         sleep( $self->throttle_time ) if $self->throttle_time;


         # TODO: load/use handshake_class (in BUILD?)
         my $handshake = $self->handshake_class->new(
                                                      host        => $self->host,
                                                      port        => $self->port,
                                                      ssl_version => $ssl_version,
                                                      ciphers     => $ciphers_part,
                                                      timeout     => $self->timeout,
                                                    );
         my $stat = eval { $handshake->hello; return 1; };

         unless ($stat)
            {
            DEBUG "SSL Handshake error: $EVAL_ERROR";
            if ( index( $EVAL_ERROR, "Can't connect" ) > -1 )
               {
               WARN
                  "Ups, Connection failed. Maybe firewalled because too fast? ${ \$self->host }:${ \$self->port }, v$ssl_version";
               return $count;
               }
            }


         # End loop, when no (new) cipher found
         my $count_accepted = $handshake->accepted_ciphers->count;
         unless ($count_accepted)
            {
            TRACE "Exit check cipher loop because NO CIPHER FOUND " . $self->host;
            last;
            }

         $count++ if $handshake->server_version == $ssl_version;


         my $count_to_check_before_remove = $ciphers_part->count;

         $self->ciphers_to_check->remove( $handshake->accepted_ciphers );    # remove from split part AND complete list
         $ciphers_part->remove( $handshake->accepted_ciphers );
         $self->accepted_ciphers->add( $handshake->accepted_ciphers );

         # End loop, when there is no more ciphersuite to check
         unless ( $ciphers_part->count )
            {
            TRACE "Exit check cipher loop because NO MORE CIPHER left for checking " . $self->host;
            last;
            }

         # End loop, if there are ciphers found, but not in ciphers_to_check
         # This may happen with SSL 2.0 and broken implementations (e.g. MS IIS)?!??
         if ( $count_to_check_before_remove == $ciphers_part->count )
            {
            TRACE "Exit check cipher loop because NO NEW CIPHER FOUND " . $self->host;
            last;
            }

         # Oben, hier falsch$count++ if $handshake->server_version == $ssl_version;

         } ## end while (1)

      } ## end foreach my $ciphers_part ( ...)

   return $count;
   } ## end sub check_all_ciphers


=head2 ->check_ciphers_by_tag($ssl_version, $tag)

checks, if the cipher suitess found by the tag are supported


=cut

sub check_ciphers_by_tag
   {
   my $self        = shift;
   my $ssl_version = shift;
   my $tag         = shift;

   sleep( $self->throttle_time ) if $self->throttle_time;

   my $handshake = $self->handshake_class->new(
                                                host        => $self->host,
                                                port        => $self->port,
                                                ssl_version => $ssl_version,
                                                ciphers     => Net::SSL::CipherSuites->new_by_tag($tag),
                                                timeout     => $self->timeout,
                                              );
   eval { $handshake->hello; return 1; } or DEBUG "SSL Handshake error: $EVAL_ERROR";

   return $handshake->accepted_ciphers;

   }


=head2 check_supported_version($ssl_version [, $ciphers] )

Tests, if there is a supported cipher for the given SSL/TLS version.
When no cipher given, it searches only for already supported ciphers (->accepted_ciphers)


=cut

sub check_supported_version
   {
   my $self        = shift;
   my $ssl_version = shift;
   my $ciphers     = shift // $self->accepted_ciphers;

   #croak "No accepted cipher suites, can't check if SSL/TLS version is supported" unless $ciphers->count;
   # no ciphers, nothing accepted ...
   unless ( $ciphers->count )
      {
      WARN "Can't check if this SSL-Version is supported, when NO ciphersuites are accepted. UUUPS! " . $self->host;
      return;
      }

   sleep( $self->throttle_time ) if $self->throttle_time;

   my $handshake =
      $self->handshake_class->new(
                                   host        => $self->host,
                                   port        => $self->port,
                                   ssl_version => $ssl_version,
                                   ciphers     => $ciphers,
                                   timeout     => $self->timeout,
                                 );
   eval { $handshake->hello; return 1; } or DEBUG "SSL Handshake error: $EVAL_ERROR";

   return $handshake->server_version && ( $handshake->server_version == $ssl_version ) && $handshake->accepted_ciphers->count;

   } ## end sub check_supported_version

=head2 ->supported_cipher_names

returns an array (or arrayref) of the names of all suppported cipher suites

TODO: Duplicate, remove, replace by $self->accepted_ciphers->unique->names

=cut

sub supported_cipher_names
   {
   my $self = shift;

   my @names = map { $ARG->{name} } @{ $self->accepted_ciphers->unique->ciphers };

   return wantarray ? @names : \@names;
   }


=head2 ->supports_only_bsi_versions

returns true if the connection only supports BSI recommended protocol versions: TLS 1.2 and maybe TLS 1.1

=cut

sub supports_only_bsi_versions
   {
   my $self = shift;

   return (     ( $self->supports_tlsv12 )
            and ( not $self->supports_tlsv1 )
            and ( not $self->supports_sslv3 )
            and ( not $self->supports_sslv2 ) );
   }


=head2 ->supports_only_tlsv12

returns true if the connection only supports TLSv12 and NO older version

In future: checks, if server NOT supports TLS 1.13!

=cut

sub supports_only_tlsv12
   {
   my $self = shift;

   return (     ( $self->supports_tlsv12 )
            and ( not $self->supports_tlsv11 )
            and ( not $self->supports_tlsv1 )
            and ( not $self->supports_sslv3 )
            and ( not $self->supports_sslv2 ) );
   }



=head2 ->supports_only_bsi_versions_ciphers

returns true if the connection only supports BSI recommended protocol versions 
AND cipher suites (with PFS!).

=cut

sub supports_only_bsi_versions_ciphers
   {
   my $self = shift;

   return ( $self->supports_only_bsi_pfs and $self->supports_only_bsi_versions );
   }


=head2 supports_ancient_ssl_versions

returns true, if ols SSL versions 2.0 and 3.0 with lots of 
bugs and security nightmares are supported.

=cut


sub supports_ancient_ssl_versions
   {
   my $self = shift;

   return ( $self->supports_sslv3 or $self->supports_sslv2 );
   }

=head2 supports_sslv3_or_newer, supports_tlsv1_or_newer, supports_tlsv11_or_newer, supports_tlsv12_or_newer

as the name says: returns true if this version and no older is supported

TODO: Tests!

=cut

sub supports_sslv3_or_newer
   {
   my $self = shift;
   return 1 if $self->supports_sslv3 and !$self->supports_sslv2;
   return 0;
   }

sub supports_tlsv1_or_newer
   {
   my $self = shift;
   return 1 if $self->supports_tlsv1 and !$self->supports_sslv3 and !$self->supports_sslv2;
   return 0;
   }

sub supports_tlsv11_or_newer
   {
   my $self = shift;
   return 1 if $self->supports_tlsv11 and !$self->supports_tlsv1 and !$self->supports_sslv3 and !$self->supports_sslv2;
   return 0;
   }

sub supports_tlsv12_or_newer
   {
   my $self = shift;
   return 1
      if $self->supports_tlsv12
      and !$self->supports_tlsv11
      and !$self->supports_tlsv1
      and !$self->supports_sslv3
      and !$self->supports_sslv2;
   return 0;
   }


=head2 supports_tlsv11_or_older, supports_tlsv1_or_older, supports_sslv3_or_older, supports_only_sslv2

as the name says: returns true if this version and no newer is supported

TODO: Tests!

=cut

sub supports_tlsv11_or_older
   {
   my $self = shift;
   return 1 if $self->supports_tlsv11 and !$self->supports_tlsv12;
   return 0;
   }

sub supports_tlsv1_or_older
   {
   my $self = shift;
   return 1 if $self->supports_tlsv1 and !$self->supports_tlsv11 and !$self->supports_tlsv12;
   return 0;
   }

sub supports_sslv3_or_older
   {
   my $self = shift;
   return 1 if $self->supports_sslv3 and !$self->supports_tlsv1 and !$self->supports_tlsv11 and !$self->supports_tlsv12;
   return 0;
   }

sub supports_only_sslv2
   {
   my $self = shift;
   return 1
      if $self->supports_sslv2
      and !$self->supports_sslv3
      and !$self->supports_tlsv1
      and !$self->supports_tlsv11
      and !$self->supports_tlsv12;
   return 0;
   }


1;
