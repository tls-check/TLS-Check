#!/usr/bin/env perl

#
# A little hack to create a (good readable) summary of most important TLS-Check-Results.
#


use strict;
use warnings;
use autodie;

use utf8;

use Carp qw(croak carp);
use English qw( -no_match_vars );

use Text::CSV_XS;

use Readonly;

use 5.010;

Readonly my $COL_CATEGORY          => 0;
Readonly my $COL_MODULE            => 1;
Readonly my $COL_CLASS             => 2;
Readonly my $COL_CLASS_DESCRIPTION => 3;
Readonly my $COL_RUNTIME           => 4;
Readonly my $COL_CHECK_NAME        => 5;
Readonly my $COL_CHECK_DESCRIPTION => 6;
Readonly my $COL_CHECK_TYPE        => 7;
Readonly my $COL_RESULT_ALL        => 8;
Readonly my $COL_RESULT_SUM        => 9;
Readonly my $COL_RESULT_MEAN       => 10;
Readonly my $COL_RESULT_PERCENT    => 11;
Readonly my $COL_RESULT_MEDIAN     => 12;
Readonly my $COL_RESULT_GROUP      => 13;


Readonly my $HACKY_CONF__NO_CATEGORIES => 1;



binmode STDIN,  ":encoding(UTF-8)";
binmode STDOUT, ":encoding(UTF-8)";

my %result;

my @categories;

init();

my $out_csv = Text::CSV_XS->new( { binary => 1, sep_char => q{;}, } );

if ($HACKY_CONF__NO_CATEGORIES)
   {
   $out_csv->combine( "Name des Tests", "Wert", "Prozent" ) or croak "CSV error at headline";
   }
else
   {
   $out_csv->combine( "Name des Tests", @categories ) or croak "CSV error at headline";
   }
say $out_csv->string;

#<<<

# Summarize: Beschreibung, Check-Modul, Check-Name, Spalte, Prozent-Angabe
# Spalte 9 ist default (Wert)

head("");
head("Webserver");
summarize( "Alle gültigen Domains",                                              Web => "HTTP active", col => $COL_RESULT_ALL, );
summarize( "Alle erreichbaren Webseiten",                                        Web => "HTTP active", );
summarize( "Webseiten die prinzipiell Verschlüsselung können",                   Web => "HTTPS active", );
summarize( "Webseiten ohne Browser-Warnung (Host und Zertifikat verifiziert)",   Web => "HTTPS all verified", );


head("");

summarize("Von den Webseiten, die prinzipiell Verschlüsselung können",                           Web            => "HTTPS active",       percentcol =>  $COL_RESULT_SUM,    ); # percent => "Web/HTTPS active"??????
summarize( "Beachten alle BSI-Empfehlungen zu Protokoll-Version/kryptografische Verfahren",      CipherStrength => "Full BSI support Vers+Ciph", );
summarize( "Webseiten ohne Browser-Warnung (Domain und Zertifikat verifiziert)",                 Web            => "HTTPS all verified",          percent => "Web/HTTPS active");
summarize( "… haben ein zum Domainname passendes Zertifikat",                                    Web            => "HTTPS host verified",         percent => "Web/HTTPS active");
summarize( "… mit validem Zertifikat einer von den Browsern akzeptierten Zertifizierungsstelle", Web            => "HTTPS cert verified",         percent => "Web/HTTPS active");
summarize( "… mit validem Zertifikat, aber falschem Host",                                       Web            => "HTTPS wrong host, cert OK",   percent => "Web/HTTPS active");

summarize_cipher("CipherStrength");

summarize( "… Leiten von verschlüsselter auf unverschlüsselte Verbindung um (schlecht)",         Web            => "Redirect to HTTP",  percentcol =>  $COL_RESULT_SUM, percent => "Web/HTTPS active");
summarize( "… Leiten von unverschlüsselter auf verschlüsselte Verbindung um (gut)",              Web            => "Redirect to HTTPS", percentcol =>  $COL_RESULT_SUM, percent => "Web/HTTPS active");
summarize( "… nutzen die Sicherheitsfunktion Strict Transport Security",                         Web            => "Supports HSTS",     percentcol =>  $COL_RESULT_SUM, percent => "Web/HTTPS active");
summarize( "… nutzen die Sicherheitsfunktion Public Key Pinning",                                Web            => "Supports HPKP",     percentcol =>  $COL_RESULT_SUM, percent => "Web/HTTPS active");
 

summarize("Von den Webseiten, die ein gültiges Zertifikat haben …",                              Web            => "HTTPS all verified", percentcol =>  $COL_RESULT_SUM);
summarize_cipher("CipherStrengthOnlyValidCerts");

head("");
summarize("Webserver, die für die Heartbleed-Attacke anfällig sind",    Heartbleed => "HTTPS Heartbleed vulnerable", percent => undef, );
head("");

summarize( "Durchschnittlicher Score der Verschlüsselung unterstützenden Seiten",                CipherStrength => "Score",               col => $COL_RESULT_MEAN, percent => undef, );
summarize( "Durchschnittlicher Score der Webseiten mit verifiziertem Zertifikat/Domain",         CipherStrengthOnlyValidCerts => "Score", col => $COL_RESULT_MEAN, percent => undef, );
summarize( "Gesamt-Score nach Einbeziehung aller Ergebnisse",                                    FinalScore     => "Final Web Score",     col => $COL_RESULT_MEAN, percent => undef, );

# TODO: Selbstsigniert



head("");
head("Mailserver (MX)");
summarize( "Alle getesteten Mailserver",                                         Mail => "#MX unique", percentcol => $COL_RESULT_SUM,  );
summarize( "Alle erreichbaren Mailserver",                                       Mail => "#MX active", percentcol => $COL_RESULT_SUM, percent => "Mail/#MX unique",  );
summarize( "Mailserver, die prinzipiell Verschlüsselung können",                 Mail => "#MX Supports STARTTLS",  percentcol => $COL_RESULT_SUM, percent => "Mail/#MX unique", );

summarize("Von den Mailservern, die prinzipiell Verschlüsselung können",         Mail => "#MX Supports STARTTLS", percentcol =>  $COL_RESULT_SUM,    percent => "Mail/#MX Supports STARTTLS");
summarize( "… haben ein gültiges und zum Domainname passendes Zertifikat",       Mail => "#MX STARTTLS OK",       percentcol =>  $COL_RESULT_SUM,    percent => "Mail/#MX Supports STARTTLS");

summarize_cipher("MailCipherStrength");
summarize( "… könnten verschlüsselt mit „nur Bettercrypto B“-Server kommunizieren", MailCipherStrength => "Supports Any BC B", );

head("");
summarize("Mailserver, die für die Heartbleed-Attacke anfällig sind",    Heartbleed => "# MX Heartbleed vulnerable", percent => undef, );
head("");

summarize( "Durchschnittlicher Score der Verschlüsselung unterstützenden Mailserver",            MailCipherStrength => "Score",   col => $COL_RESULT_MEAN, percent => undef,);

#>>>


# Marktanteil OpenSource Webserver!



#
# Summarize Cipher extra, weil das mehrfach verwendet!
#

sub summarize_cipher
   {
   my $class = shift;
   my @rest  = @ARG;

   #<<<
   summarize( "… mit Unterstützung für extrem unsicheres Protokoll SSL 2.0",                        $class => "Supports SSLv2", @rest );
   summarize( "… mit Unterstützung für sehr unsicheres Protokoll SSL 3.0",                          $class => "Supports SSLv3", @rest );
   summarize( "… mit Unterstützung für sehr unsichere Protokolle SSL 2.0 oder SSL 3.0",             $class => "Supports old SSL v2/v3", @rest );
   summarize( "… mit Unterstützung für veraltetes Protokoll TLS 1.0",                               $class => "Supports TLSv1", @rest );
   summarize( "… mit Unterstützung für TLS 1.1",                                                    $class => "Supports TLSv11", @rest );
   summarize( "… mit Unterstützung für TLS 1.2",                                                    $class => "Supports TLSv12", @rest );
   summarize( "… unterstützen nur das aktuelle Protokoll TLS 1.2 von 2008",                         $class => "Supports Only TLSv12", @rest );
   summarize( "… halten die BSI-Vorgaben fürs Protokoll ein (TLS 1.2, evtl. TLS 1.1)",              $class => "Supports Only BSI Versions", @rest );   
   summarize( "… unterstützen nur TLS 1.0 oder älter",                                              $class => "Supports TLSv1 or older", @rest );
   summarize( "… bieten sehr schwache kryptografische Verfahren an (z.B. Export, NULL,)",           $class => "Supports very weak ciphers", @rest );
   summarize( "… bieten schwache kryptografische Verfahren an (z.B. RC4, 56 Bit, ...)",             $class => "Supports weak ciphers", @rest );
   summarize( "… bieten mittelschwache kryptografische Verfahren an",                               $class => "Supports medium ciphers", @rest );
   summarize( "… bieten keine schwachen/mittelschwachen kryptografischen Verfahren an",             $class => "Supports no weak/medium cipher", @rest );
   summarize( "… Experimental: Schwache Cipher-Suiten ohne Beast/CBC anfällige",                    $class => "Supports weak ciphers, no Beast/CBC", @rest); 
   summarize( "… Experimental: Unterstützt Beast/CBC afällige Cipher",                              $class => "Supports Beast/CBC ciphers", @rest); 
   summarize( "… Experimental: Mittelschwache, aber inklusive Beast/BCB",                           $class => "Supports medium ciphers, including Beast/CBC", @rest); 
   summarize( "… Experimental: Schwache Cipher-Suiten, außer wenn Bettercrypto B Empfehlung",       $class => "Supports weak ciphers, excluding Bettercrypto B", @rest); 
   summarize( "… bieten nur empfohlene kompatible kryptografische Verfahren an (Bettercrypto B)",   $class => "Supports Only BC b", @rest );
   summarize( "… halten die BSI-Vorgaben für kryptografische Verfahren ein",                        $class => "Supports Only BSI PFS", @rest );
   summarize( "… bieten mindestens eines der vom BSI vorgegebenen kryptographischen Verfahren an",  $class => "Supports Any BSI PFS", @rest );
   summarize( "… bieten nur empfohlene sehr sichere kryptografische Verfahren an (Bettercrypto A)", $class => "Supports Only BC A", @rest );
   summarize( "… nutzen (auch) ECDSA Keys",                                                         $class => "Supports ECDSA keys", @rest );
   summarize( "… bieten auch Cipher-Suiten mit PFS an",                                             $class => "Supports PFS cipher(s)", @rest );
   summarize( "… bieten nur Cipher-Suiten mit PFS an",                                              $class => "Supports only PFS ciphers", @rest );

   #>>>

   return;
   } ## end sub summarize_cipher



sub init
   {

   my $in_csv = Text::CSV_XS->new( { binary => 1, sep_char => q{;} } );

   my $cat    = "";
   my $module = "";

   <>;
   <>;                                             # head

   my $catpos = 0;
   while (<>)
      {
      $in_csv->parse($_);
      my @fields = $in_csv->fields();

      if ( $fields[$COL_CATEGORY] )
         {
         $cat = $fields[$COL_CATEGORY];
         $catpos++;                                # New Category!
         $catpos = 0 if $cat eq "Category All Categories (Summary)";
         $categories[$catpos] = $cat;
         next;
         }

      $fields[$COL_CATEGORY] = $cat;

      $module = $fields[$COL_MODULE] if $fields[$COL_MODULE];
      next unless $fields[$COL_CHECK_NAME];
      $fields[$COL_MODULE] = $module;

      $fields[$COL_CHECK_NAME] =~ s{Suppports}{Supports};
      $result{ lc("$module/$fields[$COL_CHECK_NAME]") }[$catpos] = \@fields;

      } ## end while (<>)

   return;
   } ## end sub init


sub head
   {
   $out_csv->combine(@ARG) or croak "CSV error on Head Combine!";
   say $out_csv->string;
   return;
   }


sub summarize
   {
   my $title      = shift;
   my $module     = shift;
   my $check_name = shift;
   my %extra      = ( col => $COL_RESULT_SUM, percentcol => $COL_RESULT_ALL, percent => "$module/$check_name", @ARG );

   # loop cat


   my @fields = ($title);

   my $last_col = $HACKY_CONF__NO_CATEGORIES ? 0 : $#categories;

   # Pronzent weglassen wenn percent == undef
   for my $pos ( 0 .. $last_col )
      {
      my $value = $result{ lc("$module/$check_name") }[$pos][ $extra{col} ] // "";

      $value = sprintf( "%.3f", $value ) if $value =~ m{[.]};

      # Wenn Prozent da sein sollen
      if ( not $HACKY_CONF__NO_CATEGORIES and defined $extra{percent} )
         {
         my $percent_base = $result{ lc( $extra{percent} ) }[$pos][ $extra{percentcol} ] // "";
         if ($percent_base)
            {
            $value = sprintf( "$value (%.3f%%)", ( $value / $percent_base ) * 100 );
            $value =~ s{100[.]000%}{100%}x;
            }
         else
            {
            $value = "$value (---%)";
            }
         }

      $value =~ s{[.]}{,}g;                        #
      push @fields, $value;

      if ( $HACKY_CONF__NO_CATEGORIES and defined $extra{percent} )
         {
         my $percent_base = $result{ lc( $extra{percent} ) }[$pos][ $extra{percentcol} ] // "";
         my $percent_value;
         if ($percent_base)
            {
            $percent_value = sprintf( "%.3f%%", ( $value / $percent_base ) * 100 );
            $percent_value =~ s{100[.]000%}{100%}x;
            $percent_value =~ s{[.]}{,}g;
            }
         else
            {
            $value = "$value (---%)";
            }
         push @fields, $percent_value;
         }

      } ## end for my $pos ( 0 .. $last_col...)


   $out_csv->combine(@fields) or croak "CSV error: can't combine summary";

   say $out_csv->string;

   return;
   } ## end sub summarize


sub get_field
   {
   my $in_fields = shift;
   my %params    = @ARG;

   my $field = $in_fields->[ $params{col} ];

   return $field if exists $params{percent} and not defined $params{percent};
   return;
   }
