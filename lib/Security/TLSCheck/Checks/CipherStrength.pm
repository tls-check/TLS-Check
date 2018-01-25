package Security::TLSCheck::Checks::CipherStrength;


use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;

use Net::SSL::GetServerProperties;


=head1 NAME

Security::TLSCheck::Checks::CipherStrength - Check Strength of CipherSuites and SSL/TLS Version

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 676 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION

...



=cut

#<<<

my $key_figures = 
   [

   { name => "Supports SSLv2",             type => "flag",  source => "supports_sslv2",           description => "Server supports SSLv2" }, 
   { name => "Supports SSLv3",             type => "flag",  source => "supports_sslv3",           description => "Server supports SSLv3" }, 
   { name => "Supports TLSv1",             type => "flag",  source => "supports_tlsv1",           description => "Server supports TLSv1" }, 
   { name => "Supports TLSv11",            type => "flag",  source => "supports_tlsv11",          description => "Server supports TLSv11" }, 
   { name => "Supports TLSv12",            type => "flag",  source => "supports_tlsv12",          description => "Server supports TLSv12" }, 
   { name => "Supports SSLv3 or better",   type => "flag",  source => "supports_sslv3_or_newer",  description => "Server supports SSLv3 or above" }, 
   { name => "Supports TLSv1 or better",   type => "flag",  source => "supports_tlsv1_or_newer",  description => "Server supports TLSv1 or above" }, 
   { name => "Supports TLSv11 or better",  type => "flag",  source => "supports_tlsv11_or_newer", description => "Server supports TLSv11 or above" }, 
   { name => "Supports TLSv12 or better",  type => "flag",  source => "supports_tlsv12_or_newer", description => "Server supports TLSv12 or above" }, 
   { name => "Supports only SSLv2",        type => "flag",  source => "supports_only_sslv2",      description => "Server supports only SSLv2" }, 
   { name => "Supports SSLv3 or older",    type => "flag",  source => "supports_sslv3_or_older",  description => "Server supports only SSLv3 or older" }, 
   { name => "Supports TLSv1 or older",    type => "flag",  source => "supports_tlsv1_or_older",  description => "Server supports TLSv1 or older" }, 
   { name => "Supports TLSv11 or older",   type => "flag",  source => "supports_tlsv11_or_older",  description => "Server supports TLSv11 or older" }, 

   { name => "Supports Any BC A",          type => "flag",  source => "supports_any_bc_a",       description => "Server supports any Bettercrypto A CipherSuite" }, 
   { name => "Supports Any BC b",          type => "flag",  source => "supports_any_bc_b",       description => "Server supports any Bettercrypto B CipherSuite" }, 
   { name => "Supports Any BSI PFS",       type => "flag",  source => "supports_any_bsi_pfs",    description => "Server supports any BSI Recommendation with PFS" }, 
   { name => "Supports Any BSI (no) PFS",  type => "flag",  source => "supports_any_bsi_nopfs",  description => "Server supports any BSI Recommendation with (no) PFS" }, 
   { name => "Supports Only BC A",         type => "flag",  source => "supports_only_bc_a",      description => "Server supports only Bettercrypto A CipherSuite" }, 
   { name => "Supports Only BC b",         type => "flag",  source => "supports_only_bc_b",      description => "Server supports only Bettercrypto B CipherSuite" }, 
   { name => "Supports Only BSI PFS",      type => "flag",  source => "supports_only_bsi_pfs",   description => "Server supports only BSI Recommendation with PFS" }, 
   { name => "Supports Only BSI (no) PFS", type => "flag",  source => "supports_only_bsi_nopfs", description => "Server supports only BSI Recommendation with (no) PFS" }, 

   { name => "Supports very weak ciphers", type => "flag",  source => "supports_very_weak",       description => "Server supports very weak ciphers (e.g. EXPORT, NULL, ...)" }, 
   { name => "Supports weak ciphers",      type => "flag",  source => "supports_weak",            description => "Server supports weak ciphers (e.g. 56 bit, RC4, ...)" }, 
   { name => "Supports medium ciphers",    type => "flag",  source => "supports_medium",          description => "Server supports medium ciphers ()" }, 
   { name => "Supports no weak/medium cipher", type => "flag",source=>"supports_no_weakmedium",   description => "Server supports no weak/medium, only high or unknown ciphers" }, 

   # TODO: experimental Temp ciphers, CBC ...
   { name => "Supports weak ciphers, no Beast/CBC",             type => "flag",  source => "supports_weak_ciphers_no_cbc",            description => "Experimental: Server supports weak ciphers, excluding Beast-CBC", }, 
   { name => "Supports Beast/CBC ciphers",                      type => "flag",  source => "supports_beast_cbc_ciphers",              description => "Experimental: Server supports Beast-CBC ciphers", }, 
   { name => "Supports medium ciphers, including Beast/CBC",    type => "flag",  source => "supports_medium_ciphers_withcbc",         description => "Experimental: Server supports medium ciphers, including Beast-CBC" }, 
   { name => "Supports weak ciphers, excluding Bettercrypto B", type => "flag",  source => "supports_weak_ciphers_no_bettercrypto_b", description => "Experimental: Server supports weak ciphers, excluding Bettercrypto B" }, 
   
   
   { name => "Supports ECDSA keys",        type => "flag",  source => "supports_ec_keys",         description => "Server supports elliptic courve keys" }, 
   { name => "Supports only ECDSA keys",   type => "flag",  source => "supports_ec_keys",         description => "Server supports only elliptic courve keys" }, 
   { name => "Supports PFS cipher(s)",     type => "flag",  source => "supports_pfs",             description => "Server supports at least one cipher with perforct forward secrecy" }, 
   { name => "Supports only PFS ciphers",  type => "flag",  source => "supports_only_pfs",        description => "Server supports only ciphers with perfect forward secrecy" }, 


   { name => "Cipher-Suite with Firefox",   type => "group", source => "firefox_cipher",          description => "Selected Cipher-Suite with Firefox 42" }, 
   { name => "Cipher-Suite with Safari",    type => "group", source => "safari_cipher",           description => "Selected Cipher-Suite with Safari 9.0.1" }, 
   { name => "Cipher-Suite with Chrome",    type => "group", source => "chrome_cipher",           description => "Selected Cipher-Suite with Chrome 46.0" }, 
   { name => "Cipher-Suite with IE8 Win7",  type => "group", source => "ie8win7_cipher",          description => "Selected Cipher-Suite with IE 8 on Win 7" }, 
   { name => "Cipher-Suite with IE11 Win11",type => "group", source => "ie11win10_cipher",        description => "Selected Cipher-Suite with IE 11 on Win 11" }, 

   { name => "# of accepted Cipher Suites", type => "int",   source => "count_accepted_ciphers",  description => "Counts the number of the accepted cipher suites", }, 
   { name => "Group # of accepted Ciphers", type => "group", source => "count_accepted_ciphers",  description => "Groups the number of the accepted cipher suites", }, 

   { name => "Suppports Only BSI Versions", type => "flag",  source => "supports_only_bsi_versions", description => "Server supports only BSI recommended Versions: TLSv1.2 and up and maybe TLSv1.1" }, 
   { name => "Full BSI support Vers+Ciph",  type => "flag",  source => "supports_only_bsi_versions_ciphers", description => "Full BSI support for version and ciphers" }, 
   { name => "Supports Only TLSv12",        type => "flag",  source => "supports_only_tlsv12",    description => "Server supports only TLSv1.2" }, 
   { name => "Supports old SSL v2/v3",      type => "flag",  source => "supports_ancient_ssl_versions", description => "Server supports ancient SSL versions 2.0 or 3.0" }, 

   { name => "Score",                       type => "int",   source => "score",                   description => "Overall Encryption Strength", }, 
   { name => "Score grouped",               type => "group", source => "score",                   description => "Histogram of Overall Encryption Strength", }, 
   { name => "Score from TLS/SSL Version",  type => "int",   source => "score_tlsversion",        description => "TLS/SSL-Version Strength", }, 
   { name => "Score from CipherSuites",     type => "int",   source => "score_ciphersuites",      description => "CipherSuite Strength", }, 
   { name => "Score as Name",               type => "group", source => "named_score",             description => "Score string with CipherSuite and TLS-Version", }, 
   
   { name => "Supported CipherSuites",      type => "set",   source => "join_cipher_names",       description => "All supported CipherSuites by this server", }, 

   ];

has '+key_figures' => ( default => sub {return $key_figures} );

has '+description' => ( default => "Strength of CipherSuites and SSL/TLS Version" );

has properties => ( is => "rw", isa => "Net::SSL::GetServerProperties", 
   handles => [ 
   qw( 
      supports_sslv2
      supports_sslv3
      supports_tlsv1
      supports_tlsv11
      supports_tlsv12 
      supports_any_bc_a
      supports_any_bc_b
      supports_any_bsi_pfs
      supports_any_bsi_nopfs
      supports_only_bc_a
      supports_only_bc_b
      supports_only_bsi_pfs
      supports_only_bsi_nopfs 
      supports_very_weak
      supports_weak
      supports_medium
      supports_no_weakmedium
      
      supports_weak_ciphers_no_cbc
      supports_beast_cbc_ciphers
      supports_medium_ciphers_withcbc
      supports_weak_ciphers_no_bettercrypto_b 
      
      firefox_cipher   
      safari_cipher    
      chrome_cipher    
      ie8win7_cipher   
      ie11win10_cipher 
      
      count_accepted_ciphers
      
      supports_only_bsi_versions
      supports_only_bsi_versions_ciphers
      supports_only_tlsv12
      supports_ancient_ssl_versions
      
      score
      named_score
      score_ciphersuites
      score_tlsversion
      
      
      supports_sslv3_or_newer
      supports_tlsv1_or_newer
      supports_tlsv11_or_newer
      supports_tlsv12_or_newer
      supports_tlsv11_or_older
      supports_tlsv1_or_older
      supports_sslv3_or_older
      supports_only_sslv2

      supports_ec_keys
      supports_only_ec_keys
      supports_pfs         
      supports_only_pfs    
      
      ), ], );

#>>>


=head1 METHODS

=head2 run_check

...

=cut

sub run_check
   {
   my $self = shift;

   my $www = $self->www;

   # check web only if there is some HTTPS
   unless ( $self->other_check("Security::TLSCheck::Checks::Web")->https_active )
      {
      DEBUG "Skipped CipherStrength tests for $www because no https active";
      return;
      }

   my $prop = Net::SSL::GetServerProperties->new( host => $www, timeout => $self->timeout, );
   $prop->get_properties;

   $self->properties($prop);

   return $self->result;
   }

=head2 ->join_cipher_names

Joins all (supported) cipher names with a : to one string, suitable for the Check type "set".

=cut

sub join_cipher_names
   {
   my $self = shift;

   my $ciphers = join( q{:}, $self->properties->supported_cipher_names );
   TRACE "Score ${ \$self->score }, Supported Ciphers for ${ \$self->domain }: $ciphers";
   return $ciphers;
   }


__PACKAGE__->meta->make_immutable;

1;
