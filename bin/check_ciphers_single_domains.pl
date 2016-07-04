#!/usr/bin/env perl
## no critic

# TODO: This is a hack and will be changed

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";
use English qw( -no_match_vars );


use Net::SSL::GetServerProperties;

use 5.010;

say "-- ";
say "-- TLS-Check / Net::SSL::GetServerProperties -- Version $Net::SSL::GetServerProperties::VERSION";
say "-- Small helper for getting a quick (and incomplete) overview of one or more hosts";
say "-- It's more an example for the API of Net::SSL::GetServerProperties then an analysis program!";
say "-- ";
say "-- TLS-Check is at the moment made for mass analysis, not individual analysis of single domains.";
say "-- Nevertheless you can use it for single domain analysis, but it is neither complete nor perfect ...";
say "-- ";
say "-- usage: $PROGRAM_NAME <hostname> [ <more mosts> ... ]";
say "-- ";

foreach my $host (@ARGV)
   {

   my $prop = Net::SSL::GetServerProperties->new( host => $host, );
   $prop->get_properties;

   say "";
   say "Summary for $host";
   say "Supported Cipher Suites at Host $host: ";
   say "  * 0x$_->{code} $_->{name}" foreach @{ $prop->accepted_ciphers->order_by_code->ciphers };
   say "Supports SSLv2"   if $prop->supports_sslv2;
   say "Supports SSLv3"   if $prop->supports_sslv3;
   say "Supports TLSv1"   if $prop->supports_tlsv1;
   say "Supports TLSv1.1" if $prop->supports_tlsv11;
   say "Supports TLSv1.2" if $prop->supports_tlsv12;

   say "Supports at least one Bettercrypto A Cipher Suite"                     if $prop->supports_any_bc_a;
   say "Supports at least one Bettercrypto B Cipher Suite"                     if $prop->supports_any_bc_b;
   say "Supports at least one BSI TR-02102-2 Cipher Suite with PFS"            if $prop->supports_any_bsi_pfs;
   say "Supports at least one BSI TR-02102-2 Cipher Suite with or without PFS" if $prop->supports_any_bsi_nopfs;

   say "Supports only Bettercrypto A Cipher Suites"                     if $prop->supports_only_bc_a;
   say "Supports only Bettercrypto B Cipher Suites"                     if $prop->supports_only_bc_b;
   say "Supports only BSI TR-02102-2 Cipher Suites with PFS"            if $prop->supports_only_bsi_pfs;
   say "Supports only BSI TR-02102-2 Cipher Suites with or without PFS" if $prop->supports_only_bsi_nopfs;

   say "Supports weak Cipher Suites: " . $prop->weak_ciphers->names     if $prop->supports_weak;
   say "Supports medium Cipher Suites: " . $prop->medium_ciphers->names if $prop->supports_medium;
   say "Supports no weak or medium Cipher Suites, only high or unknown" if $prop->supports_no_weakmedium;
   say "Supports ancient SSL Versions 2.0 or 3.0"                       if $prop->supports_ancient_ssl_versions;

   say "Supports EC keys"      if $prop->supports_ec_keys;
   say "Supports only EC keys"      if $prop->supports_only_ec_keys;
   say "Supports PFS cipher suites"      if $prop->supports_pfs;
   say "Supports only PFS cipher suites"      if $prop->supports_only_pfs;
   

   say "Cipher Suite used by Firefox:        " . $prop->firefox_cipher;
   say "Cipher Suite used by Safari:         " . $prop->safari_cipher;
   say "Cipher Suite used by Chrome:         " . $prop->chrome_cipher;
   say "Cipher Suite used by Win 7 (IE 8):   " . $prop->ie8win7_cipher;
   say "Cipher Suite used by Win 10 (IE 11): " . $prop->ie11win10_cipher;

   say "Supports only SSL/TLS versions recommended by BSI TR-02102-2" if $prop->supports_only_bsi_versions;
   say "Supports only SSL/TLS versions and cipher suites with PFS recommended by BSI TR-02102-2"
      if $prop->supports_only_bsi_versions_ciphers;
   say "Supports only TLS 1.2 (or newer)" if $prop->supports_only_tlsv12;

   say "Overall Score for this Host: " . $prop->score;

   say "";

   } ## end foreach my $host (@ARGV)


