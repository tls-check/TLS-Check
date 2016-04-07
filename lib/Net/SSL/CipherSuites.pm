package Net::SSL::CipherSuites;

use Moose;
use 5.010;

use English qw( -no_match_vars );
use FindBin;
use File::ShareDir;
use Text::CSV_XS;
use Storable qw(dclone);
use Carp qw(croak carp);
use Scalar::Util qw(blessed);
use List::Util qw(any);

use Readonly;

=head1 NAME

 Net::SSL::CipherSuites - functions for getting, filtering lists of SSL/TLS cipher suites

=head1 VERSION

Version 0.8, $Revision: 626 $

=cut

#<<<
my $BASE_VERSION = "0.8"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 626 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8

   # empty cipher list
   my $ciphers = Net::SSL::CipherSuites->new(); 
   # fill by Bettercrypto A list
   $ciphers->new_by_tags("bettercrypto_a");

   # or directly
   my $ciphers = Net::SSL::CipherSuites->new_by_tags("bettercrypto_a"); 

   # All ciphers
   my $ciphers = Net::SSL::CipherSuites->new_with_all; 
   
   # by name
   my $ciphers = Net::SSL::CipherSuites->new_by_name(qw(NULL NULL_WITH_NULL_NULL RSA_WITH_NULL_SHA256)); 
   
   # add ciphers by tag
   $ciphers->add( Net::SSL::CipherSuites->new_by_tags("SSLv3") );
   
   # remove ciphers from list (e.g. used or other tag)
   $ciphers->remove( Net::SSL::CipherSuites->by_tags( qw(weak WEAK LOW) ) );
   
   # Important: make cipher list unique, 
   # because by selecting via name/tag/.... there may be duplicates!
   # even with only one Tag there MAY be duplicates
   $ciphers->unique;
   
   # 
   ....
   
   
   
   
   
   
   






Werte pro Cipher-Suite:

  cipher suite name       zb ECDHE-ECDSA-AES256-GCM-SHA384  
  cipher suite value      zb ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  
  constant                as hex string 
  
  openssl score           HIGH, MEDIUM, LOW, WAEK (0.9.8)
  sslaudit score          sslaudit.ini
  BSI score
  bettercrypto score
  our score               anhand: andere scores, insbes. BSI, Bits, Algorithmen, ...
  
  protocol version
  Encryption Algorithm    None, AES, AESCCM, AESGCM, CAMELLIA, DES, 3DES, FZA, IDEA, RC4, RC2, SEED
  Key Size                bits
  MAC Algorithm           MD5, SHA1, SHA256, SHA384, AEAD
  Authentication          None, DSS, RSA, ECDH, ECDSA, KRB5, PSK
  Key Exchange            DH, ECDH, ECDH/ECDSA, RSA, KRB5, PSK, SRP
  
  source                  rfc123 





=head1 DESCRIPTION

The purpose of this module is to collect and manage as many SSL/TLS cipher suites as possible. 
It manages lists of cipher suites, can filter all by tags or names, can add new cipher suites to 
an cipher list object or delete suites from the list. Cipher(lists) can be converted in their 
binary constant, so that they can be used in a SSL/TLS handshake and vice versa.

For best performance (and memory usage) the cipher lists are managed as ordinary hashrefs, 
they are not objects. Only the cipher lists are objects.


=cut



Readonly my $CODE_HEX_LEN    => 4;                 # length of a SSLv3/TLS Cipher Suite code in chars
Readonly my $CODE_V2_HEX_LEN => 6;                 # dito, but SSLv2
Readonly my $CODE_LEN        => 2;
Readonly my $CODE_V2_LEN     => 3;



Readonly my $SCORE_BEST => 100;
Readonly my $SCORE_GOOD => 80;

Readonly my $SCORE_REDUCE => 5;

Readonly my $SSL3 => 0x0300;


has ciphers => (
                 is      => 'rw',
                 isa     => 'ArrayRef',
                 traits  => ['Array'],
                 handles => { count => "count", all => "elements", },
                 default => sub { [] },
               );

#
# TLS list:
# http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
# http://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
#

#
# Rules for cipher suites:
# https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Protocol_and_Cipher_Configuration
#


#
# SSL map
# https://github.com/iphelix/sslmap/blob/master/sslmap.py
#
# PCT_*
# https://www.wireshark.org/lists/ethereal-dev/200204/msg00080.html
#
# Wireshark komplett
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ssl-utils.c
#

#
# additional ciphers and lists:
# GOST official: https://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
#
#
#'000080': {'name': 'TLS_GOSTR341094_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94', 'au': 'VKO GOST R 34.10-94', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
#'000081': {'name': 'TLS_GOSTR341001_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
#'000082': {'name': 'TLS_GOSTR341094_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94 ', 'au': 'VKO GOST R 34.10-94 ', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
#'000083': {'name': 'TLS_GOSTR341001_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},



#<<<
my %ciphers = 
   (
   # Long name                                    SSL/TLS Version     hex code          OpenSSL name                                  Encryption used    Encrypion      Message          Authentication      Key Exchange          Scrores
   #   SSL/TLS Standard name without              version where                         has duplicates!                                                  size (bits)    Authentification
   #   Prefix SSL_CK / SSL / TLS                  cipher appeared                                                                                                                Integrity check                                           
   NULL_WITH_MD5                             => { tlsver => 'SSLv2',  code => '000000', shortname => 'NULL-MD5',                      enc => 'None',     size => 0,     mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_IDEA_128_SHA                          => { tlsver => 'SSLv2',  code => '000007', shortname => 'IDEA-CBC-SHA',                  enc => 'IDEA',     size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   RC4_128_WITH_MD5                          => { tlsver => 'SSLv2',  code => '010080', shortname => 'RC4-MD5',                       enc => 'RC4',      size => 128,   mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 8,   }, tags => '',   }, 
   RC4_128_EXPORT40_WITH_MD5                 => { tlsver => 'SSLv2',  code => '020080', shortname => 'EXP-RC4-MD5',                   enc => 'RC4',      size => 40,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   RC2_128_CBC_WITH_MD5                      => { tlsver => 'SSLv2',  code => '030080', shortname => 'RC2-CBC-MD5',                   enc => 'RC2',      size => 128,   mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   RC2_128_CBC_EXPORT40_WITH_MD5             => { tlsver => 'SSLv2',  code => '040080', shortname => 'EXP-RC2-CBC-MD5',               enc => 'RC2',      size => 40,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   IDEA_128_CBC_WITH_MD5                     => { tlsver => 'SSLv2',  code => '050080', shortname => 'IDEA-CBC-MD5',                  enc => 'IDEA',     size => 128,   mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   DES_64_CBC_WITH_MD5                       => { tlsver => 'SSLv2',  code => '060040', shortname => 'DES-CBC-MD5',                   enc => 'DES',      size => 56,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   DES_64_CBC_WITH_SHA                       => { tlsver => 'SSLv2',  code => '060140', shortname => 'DES-CBC-SHA',                   enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   DES_192_EDE3_CBC_WITH_MD5                 => { tlsver => 'SSLv2',  code => '0700C0', shortname => 'DES-CBC3-MD5',                  enc => '3DES',     size => 168,   mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DES_192_EDE3_CBC_WITH_SHA                 => { tlsver => 'SSLv2',  code => '0701C0', shortname => 'DES-CBC3-SHA',                  enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   RC4_64_WITH_MD5                           => { tlsver => 'SSLv2',  code => '080080', shortname => 'RC4-64-MD5',                    enc => 'RC4',      size => 64,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 3,   }, tags => '',   }, 
   DES_64_CFB64_WITH_MD5_1                   => { tlsver => 'SSLv2',  code => 'FF0800', shortname => 'DES-CFB-M1',                    enc => 'DES',      size => 64,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 20,  }, tags => '',   }, 
   NULL                                      => { tlsver => 'SSLv2',  code => 'FF0810', shortname => 'NULL',                          enc => 'None',     size => 0,     mac => undef,    auth => 'None',     keyx => undef,        scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   NULL_WITH_NULL_NULL                       => { tlsver => 'SSLv3',  code =>   '0000', shortname => 'NULL-MD5',                      enc => 'None',     size => 0,     mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   RSA_NULL_MD5                              => { tlsver => 'SSLv3',  code =>   '0001', shortname => 'NULL-MD5',                      enc => 'None',     size => 0,     mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   RSA_NULL_SHA                              => { tlsver => 'SSLv3',  code =>   '0002', shortname => 'NULL-SHA',                      enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_RC4_40_MD5                            => { tlsver => 'SSLv3',  code =>   '0003', shortname => 'EXP-RC4-MD5',                   enc => 'RC4',      size => 40,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   RSA_RC4_128_MD5                           => { tlsver => 'SSLv3',  code =>   '0004', shortname => 'RC4-MD5',                       enc => 'RC4',      size => 128,   mac => 'MD5',    auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 8,   }, tags => '',   }, 
   RSA_RC4_128_SHA                           => { tlsver => 'SSLv3',  code =>   '0005', shortname => 'RC4-SHA',                       enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 8,   }, tags => '',   }, 
   RSA_RC2_40_MD5                            => { tlsver => 'SSLv3',  code =>   '0006', shortname => 'EXP-RC2-CBC-MD5',               enc => 'RC2',      size => 40,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   RSA_WITH_IDEA_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '0007', shortname => 'IDEA-CBC-SHA',                  enc => 'IDEA',     size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   RSA_DES_40_CBC_SHA                        => { tlsver => 'SSLv3',  code =>   '0008', shortname => 'EXP-DES-CBC-SHA',               enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA(512)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   RSA_DES_64_CBC_SHA                        => { tlsver => 'SSLv3',  code =>   '0009', shortname => 'DES-CBC-SHA',                   enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   RSA_DES_192_CBC3_SHA                      => { tlsver => 'SSLv3',  code =>   '000A', shortname => 'DES-CBC3-SHA',                  enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DH_DSS_DES_40_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '000B', shortname => 'EXP-DH-DSS-DES-CBC-SHA',        enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH(512)',    scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   DH_DSS_DES_64_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '000C', shortname => 'DH-DSS-DES-CBC-SHA',            enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'low',    osaft => 20,  }, tags => '',   }, 
   DH_DSS_DES_192_CBC3_SHA                   => { tlsver => 'SSLv3',  code =>   '000D', shortname => 'DH-DSS-DES-CBC3-SHA',           enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 80,  }, tags => '',   }, 
   DH_RSA_DES_40_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '000E', shortname => 'EXP-DH-RSA-DES-CBC-SHA',        enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'RSA',      keyx => 'DH(512)',    scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   DH_RSA_DES_64_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '000F', shortname => 'DH-RSA-DES-CBC-SHA',            enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'low',    osaft => 20,  }, tags => '',   }, 
   DH_RSA_DES_192_CBC3_SHA                   => { tlsver => 'SSLv3',  code =>   '0010', shortname => 'DH-RSA-DES-CBC3-SHA',           enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 80,  }, tags => '',   }, 
   EDH_DSS_DES_40_CBC_SHA                    => { tlsver => 'SSLv3',  code =>   '0011', shortname => 'EXP-EDH-DSS-DES-CBC-SHA',       enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH(512)',    scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   EDH_DSS_DES_64_CBC_SHA                    => { tlsver => 'SSLv3',  code =>   '0012', shortname => 'EDH-DSS-DES-CBC-SHA',           enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'LOW',    osaft => 1,   }, tags => '',   }, 
   EDH_DSS_DES_192_CBC3_SHA                  => { tlsver => 'SSLv3',  code =>   '0013', shortname => 'EDH-DSS-DES-CBC3-SHA',          enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   EDH_RSA_DES_40_CBC_SHA                    => { tlsver => 'SSLv3',  code =>   '0014', shortname => 'EXP-EDH-RSA-DES-CBC-SHA',       enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'RSA',      keyx => 'DH(512)',    scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   EDH_RSA_DES_64_CBC_SHA                    => { tlsver => 'SSLv3',  code =>   '0015', shortname => 'EDH-RSA-DES-CBC-SHA',           enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   EDH_RSA_DES_192_CBC3_SHA                  => { tlsver => 'SSLv3',  code =>   '0016', shortname => 'EDH-RSA-DES-CBC3-SHA',          enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   ADH_RC4_40_MD5                            => { tlsver => 'SSLv3',  code =>   '0017', shortname => 'EXP-ADH-RC4-MD5',               enc => 'RC4',      size => 40,    mac => 'MD5',    auth => 'None',     keyx => 'DH(512)',    scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   ADH_RC4_128_MD5                           => { tlsver => 'SSLv3',  code =>   '0018', shortname => 'ADH-RC4-MD5',                   enc => 'RC4',      size => 128,   mac => 'MD5',    auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ADH_DES_40_CBC_SHA                        => { tlsver => 'SSLv3',  code =>   '0019', shortname => 'EXP-ADH-DES-CBC-SHA',           enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'None',     keyx => 'DH(512)',    scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'export', }, 
   ADH_DES_64_CBC_SHA                        => { tlsver => 'SSLv3',  code =>   '001A', shortname => 'ADH-DES-CBC-SHA',               enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ADH_DES_192_CBC_SHA                       => { tlsver => 'SSLv3',  code =>   '001B', shortname => 'ADH-DES-CBC3-SHA',              enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   FZA_DMS_NULL_SHA                          => { tlsver => 'SSLv3',  code =>   '001C', shortname => 'FZA-NULL-SHA',                  enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'KEA',      keyx => 'FZA',        scores => { osaft_openssl => 'weak',   osaft => 11,  }, tags => '',   }, 
   FZA_DMS_FZA_SHA                           => { tlsver => 'SSLv3',  code =>   '001D', shortname => 'FZA-FZA-SHA',                   enc => 'FZA',      size => 0,     mac => 'SHA1',   auth => 'KEA',      keyx => 'FZA',        scores => { osaft_openssl => 'MEDIUM', osaft => 81,  }, tags => '',   }, 
   FZA_DMS_RC4_SHA                           => { tlsver => 'SSLv3',  code =>   '001E', shortname => 'FZA-RC4-SHA',                   enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'KEA',      keyx => 'FZA',        scores => { osaft_openssl => 'WEAK',   osaft => 11,  }, tags => '',   }, 
   KRB5_DES_64_CBC_SHA                       => { tlsver => 'SSLv3',  code =>   '001E', shortname => 'KRB5-DES-CBC-SHA',              enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   KRB5_DES_192_CBC3_SHA                     => { tlsver => 'SSLv3',  code =>   '001F', shortname => 'KRB5-DES-CBC3-SHA',             enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   KRB5_RC4_128_SHA                          => { tlsver => 'SSLv3',  code =>   '0020', shortname => 'KRB5-RC4-SHA',                  enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   KRB5_IDEA_128_CBC_SHA                     => { tlsver => 'SSLv3',  code =>   '0021', shortname => 'KRB5-IDEA-CBC-SHA',             enc => 'IDEA',     size => 128,   mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   KRB5_DES_64_CBC_MD5                       => { tlsver => 'SSLv3',  code =>   '0022', shortname => 'KRB5-DES-CBC-MD5',              enc => 'DES',      size => 56,    mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'LOW',    osaft => 20,  }, tags => '',   }, 
   KRB5_DES_192_CBC3_MD5                     => { tlsver => 'SSLv3',  code =>   '0023', shortname => 'KRB5-DES-CBC3-MD5',             enc => '3DES',     size => 168,   mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   KRB5_RC4_128_MD5                          => { tlsver => 'SSLv3',  code =>   '0024', shortname => 'KRB5-RC4-MD5',                  enc => 'RC4',      size => 128,   mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   KRB5_IDEA_128_CBC_MD5                     => { tlsver => 'SSLv3',  code =>   '0025', shortname => 'KRB5-IDEA-CBC-MD5',             enc => 'IDEA',     size => 128,   mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'MEDIUM', osaft => 80,  }, tags => '',   }, 
   KRB5_DES_40_CBC_SHA                       => { tlsver => 'SSLv3',  code =>   '0026', shortname => 'EXP-KRB5-DES-CBC-SHA',          enc => 'DES',      size => 40,    mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   KRB5_RC2_40_CBC_SHA                       => { tlsver => 'SSLv3',  code =>   '0027', shortname => 'EXP-KRB5-RC2-CBC-SHA',          enc => 'RC2',      size => 40,    mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   KRB5_RC4_40_SHA                           => { tlsver => 'SSLv3',  code =>   '0028', shortname => 'EXP-KRB5-RC4-SHA',              enc => 'RC4',      size => 40,    mac => 'SHA1',   auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   KRB5_DES_40_CBC_MD5                       => { tlsver => 'SSLv3',  code =>   '0029', shortname => 'EXP-KRB5-DES-CBC-MD5',          enc => 'DES',      size => 40,    mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   KRB5_RC2_40_CBC_MD5                       => { tlsver => 'SSLv3',  code =>   '002A', shortname => 'EXP-KRB5-RC2-CBC-MD5',          enc => 'RC2',      size => 40,    mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   KRB5_RC4_40_MD5                           => { tlsver => 'SSLv3',  code =>   '002B', shortname => 'EXP-KRB5-RC4-MD5',              enc => 'RC4',      size => 40,    mac => 'MD5',    auth => 'KRB5',     keyx => 'KRB5',       scores => { osaft_openssl => 'WEAK',   osaft => 0,   }, tags => 'export', }, 
   RSA_WITH_AES_128_SHA                      => { tlsver => 'SSLv3',  code =>   '002F', shortname => 'AES128-SHA',                    enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DHE_DSS_WITH_AES_128_SHA                  => { tlsver => 'SSLv3',  code =>   '0032', shortname => 'DHE-DSS-AES128-SHA',            enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_128_SHA                  => { tlsver => 'SSLv3',  code =>   '0033', shortname => 'DHE-RSA-AES128-SHA',            enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   ADH_WITH_AES_128_SHA                      => { tlsver => 'SSLv3',  code =>   '0034', shortname => 'ADH-AES128-SHA',                enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_WITH_AES_256_SHA                      => { tlsver => 'SSLv3',  code =>   '0035', shortname => 'AES256-SHA',                    enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   DHE_DSS_WITH_AES_256_SHA                  => { tlsver => 'SSLv3',  code =>   '0038', shortname => 'DHE-DSS-AES256-SHA',            enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   DHE_RSA_WITH_AES_256_SHA                  => { tlsver => 'SSLv3',  code =>   '0039', shortname => 'DHE-RSA-AES256-SHA',            enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   ADH_WITH_AES_256_SHA                      => { tlsver => 'SSLv3',  code =>   '003A', shortname => 'ADH-AES256-SHA',                enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_WITH_CAMELLIA_128_CBC_SHA             => { tlsver => 'SSLv3',  code =>   '0041', shortname => 'CAMELLIA128-SHA',               enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DH_DSS_WITH_CAMELLIA_128_CBC_SHA          => { tlsver => 'SSLv3',  code =>   '0042', shortname => 'DH-DSS-CAMELLIA128-SHA',        enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 81,  }, tags => '',   }, 
   DH_RSA_WITH_CAMELLIA_128_CBC_SHA          => { tlsver => 'SSLv3',  code =>   '0043', shortname => 'DH-RSA-CAMELLIA128-SHA',        enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 81,  }, tags => '',   }, 
   DHE_DSS_WITH_CAMELLIA_128_CBC_SHA         => { tlsver => 'SSLv3',  code =>   '0044', shortname => 'DHE-DSS-CAMELLIA128-SHA',       enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   DHE_RSA_WITH_CAMELLIA_128_CBC_SHA         => { tlsver => 'SSLv3',  code =>   '0045', shortname => 'DHE-RSA-CAMELLIA128-SHA',       enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 80,  }, tags => '',   }, 
   ADH_WITH_CAMELLIA_128_CBC_SHA             => { tlsver => 'SSLv3',  code =>   '0046', shortname => 'ADH-CAMELLIA128-SHA',           enc => 'CAMELLIA', size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_EXPORT1024_WITH_RC4_56_MD5            => { tlsver => 'SSLv3',  code =>   '0060', shortname => 'EXP1024-RC4-MD5',               enc => 'RC4',      size => 56,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(1024)',  scores => { osaft_openssl => 'WEAK',   osaft => 1,   }, tags => 'export', }, 
   RSA_EXPORT1024_WITH_RC2_CBC_56_MD5        => { tlsver => 'SSLv3',  code =>   '0061', shortname => 'EXP1024-RC2-CBC-MD5',           enc => 'RC2',      size => 56,    mac => 'MD5',    auth => 'RSA',      keyx => 'RSA(1024)',  scores => { osaft_openssl => 'WEAK',   osaft => 1,   }, tags => 'export', }, 
   RSA_EXPORT1024_WITH_DES_CBC_SHA           => { tlsver => 'SSLv3',  code =>   '0062', shortname => 'EXP1024-DES-CBC-SHA',           enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA(1024)',  scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA       => { tlsver => 'SSLv3',  code =>   '0063', shortname => 'EXP1024-DHE-DSS-DES-CBC-SHA',   enc => 'DES',      size => 56,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH(1024)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   RSA_EXPORT1024_WITH_RC4_56_SHA            => { tlsver => 'SSLv3',  code =>   '0064', shortname => 'EXP1024-RC4-SHA',               enc => 'RC4',      size => 56,    mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA(1024)',  scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   DHE_DSS_EXPORT1024_WITH_RC4_56_SHA        => { tlsver => 'SSLv3',  code =>   '0065', shortname => 'EXP1024-DHE-DSS-RC4-SHA',       enc => 'RC4',      size => 56,    mac => 'SHA1',   auth => 'DSS',      keyx => 'DH(1024)',   scores => { osaft_openssl => 'WEAK',   osaft => 2,   }, tags => 'export', }, 
   DHE_DSS_WITH_RC4_128_SHA                  => { tlsver => 'SSLv3',  code =>   '0066', shortname => 'DHE-DSS-RC4-SHA',               enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 80,  }, tags => '',   }, 
   GOSTR341094_WITH_28147_CNT_IMIT           => { tlsver => 'SSLv3',  code =>   '0080', shortname => 'GOST94-GOST89-GOST89',          enc => 'GOST89',   size => 256,   mac => 'GOST89', auth => 'GOST94',   keyx => 'VKO',        scores => {                            osaft => 1,   }, tags => '',   }, 
   GOSTR341001_WITH_28147_CNT_IMIT           => { tlsver => 'SSLv3',  code =>   '0081', shortname => 'GOST2001-GOST89-GOST89',        enc => 'GOST89',   size => 256,   mac => 'GOST89', auth => 'GOST01',   keyx => 'VKO',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_WITH_CAMELLIA_256_CBC_SHA             => { tlsver => 'SSLv3',  code =>   '0084', shortname => 'CAMELLIA256-SHA',               enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   DH_DSS_WITH_CAMELLIA_256_CBC_SHA          => { tlsver => 'SSLv3',  code =>   '0085', shortname => 'DH-DSS-CAMELLIA256-SHA',        enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DH_RSA_WITH_CAMELLIA_256_CBC_SHA          => { tlsver => 'SSLv3',  code =>   '0086', shortname => 'DH-RSA-CAMELLIA256-SHA',        enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_DSS_WITH_CAMELLIA_256_CBC_SHA         => { tlsver => 'SSLv3',  code =>   '0087', shortname => 'DHE-DSS-CAMELLIA256-SHA',       enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   DHE_RSA_WITH_CAMELLIA_256_CBC_SHA         => { tlsver => 'SSLv3',  code =>   '0088', shortname => 'DHE-RSA-CAMELLIA256-SHA',       enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 100, }, tags => '',   }, 
   ADH_WITH_CAMELLIA_256_CBC_SHA             => { tlsver => 'SSLv3',  code =>   '0089', shortname => 'ADH-CAMELLIA256-SHA',           enc => 'CAMELLIA', size => 256,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   PSK_WITH_RC4_128_SHA                      => { tlsver => 'SSLv3',  code =>   '008A', shortname => 'PSK-RC4-SHA',                   enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'MEDIUM', osaft => 1,   }, tags => '',   }, 
   PSK_WITH_3DES_EDE_CBC_SHA                 => { tlsver => 'SSLv3',  code =>   '008B', shortname => 'PSK-3DES-EDE-CBC-SHA',          enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'HIGH',   osaft => 1,   }, tags => '',   }, 
   PSK_WITH_AES_128_CBC_SHA                  => { tlsver => 'SSLv3',  code =>   '008C', shortname => 'PSK-AES128-CBC-SHA',            enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'HIGH',   osaft => 1,   }, tags => '',   }, 
   PSK_WITH_AES_256_CBC_SHA                  => { tlsver => 'SSLv3',  code =>   '008D', shortname => 'PSK-AES256-CBC-SHA',            enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'HIGH',   osaft => 1,   }, tags => '',   }, 
   RSA_WITH_SEED_SHA                         => { tlsver => 'SSLv3',  code =>   '0096', shortname => 'SEED-SHA',                      enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'MEDIUM', osaft => 11,  }, tags => 'OSX', }, 
   DH_DSS_WITH_SEED_SHA                      => { tlsver => 'SSLv3',  code =>   '0097', shortname => 'DH-DSS-SEED-SHA',               enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DH_RSA_WITH_SEED_SHA                      => { tlsver => 'SSLv3',  code =>   '0098', shortname => 'DH-RSA-SEED-SHA',               enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DHE_DSS_WITH_SEED_SHA                     => { tlsver => 'SSLv3',  code =>   '0099', shortname => 'DHE-DSS-SEED-SHA',              enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'MEDIUM', osaft => 81,  }, tags => 'OSX', }, 
   DHE_RSA_WITH_SEED_SHA                     => { tlsver => 'SSLv3',  code =>   '009A', shortname => 'DHE-RSA-SEED-SHA',              enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'MEDIUM', osaft => 81,  }, tags => 'OSX', }, 
   ADH_WITH_SEED_SHA                         => { tlsver => 'SSLv3',  code =>   '009B', shortname => 'ADH-SEED-SHA',                  enc => 'SEED',     size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => 'OSX', }, 
   ECDH_ECDSA_WITH_NULL_SHA                  => { tlsver => 'SSLv3',  code =>   'C001', shortname => 'ECDH-ECDSA-NULL-SHA',           enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ECDH_ECDSA_WITH_RC4_128_SHA               => { tlsver => 'SSLv3',  code =>   'C002', shortname => 'ECDH-ECDSA-RC4-SHA',            enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'weak',   osaft => 81,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_DES_192_CBC3_SHA          => { tlsver => 'SSLv3',  code =>   'C003', shortname => 'ECDH-ECDSA-DES-CBC3-SHA',       enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_128_CBC_SHA           => { tlsver => 'SSLv3',  code =>   'C004', shortname => 'ECDH-ECDSA-AES128-SHA',         enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_256_CBC_SHA           => { tlsver => 'SSLv3',  code =>   'C005', shortname => 'ECDH-ECDSA-AES256-SHA',         enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_NULL_SHA                 => { tlsver => 'SSLv3',  code =>   'C006', shortname => 'ECDHE-ECDSA-NULL-SHA',          enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ECDHE_ECDSA_WITH_RC4_128_SHA              => { tlsver => 'SSLv3',  code =>   'C007', shortname => 'ECDHE-ECDSA-RC4-SHA',           enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 81,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_DES_192_CBC3_SHA         => { tlsver => 'SSLv3',  code =>   'C008', shortname => 'ECDHE-ECDSA-DES-CBC3-SHA',      enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_128_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C009', shortname => 'ECDHE-ECDSA-AES128-SHA',        enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_256_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C00A', shortname => 'ECDHE-ECDSA-AES256-SHA',        enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDH_RSA_WITH_NULL_SHA                    => { tlsver => 'SSLv3',  code =>   'C00B', shortname => 'ECDH-RSA-NULL-SHA',             enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ECDH_RSA_WITH_RC4_128_SHA                 => { tlsver => 'SSLv3',  code =>   'C00C', shortname => 'ECDH-RSA-RC4-SHA',              enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'weak',   osaft => 81,  }, tags => '',   }, 
   ECDH_RSA_WITH_DES_192_CBC3_SHA            => { tlsver => 'SSLv3',  code =>   'C00D', shortname => 'ECDH-RSA-DES-CBC3-SHA',         enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_128_CBC_SHA             => { tlsver => 'SSLv3',  code =>   'C00E', shortname => 'ECDH-RSA-AES128-SHA',           enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_256_CBC_SHA             => { tlsver => 'SSLv3',  code =>   'C00F', shortname => 'ECDH-RSA-AES256-SHA',           enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDHE_RSA_WITH_NULL_SHA                   => { tlsver => 'SSLv3',  code =>   'C010', shortname => 'ECDHE-RSA-NULL-SHA',            enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ECDHE_RSA_WITH_RC4_128_SHA                => { tlsver => 'SSLv3',  code =>   'C011', shortname => 'ECDHE-RSA-RC4-SHA',             enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 81,  }, tags => '',   }, 
   ECDHE_RSA_WITH_DES_192_CBC3_SHA           => { tlsver => 'SSLv3',  code =>   'C012', shortname => 'ECDHE-RSA-DES-CBC3-SHA',        enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_128_CBC_SHA            => { tlsver => 'SSLv3',  code =>   'C013', shortname => 'ECDHE-RSA-AES128-SHA',          enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_256_CBC_SHA            => { tlsver => 'SSLv3',  code =>   'C014', shortname => 'ECDHE-RSA-AES256-SHA',          enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 11,  }, tags => '',   }, 
   ECDH_anon_WITH_NULL_SHA                   => { tlsver => 'SSLv3',  code =>   'C015', shortname => 'AECDH-NULL-SHA',                enc => 'None',     size => 0,     mac => 'SHA1',   auth => 'None',     keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   ECDH_anon_WITH_RC4_128_SHA                => { tlsver => 'SSLv3',  code =>   'C016', shortname => 'AECDH-RC4-SHA',                 enc => 'RC4',      size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 11,  }, tags => '',   }, 
   ECDH_anon_WITH_DES_192_CBC3_SHA           => { tlsver => 'SSLv3',  code =>   'C017', shortname => 'AECDH-DES-CBC3-SHA',            enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'None',     keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 11,  }, tags => '',   }, 
   ECDH_anon_WITH_AES_128_CBC_SHA            => { tlsver => 'SSLv3',  code =>   'C018', shortname => 'AECDH-AES128-SHA',              enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 11,  }, tags => '',   }, 
   ECDH_anon_WITH_AES_256_CBC_SHA            => { tlsver => 'SSLv3',  code =>   'C019', shortname => 'AECDH-AES256-SHA',              enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'None',     keyx => 'ECDH',       scores => { osaft_openssl => 'weak',   osaft => 11,  }, tags => '',   }, 
   SRP_SHA_WITH_3DES_EDE_CBC_SHA             => { tlsver => 'SSLv3',  code =>   'C01A', shortname => 'SRP-3DES-EDE-CBC-SHA',          enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'None',     keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         => { tlsver => 'SSLv3',  code =>   'C01B', shortname => 'SRP-RSA-3DES-EDE-CBC-SHA',      enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         => { tlsver => 'SSLv3',  code =>   'C01C', shortname => 'SRP-DSS-3DES-EDE-CBC-SHA',      enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'DSS',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_WITH_AES_128_CBC_SHA              => { tlsver => 'SSLv3',  code =>   'C01D', shortname => 'SRP-AES-128-CBC-SHA',           enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'None',     keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_RSA_WITH_AES_128_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C01E', shortname => 'SRP-RSA-AES-128-CBC-SHA',       enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_DSS_WITH_AES_128_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C01F', shortname => 'SRP-DSS-AES-128-CBC-SHA',       enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_WITH_AES_256_CBC_SHA              => { tlsver => 'SSLv3',  code =>   'C020', shortname => 'SRP-AES-256-CBC-SHA',           enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'None',     keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_RSA_WITH_AES_256_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C021', shortname => 'SRP-RSA-AES-256-CBC-SHA',       enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   SRP_SHA_DSS_WITH_AES_256_CBC_SHA          => { tlsver => 'SSLv3',  code =>   'C022', shortname => 'SRP-DSS-AES-256-CBC-SHA',       enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'DSS',      keyx => 'SRP',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   RSA_FIPS_WITH_3DES_EDE_CBC_SHA            => { tlsver => 'SSLv3',  code =>   'FEE0', shortname => 'RSA-FIPS-3DES-EDE-SHA',         enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA_FIPS', keyx => 'RSA_FIPS',   scores => { osaft_openssl => 'high',   osaft => 99,  }, tags => '',   }, 
   RSA_FIPS_WITH_DES_CBC_SHA                 => { tlsver => 'SSLv3',  code =>   'FEE1', shortname => 'RSA-FIPS-DES-CBC-SHA',          enc => 'DES_CBC',  size => 56,    mac => 'SHA1',   auth => 'RSA_FIPS', keyx => 'RSA_FIPS',   scores => { osaft_openssl => 'low',    osaft => 20,  }, tags => '',   }, 
   RSA_FIPS_WITH_DES_CBC_SHA_alias           => { tlsver => 'SSLv3',  code =>   'FEFE', shortname => 'RSA-FIPS-DES-CBC-SHA',          enc => 'DES_CBC',  size => 56,    mac => 'SHA1',   auth => 'RSA_FIPS', keyx => 'RSA_FIPS',   scores => { osaft_openssl => 'low',    osaft => 20,  }, tags => '',   }, 
   RSA_FIPS_WITH_3DES_EDE_CBC_SHA_alias      => { tlsver => 'SSLv3',  code =>   'FEFF', shortname => 'RSA-FIPS-3DES-EDE-SHA',         enc => '3DES',     size => 168,   mac => 'SHA1',   auth => 'RSA_FIPS', keyx => 'RSA_FIPS',   scores => { osaft_openssl => 'high',   osaft => 99,  }, tags => '',   }, 
   __GOST94_NULL_GOST94                      => { tlsver => 'SSLv3',  code =>   'FF00', shortname => 'GOST94-NULL-GOST94',            enc => 'None',     size => 0,     mac => 'GOST94', auth => 'GOST94',   keyx => 'VKO',        scores => {                            osaft => 1,   }, tags => '',   }, 
   __GOST2001_NULL_GOST94                    => { tlsver => 'SSLv3',  code =>   'FF01', shortname => 'GOST2001-NULL-GOST94',          enc => 'None',     size => 0,     mac => 'GOST94', auth => 'GOST01',   keyx => 'VKO',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_WITH_NULL_SHA256                      => { tlsver => 'TLSv12', code =>   '003B', shortname => 'NULL-SHA256',                   enc => 'None',     size => 0,     mac => 'SHA256', auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'weak',   osaft => 0,   }, tags => '',   }, 
   RSA_WITH_AES_128_SHA256                   => { tlsver => 'TLSv12', code =>   '003C', shortname => 'AES128-SHA256',                 enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_256_SHA256                   => { tlsver => 'TLSv12', code =>   '003D', shortname => 'AES256-SHA256',                 enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DH_DSS_WITH_AES_128_SHA256                => { tlsver => 'TLSv12', code =>   '003E', shortname => 'DH-DSS-AES128-SHA256',          enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DH_RSA_WITH_AES_128_SHA256                => { tlsver => 'TLSv12', code =>   '003F', shortname => 'DH-RSA-AES128-SHA256',          enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_DSS_WITH_AES_128_SHA256               => { tlsver => 'TLSv12', code =>   '0040', shortname => 'DHE-DSS-AES128-SHA256',         enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_128_SHA256               => { tlsver => 'TLSv12', code =>   '0067', shortname => 'DHE-RSA-AES128-SHA256',         enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DH_DSS_WITH_AES_256_SHA256                => { tlsver => 'TLSv12', code =>   '0068', shortname => 'DH-DSS-AES256-SHA256',          enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DH_RSA_WITH_AES_256_SHA256                => { tlsver => 'TLSv12', code =>   '0069', shortname => 'DH-RSA-AES256-SHA256',          enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_DSS_WITH_AES_256_SHA256               => { tlsver => 'TLSv12', code =>   '006A', shortname => 'DHE-DSS-AES256-SHA256',         enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_256_SHA256               => { tlsver => 'TLSv12', code =>   '006B', shortname => 'DHE-RSA-AES256-SHA256',         enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ADH_WITH_AES_128_SHA256                   => { tlsver => 'TLSv12', code =>   '006C', shortname => 'ADH-AES128-SHA256',             enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 10,  }, tags => '',   }, 
   ADH_WITH_AES_256_SHA256                   => { tlsver => 'TLSv12', code =>   '006D', shortname => 'ADH-AES256-SHA256',             enc => 'AES',      size => 256,   mac => 'SHA256', auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 10,  }, tags => '',   }, 
   RSA_WITH_AES_128_GCM_SHA256               => { tlsver => 'TLSv12', code =>   '009C', shortname => 'AES128-GCM-SHA256',             enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_256_GCM_SHA384               => { tlsver => 'TLSv12', code =>   '009D', shortname => 'AES256-GCM-SHA384',             enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_128_GCM_SHA256           => { tlsver => 'TLSv12', code =>   '009E', shortname => 'DHE-RSA-AES128-GCM-SHA256',     enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_256_GCM_SHA384           => { tlsver => 'TLSv12', code =>   '009F', shortname => 'DHE-RSA-AES256-GCM-SHA384',     enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DH_RSA_WITH_AES_128_GCM_SHA256            => { tlsver => 'TLSv12', code =>   '00A0', shortname => 'DH-RSA-AES128-GCM-SHA256',      enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DH_RSA_WITH_AES_256_GCM_SHA384            => { tlsver => 'TLSv12', code =>   '00A1', shortname => 'DH-RSA-AES256-GCM-SHA384',      enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_DSS_WITH_AES_128_GCM_SHA256           => { tlsver => 'TLSv12', code =>   '00A2', shortname => 'DHE-DSS-AES128-GCM-SHA256',     enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DHE_DSS_WITH_AES_256_GCM_SHA384           => { tlsver => 'TLSv12', code =>   '00A3', shortname => 'DHE-DSS-AES256-GCM-SHA384',     enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   DH_DSS_WITH_AES_128_GCM_SHA256            => { tlsver => 'TLSv12', code =>   '00A4', shortname => 'DH-DSS-AES128-GCM-SHA256',      enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DH_DSS_WITH_AES_256_GCM_SHA384            => { tlsver => 'TLSv12', code =>   '00A5', shortname => 'DH-DSS-AES256-GCM-SHA384',      enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   ADH_WITH_AES_128_GCM_SHA256               => { tlsver => 'TLSv12', code =>   '00A6', shortname => 'ADH-AES128-GCM-SHA256',         enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 10,  }, tags => '',   }, 
   ADH_WITH_AES_256_GCM_SHA384               => { tlsver => 'TLSv12', code =>   '00A7', shortname => 'ADH-AES256-GCM-SHA384',         enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'None',     keyx => 'DH',         scores => { osaft_openssl => 'weak',   osaft => 10,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_128_SHA256           => { tlsver => 'TLSv12', code =>   'C023', shortname => 'ECDHE-ECDSA-AES128-SHA256',     enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_256_SHA384           => { tlsver => 'TLSv12', code =>   'C024', shortname => 'ECDHE-ECDSA-AES256-SHA384',     enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_128_SHA256            => { tlsver => 'TLSv12', code =>   'C025', shortname => 'ECDH-ECDSA-AES128-SHA256',      enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_256_SHA384            => { tlsver => 'TLSv12', code =>   'C026', shortname => 'ECDH-ECDSA-AES256-SHA384',      enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_128_SHA256             => { tlsver => 'TLSv12', code =>   'C027', shortname => 'ECDHE-RSA-AES128-SHA256',       enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_256_SHA384             => { tlsver => 'TLSv12', code =>   'C028', shortname => 'ECDHE-RSA-AES256-SHA384',       enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_128_SHA256              => { tlsver => 'TLSv12', code =>   'C029', shortname => 'ECDH-RSA-AES128-SHA256',        enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_256_SHA384              => { tlsver => 'TLSv12', code =>   'C02A', shortname => 'ECDH-RSA-AES256-SHA384',        enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       => { tlsver => 'TLSv12', code =>   'C02B', shortname => 'ECDHE-ECDSA-AES128-GCM-SHA256', enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       => { tlsver => 'TLSv12', code =>   'C02C', shortname => 'ECDHE-ECDSA-AES256-GCM-SHA384', enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_128_GCM_SHA256        => { tlsver => 'TLSv12', code =>   'C02D', shortname => 'ECDH-ECDSA-AES128-GCM-SHA256',  enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_ECDSA_WITH_AES_256_GCM_SHA384        => { tlsver => 'TLSv12', code =>   'C02E', shortname => 'ECDH-ECDSA-AES256-GCM-SHA384',  enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'ECDH',     keyx => 'ECDH/ECDSA', scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_128_GCM_SHA256         => { tlsver => 'TLSv12', code =>   'C02F', shortname => 'ECDHE-RSA-AES128-GCM-SHA256',   enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDHE_RSA_WITH_AES_256_GCM_SHA384         => { tlsver => 'TLSv12', code =>   'C030', shortname => 'ECDHE-RSA-AES256-GCM-SHA384',   enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'ECDH',       scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_128_GCM_SHA256          => { tlsver => 'TLSv12', code =>   'C031', shortname => 'ECDH-RSA-AES128-GCM-SHA256',    enc => 'AESGCM',   size => 128,   mac => 'AEAD',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   ECDH_RSA_WITH_AES_256_GCM_SHA384          => { tlsver => 'TLSv12', code =>   'C032', shortname => 'ECDH-RSA-AES256-GCM-SHA384',    enc => 'AESGCM',   size => 256,   mac => 'AEAD',   auth => 'ECDH',     keyx => 'ECDH/RSA',   scores => { osaft_openssl => 'HIGH',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_128_CCM                      => { tlsver => 'TLSv12', code =>   'C09C', shortname => 'RSA-AES128-CCM',                enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_256_CCM                      => { tlsver => 'TLSv12', code =>   'C09D', shortname => 'RSA-AES256-CCM',                enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_128_CCM                  => { tlsver => 'TLSv12', code =>   'C09E', shortname => 'DHE-RSA-AES128-CCM',            enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_256_CCM                  => { tlsver => 'TLSv12', code =>   'C09F', shortname => 'DHE-RSA-AES256-CCM',            enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_128_CCM_8                    => { tlsver => 'TLSv12', code =>   'C0A0', shortname => 'RSA-AES128-CCM-8',              enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   RSA_WITH_AES_256_CCM_8                    => { tlsver => 'TLSv12', code =>   'C0A1', shortname => 'RSA-AES256-CCM-8',              enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'RSA',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_128_CCM_8                => { tlsver => 'TLSv12', code =>   'C0A2', shortname => 'DHE-RSA-AES128-CCM-8',          enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_RSA_WITH_AES_256_CCM_8                => { tlsver => 'TLSv12', code =>   'C0A3', shortname => 'DHE-RSA-AES256-CCM-8',          enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   PSK_WITH_AES_128_CCM                      => { tlsver => 'TLSv12', code =>   'C0A4', shortname => 'PSK-RSA-AES128-CCM',            enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   PSK_WITH_AES_256_CCM                      => { tlsver => 'TLSv12', code =>   'C0A5', shortname => 'PSK-RSA-AES256-CCM',            enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   PSK_WITH_AES_128_CCM_8                    => { tlsver => 'TLSv12', code =>   'C0A8', shortname => 'PSK-RSA-AES128-CCM-8',          enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   PSK_WITH_AES_256_CCM_8                    => { tlsver => 'TLSv12', code =>   'C0A9', shortname => 'PSK-RSA-AES256-CCM-8',          enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'PSK',      keyx => 'PSK',        scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_128_CCM              => { tlsver => 'TLSv12', code =>   'C0AC', shortname => 'ECDHE-RSA-AES128-CCM',          enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_256_CCM              => { tlsver => 'TLSv12', code =>   'C0AD', shortname => 'ECDHE-RSA-AES256-CCM',          enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_128_CCM_8            => { tlsver => 'TLSv12', code =>   'C0AE', shortname => 'ECDHE-RSA-AES128-CCM-8',        enc => 'AESCCM',   size => 128,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   ECDHE_ECDSA_WITH_AES_256_CCM_8            => { tlsver => 'TLSv12', code =>   'C0AF', shortname => 'ECDHE-RSA-AES256-CCM-8',        enc => 'AESCCM',   size => 256,   mac => 'AEAD',   auth => 'ECDSA',    keyx => 'ECDH',       scores => { osaft_openssl => 'high',   osaft => 91,  }, tags => '',   }, 
   DHE_PSK_WITH_NULL_SHA                     => { tlsver => undef,    code =>   '002D', shortname => 'DHE-PSK-SHA',                   enc => undef,      size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'DHE',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_NULL_SHA                     => { tlsver => undef,    code =>   '002E', shortname => 'RSA-PSK-SHA',                   enc => undef,      size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'RSA',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DH_DSS_WITH_AES_128_SHA                   => { tlsver => undef,    code =>   '0030', shortname => 'DH-DSS-AES128-SHA',             enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DH_RSA_WITH_AES_128_SHA                   => { tlsver => undef,    code =>   '0031', shortname => 'DH-RSA-AES128-SHA',             enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DH_DSS_WITH_AES_256_SHA                   => { tlsver => undef,    code =>   '0036', shortname => 'DH-DSS-AES256-SHA',             enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'DSS',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DH_RSA_WITH_AES_256_SHA                   => { tlsver => undef,    code =>   '0037', shortname => 'DH-RSA-AES256-SHA',             enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'RSA',      keyx => 'DH',         scores => { osaft_openssl => 'medium', osaft => 81,  }, tags => '',   }, 
   DHE_PSK_WITH_RC4_128_SHA                  => { tlsver => undef,    code =>   '008E', shortname => 'DHE-PSK-RC4-SHA',               enc => 'RC4',      size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_3DES_EDE_CBC_SHA             => { tlsver => undef,    code =>   '008F', shortname => 'DHE-PSK-3DES-SHA',              enc => '3DES',     size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_128_CBC_SHA              => { tlsver => undef,    code =>   '0090', shortname => 'DHE-PSK-AES128-SHA',            enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_256_CBC_SHA              => { tlsver => undef,    code =>   '0091', shortname => 'DHE-PSK-AES256-SHA',            enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_RC4_128_SHA                  => { tlsver => undef,    code =>   '0092', shortname => 'RSA-PSK-RC4-SHA',               enc => 'RC4',      size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_3DES_EDE_CBC_SHA             => { tlsver => undef,    code =>   '0093', shortname => 'RSA-PSK-3DES-SHA',              enc => '3DES',     size => undef, mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_128_CBC_SHA              => { tlsver => undef,    code =>   '0094', shortname => 'RSA-PSK-AES128-SHA',            enc => 'AES',      size => 128,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_256_CBC_SHA              => { tlsver => undef,    code =>   '0095', shortname => 'RSA-PSK-AES256-SHA',            enc => 'AES',      size => 256,   mac => 'SHA1',   auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_128_GCM_SHA256           => { tlsver => undef,    code =>   '00AA', shortname => 'DHE-PSK-AES128-GCM-SHA256',     enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_256_GCM_SHA384           => { tlsver => undef,    code =>   '00AB', shortname => 'DHE-PSK-AES256-GCM-SHA384',     enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_128_GCM_SHA256           => { tlsver => undef,    code =>   '00AC', shortname => 'RSA-PSK-AES128-GCM-SHA256',     enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_256_GCM_SHA384           => { tlsver => undef,    code =>   '00AD', shortname => 'RSA-PSK-AES256-GCM-SHA384',     enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   PSK_WITH_AES_128_CBC_SHA256               => { tlsver => undef,    code =>   '00AE', shortname => 'PSK-AES128-SHA256',             enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   PSK_WITH_AES_256_CBC_SHA384               => { tlsver => undef,    code =>   '00AF', shortname => 'PSK-AES256-SHA384',             enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   PSK_WITH_NULL_SHA256                      => { tlsver => undef,    code =>   '00B0', shortname => 'PSK-SHA256',                    enc => 'AES',      size => undef, mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   PSK_WITH_NULL_SHA384                      => { tlsver => undef,    code =>   '00B1', shortname => 'PSK-SHA384',                    enc => 'AES',      size => undef, mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_256_CBC_SHA256           => { tlsver => undef,    code =>   '00B2', shortname => 'DHE-PSK-AES128-SHA256',         enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_AES_256_CBC_SHA384           => { tlsver => undef,    code =>   '00B3', shortname => 'DHE-PSK-AES256-SHA384',         enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_NULL_SHA256                  => { tlsver => undef,    code =>   '00B4', shortname => 'DHE-PSK-SHA256',                enc => 'AES',      size => undef, mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_PSK_WITH_NULL_SHA384                  => { tlsver => undef,    code =>   '00B5', shortname => 'DHE-PSK-SHA384',                enc => 'AES',      size => undef, mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_256_CBC_SHA256           => { tlsver => undef,    code =>   '00B6', shortname => 'RSA-PSK-AES128-SHA256',         enc => 'AES',      size => 128,   mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_AES_256_CBC_SHA384           => { tlsver => undef,    code =>   '00B7', shortname => 'RSA-PSK-AES256-SHA384',         enc => 'AES',      size => 256,   mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_NULL_SHA256                  => { tlsver => undef,    code =>   '00B8', shortname => 'RSA-PSK-SHA256',                enc => 'AES',      size => undef, mac => 'SHA256', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   RSA_PSK_WITH_NULL_SHA384                  => { tlsver => undef,    code =>   '00B9', shortname => 'RSA-PSK-SHA384',                enc => 'AES',      size => undef, mac => 'SHA384', auth => 'PSK',      keyx => 'PSK',        scores => {                            osaft => 1,   }, tags => '',   }, 
   ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   => { tlsver => undef,    code =>   'CC13', shortname => 'ECDHE-RSA-CHACHA20-POLY1305',   enc => 'ChaCha20', size => 256,   mac => 'RSA',    auth => 'RSA',      keyx => 'ECDH',       scores => {                            osaft => 1,   }, tags => '',   }, 
   ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => { tlsver => undef,    code =>   'CC14', shortname => 'ECDHE-ECDSA-CHACHA20-POLY1305', enc => 'ChaCha20', size => 256,   mac => 'ECDSA',  auth => 'ECDSA',    keyx => 'ECDH',       scores => {                            osaft => 1,   }, tags => '',   }, 
   DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     => { tlsver => undef,    code =>   'CC15', shortname => 'DHE-RSA-CHACHA20-POLY1305',     enc => 'ChaCha20', size => 256,   mac => 'RSA',    auth => 'RSA',      keyx => 'DH',         scores => {                            osaft => 1,   }, tags => '',   }, 
   PSK_WITH_NULL_SHA                         => { tlsver => undef,    code =>   '002C', shortname => 'PSK-SHA',                       enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   EMPTY_RENEGOTIATION_INFO_SCSV             => { tlsver => undef,    code =>   '00FF', shortname => 'SCSV',                          enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   TLS_FALLBACK_SCSV                         => { tlsver => undef,    code =>   '5600', shortname => 'SCSV',                          enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   __GOST_MD5                                => { tlsver => undef,    code =>   'FF00', shortname => 'GOST-MD5',                      enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   __GOST_GOST94                             => { tlsver => undef,    code =>   'FF01', shortname => 'GOST-GOST94',                   enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_CERT_X509                            => { tlsver => undef,    code => '800001', shortname => 'PCT_SSL_CERT_TYPE',             enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_CERT_X509_CHAIN                      => { tlsver => undef,    code => '800003', shortname => 'PCT_SSL_CERT_TYPE',             enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_HASH_MD5                             => { tlsver => undef,    code => '810001', shortname => 'PCT_SSL_HASH_TYPE',             enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_HASH_SHA                             => { tlsver => undef,    code => '810003', shortname => 'PCT_SSL_HASH_TYPE',             enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_EXCH_RSA_PKCS1                       => { tlsver => undef,    code => '820003', shortname => 'PCT_SSL_EXCH_TYPE',             enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT1_CIPHER_RC4                           => { tlsver => undef,    code => '823004', shortname => 'PCT_SSL_CIPHER_TYPE_1ST_HALF',  enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   'PCT1_ENC_BITS_40|PCT1_MAC_BITS_128'      => { tlsver => undef,    code => '842840', shortname => 'PCT_SSL_CIPHER_TYPE_2ND_HALF',  enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   'PCT1_ENC_BITS_128|PCT1_MAC_BITS_128'     => { tlsver => undef,    code => '848040', shortname => 'PCT_SSL_CIPHER_TYPE_2ND_HALF',  enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   PCT_VERSION_1                             => { tlsver => undef,    code => '8F8001', shortname => 'PCT_SSL_COMPAT',                enc => undef,      size => undef, mac => undef,    auth => undef,      keyx => undef,        scores => {                                          }, tags => '',   }, 
   );

#>>>


my %ciphers_by_code;
my %ciphers_by_name;
my %ciphers_by_tag;

my $init;

_init();

sub _init
   {
   die "already initialised!\n" if $init;
   $init = 1;

   return if $COMPILING;                           # no init when called with -c CLI switch

   #
   # bettercrypto scores
   # https://bettercrypto.org
   #
   my %bettercrypto_a = map { $ARG => 1 } qw(
      DHE-RSA-AES256-GCM-SHA384
      DHE-RSA-AES256-SHA256
      ECDHE-RSA-AES256-GCM-SHA384
      ECDHE-RSA-AES256-SHA384
      );

   my %bettercrypto_b = map { $ARG => 1 } (
      keys %bettercrypto_a,
      qw(
         DHE-RSA-AES128-GCM-SHA256
         DHE-RSA-AES128-SHA256
         ECDHE-RSA-AES128-GCM-SHA256
         ECDHE-RSA-AES128-SHA256
         DHE-RSA-CAMELLIA256-SHA
         DHE-RSA-AES256-SHA
         ECDHE-RSA-AES256-SHA
         DHE-RSA-CAMELLIA128-SHA
         DHE-RSA-AES128-SHA
         ECDHE-RSA-AES128-SHA
         CAMELLIA256-SHA
         AES256-SHA
         CAMELLIA128-SHA
         AES128-SHA
         )
   );


   foreach my $cipher_name ( keys %ciphers )
      {
      push @{ $ciphers_by_code{ $ciphers{$cipher_name}{code} } }, $ciphers{$cipher_name};

      $ciphers{$cipher_name}{name} = $cipher_name;
      $ciphers{$cipher_name}{tags} = [ split( /:/, $ciphers{$cipher_name}{tags} ) ];

      # bettercrypto scores: list a = 100, b = 80; other 0
      if ( $bettercrypto_a{ $ciphers{$cipher_name}{shortname} } )
         {
         $ciphers{$cipher_name}{scores}{bettercrypto} = $SCORE_BEST;

         push @{ $ciphers_by_tag{bettercrypto_a} }, $ciphers{$cipher_name};
         push @{ $ciphers_by_tag{bettercrypto_b} }, $ciphers{$cipher_name};    # all a are members of b!
                                                   #push @{ $ciphers{$cipher_name}{tags} }, "bettercrypto_a";    # all a are members of b!
         }
      elsif ( $bettercrypto_b{ $ciphers{$cipher_name}{shortname} } )
         {
         $ciphers{$cipher_name}{scores}{bettercrypto} = $SCORE_GOOD;

         push @{ $ciphers_by_tag{bettercrypto_b} }, $ciphers{$cipher_name};

         #push @{ $ciphers{$cipher_name}{tags} }, "bettercrypto_b";
         }

      # else { $ciphers{$cipher_name}{scores}{bettercrypto} = 0; }

      } ## end foreach my $cipher_name ( keys...)

   #foreach


   my $DATADIR = eval { return File::ShareDir::module_dir(__PACKAGE__) };
   $DATADIR = "$FindBin::Bin/../files/CipherSuites" if not defined $DATADIR;    # or not -d $DATADIR;

   # $DATADIR = "../../files/CipherSuites" unless -d $DATADIR;

   _parse_iana_cipherlist($DATADIR);

   _init_bsi_score();

   # reset by code
   %ciphers_by_code = ();

   foreach my $cipher ( values %ciphers )
      {
      # $cipher->{code_bin} = pack( "H6", $cipher->{code} );

      push @{ $ciphers_by_code{ $cipher->{code} } },      $cipher;
      push @{ $ciphers_by_name{ $cipher->{shortname} } }, $cipher;    # there may be multiple short names, but only one long
      $ciphers_by_name{ $cipher->{name} } = [$cipher];                # long and short (openssl) name with 1 lookup

      push @{ $ciphers_by_tag{ $cipher->{tlsver} } }, $cipher if defined $cipher->{tlsver};
      push @{ $ciphers_by_tag{ $cipher->{enc} } },    $cipher if defined $cipher->{enc};
      push @{ $ciphers_by_tag{ $cipher->{mac} } },    $cipher if defined $cipher->{mac};
      push @{ $ciphers_by_tag{ $cipher->{auth} } },   $cipher if defined $cipher->{auth};
      push @{ $ciphers_by_tag{ $cipher->{keyx} } },   $cipher if defined $cipher->{keyx};
      push @{ $ciphers_by_tag{"$cipher->{size}bits"} }, $cipher if defined $cipher->{size};

      #push @{ $ciphers_by_tag{$ARG} }, $cipher foreach ( @{ $cipher->{tags} } );

      foreach my $tag ( @{ $cipher->{tags} } )
         {
         push @{ $ciphers_by_tag{$tag} }, $cipher;
         $cipher->{is}{$tag} = 1;
         }

      # hack for bettercrypto "is" field;
      # TODO: fix!

      if ( ( $cipher->{scores}{bettercrypto} // 0 ) == $SCORE_BEST )
         {
         $cipher->{is}{bettercrypto_a} = 1;
         }

      if ( ( $cipher->{scores}{bettercrypto} // 0 ) >= $SCORE_GOOD )
         {
         $cipher->{is}{bettercrypto_b} = 1;
         }

      # 3 byte SSLv2 cipher?
      if ( length( $cipher->{code} ) == $CODE_V2_HEX_LEN and $cipher !~ m{^00} )
         {
         $cipher->{only_sslv2} = 1;
         push @{ $ciphers_by_tag{only_sslv2} }, $cipher;
         }
      else
         {
         push @{ $ciphers_by_tag{sslv3_or_later} }, $cipher;
         }
      } ## end foreach my $cipher ( values...)

   _prefer_iana_ciphers();

   _set_browser_tags();


   return;
   } ## end sub _init


sub _parse_iana_cipherlist
   {
   my $path = shift;

   #
   # Read IANA Cipherlist
   # (via http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
   #

   my $csv = Text::CSV_XS->new( { binary => 1, } );
   open my $IANA, "<", "$path/tls-parameters-4.csv"    ## no critic (InputOutput::RequireBriefOpen)
      or die "can't read $path/tls-parameters-4.csv: $OS_ERROR\n";
   my $first_line = <$IANA>;

   while ( my $row = $csv->getline($IANA) )
      {
      my ( $code, $name, $dtls_ok, $reference ) = @$row;

      next if $name =~ /^ (?: Unassigned | Reserved )/x;
      $name =~ s{^TLS_}{}x;
      #### say "Cipher name not found: $name ($code)" and next unless $ciphers{$name};

      $code =~ s{,?0x}{}g;
      ### die "FATAL! different code for $name: $code instead of $ciphers{$name}{code}\n" #### if length($code) != 6;

      # When no cipher with this name,
      # look up the code, clone this and make AIANA additions to the cloned one
      unless ( $ciphers{$name} )
         {
         my $cipher = $ciphers_by_code{$code}[0];

         my $new_cipher;
         if ( defined $cipher )
            {
            $new_cipher = dclone($cipher);
            $new_cipher->{name} = $name;
            }
         else
            {
            $new_cipher = _build_new_cipher( name => $name, code => $code );
            }
         $ciphers{$name} = $new_cipher;
         }


      if ( $dtls_ok eq "Y" ) { $ciphers{$name}{dtls} = 1; }

      # elsif ( $dtls_ok ne "N" ) { die "FATAL: unknown dtls-status: $dtls_ok\n" }

      # put RFCs in tags
      push @{ $ciphers{$name}{tags} }, "iana", grep { $ARG } split( m{ [\[\]]+ }x, $reference );

      # IANA Flag
      $ciphers{$name}{iana} = 1;

      } ## end while ( my $row = $csv->getline...)

   close $IANA or die "WTF, can't close IANA File: $OS_ERROR\n";

   return;
   } ## end sub _parse_iana_cipherlist


#
# When there are multiple ciphers by code,
# then place the iana cipher in the first position
#

sub _prefer_iana_ciphers
   {

   foreach my $code ( keys %ciphers_by_code )
      {
      next if scalar @{ $ciphers_by_code{$code} } == 1;    # no duplicates
      next if $ciphers_by_code{$code}[0]{iana};    # first is already iana

      for my $pos ( 1 .. $#{ $ciphers_by_code{$code} } )
         {
         unshift @{ $ciphers_by_code{$code} }, splice( @{ $ciphers_by_code{$code} }, $pos, 1 )
            if $ciphers_by_code{$code}[$pos]{iana};
         }

      }
   return;
   }



sub _build_new_cipher
   {
   my %cipher = @ARG;
   $cipher{shortname} = _create_short_name( $cipher{name} );

   # TODO: add enc, keyx, ... to the hash.

   return \%cipher;
   }

sub _create_short_name
   {
   my $name = shift;

   $name =~ s{WITH_}{}xg;
   $name =~ s{ (?<= [[:alpha:]] ) _ (?= \d ) }{}xg;    # AES_128 => AES128; but something like RC4_128 => RC4_128
   $name =~ s{_}{-}xg;

   return $name;
   }

# Cipher scrores according to the recommendations
# of the german "Bundesamt für Sicherheit in der Informationstechnik" (BSI)
sub _init_bsi_score
   {

   my @bsi_pfs = qw(
      ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
      ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
      ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

      ECDHE_RSA_WITH_AES_128_CBC_SHA256
      ECDHE_RSA_WITH_AES_128_GCM_SHA256
      ECDHE_RSA_WITH_AES_256_CBC_SHA384
      ECDHE_RSA_WITH_AES_256_GCM_SHA384

      DHE_DSS_WITH_AES_128_CBC_SHA256
      DHE_DSS_WITH_AES_128_GCM_SHA256
      DHE_DSS_WITH_AES_256_CBC_SHA256
      DHE_DSS_WITH_AES_256_GCM_SHA384

      DHE_RSA_WITH_AES_128_CBC_SHA256
      DHE_RSA_WITH_AES_128_GCM_SHA256
      DHE_RSA_WITH_AES_256_CBC_SHA256
      DHE_RSA_WITH_AES_256_GCM_SHA384
      );

   # remove the E from DHE
   my @bsi_nopfs = map { ( my $nopfs = $ARG ) =~ s{DHE_}{DH_}x; $nopfs; } @bsi_pfs;    ## nocritic

   push @bsi_pfs, qw(
      ECDHE_PSK_WITH_AES_128_CBC_SHA256
      ECDHE_PSK_WITH_AES_256_CBC_SHA384

      DHE_PSK_WITH_AES_128_CBC_SHA256
      DHE_PSK_WITH_AES_128_GCM_SHA256
      DHE_PSK_WITH_AES_256_CBC_SHA384
      DHE_PSK_WITH_AES_256_GCM_SHA384
      );


   push @bsi_nopfs, qw(
      RSA_PSK_WITH_AES_128_CBC_SHA256
      RSA_PSK_WITH_AES_128_GCM_SHA256
      RSA_PSK_WITH_AES_256_CBC_SHA384
      RSA_PSK_WITH_AES_256_GCM_SHA384
      );


   #
   # Score 100: recommended cipher suite with PFS
   #        95: dito, but DHE
   #        80: recommended cipher suite without PFS
   #        75: dito, but DHE
   #

   foreach my $name (@bsi_pfs)
      {
      my $cipher = $ciphers{$name};
      $cipher->{scores}{bsi} = $name =~ m{ ( ^EC | _PSK_ ) }x ? $SCORE_BEST : $SCORE_BEST - $SCORE_REDUCE;
      push @{ $cipher->{tags} }, "bsi_pfs";
      }

   foreach my $name (@bsi_nopfs)
      {
      my $cipher = $ciphers{$name};
      $cipher->{scores}{bsi} = $name =~ m{ ( ^EC | _PSK_ ) }x ? $SCORE_GOOD : $SCORE_GOOD - $SCORE_REDUCE;
      push @{ $cipher->{tags} }, "bsi_nopfs";
      }


   return 1;
   } ## end sub _init_bsi_score



=head2 CIPHER STRINGS FROM BROWSERS – notes!

Checked at cc.dcsec.uni-hannover.de:

Safari:

Version:
3.1 / TLSv1

Ciphers:
ff,c024,c023,c00a,c009,c008,c028,c027,c014,c013,c012,c026,c025,c005,c004,c003,c02a,c029,c00f,c00e,c00d,6b,67,39,33,16,3d,3c,35,2f,0a,c007,c011,c002,c00c,05,04

Extensions:
0000,000a,000b,000d,3374

UA:
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7


Firefox:

Version:
3.1 / TLSv1

Ciphers:
c02b,c02f,c00a,c009,c013,c014,33,39,2f,35,0a

Extensions:
0000,ff01,000a,000b,0023,3374,0010,0005,000d

UA:
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:41.0) Gecko/20100101 Firefox/41.0


Chrome:

Version:
3.1 / TLSv1

Ciphers:
c02b,c02f,9e,cc14,cc13,cc15,c00a,c014,39,c009,c013,33,9c,35,2f,0a

Extensions:
ff01,0000,0017,0023,000d,0005,3374,0012,0010,7550,000b,000a

UA:
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36


=cut

sub _set_browser_tags
   {
   my @safari = qw(c024 c023 c00a c009 c008 c028 c027 c014 c013 c012 c026 c025 c005 c004 c003
      c02a c029 c00f c00e c00d 6b 67 39 33 16 3d 3c 35 2f 0a c007 c011 c002 c00c 05 04);
   my @firefox = qw(c02b c02f c00a c009 c013 c014 33 39 2f 35 0a);
   my @chrome  = qw(c02b c02f 9e cc14 cc13 cc15 c00a c014 39 c009 c013 33 9c 35 2f 0a);

   # via https://www.ssllabs.com/ssltest/viewClient.html?name=IE&version=8%2d10&platform=Win%207
   my @ie8_win7 = qw(c014 c013 35 2f c00a c009 38 32 0a 13 05 04);

   # via https://www.ssllabs.com/ssltest/viewClient.html?name=IE&version=11&platform=Win%2010
   my @ie11_win10 = qw(c030 c02f c028 c027 c014 c013 9f 9e 9d 9c 3d 3c 35 2f c02c c02b c024 c023 c00a c009 6a 40 38 32 0a 13);

   _set_tag_by_code( "firefox",    @firefox );
   _set_tag_by_code( "safari",     @safari );
   _set_tag_by_code( "chrome",     @chrome );
   _set_tag_by_code( "ie8_win7",   @ie8_win7 );
   _set_tag_by_code( "ie11_win10", @ie11_win10 );

   return;
   } ## end sub _set_browser_tags

#
# search the FIRST cipher suite for each code and set the tag!
#

sub _set_tag_by_code
   {
   my $tag   = shift;
   my @codes = @ARG;

   foreach my $code (@codes)
      {
      $code = "00$code" if length($code) == 2;
      $code = uc($code);
      my $cipher = $ciphers_by_code{$code}[0] // die "Cipher with Code $code not found!\n";

      #push @{ $cipher->{tags} }, $tag;

      push @{ $ciphers_by_tag{$tag} }, $cipher;
      $cipher->{is}{$tag} = 1;
      }

   return;
   }



=head1 METHODS



=head2 new_with_all

Selects all cipher suites available

=cut

sub new_with_all
   {
   my $self = shift;
   $self = $self->new unless ref $self;
   $self->ciphers( [ values %ciphers ] );
   return $self;
   }



=head2 ->new_by_name($name1, $name2, @names, ...)

Selects ciphers by their name (short or long).

Duplicates are not removed!

=cut

sub new_by_name
   {
   my $self = shift;
   $self = $self->new unless ref $self;
   my @ciphers = map { @{ $ciphers_by_name{$ARG} // [] } } @ARG;
   $self->ciphers( \@ciphers );
   return $self;
   }



=head2 ->new_by_tag(@tags)

Returns all Ciphers, selected by one or more Tags. The list of tags can 
be one or more arrays or arrayrefs or any combination.

Duplicates are not removed!

=cut

sub new_by_tag
   {
   my $self = shift;
   $self = $self->new unless ref $self;
   my @ciphers = map { @{ $ciphers_by_tag{$ARG} // [] } } @ARG;
   $self->ciphers( \@ciphers );
   return $self;
   }



=head2 ->new_by_code(@codes)

Returns all Ciphers, selected by one or more codes as hex string.

Duplicates are not removed!

=cut

sub new_by_code
   {
   my $self = shift;
   $self = $self->new unless ref $self;
   $self->ciphers( [ map { $ciphers_by_code{$ARG}[0] // croak "Cipher $ARG not found" } @ARG ] );
   return $self;
   }

#sub _cipher_by_code
#   {
#   my $code = shift;
#
#   my $cipher = $ciphers_by_code{$ARG};
#   return $cipher if $cipher;
#
#   # no cipher found
#   # but check SSLv2 ciphers
#   if (length($code) == 4)
#      {
#      $cipher = $ciphers_by_code{"00$code"};
#      return $cipher if $cipher;
#      }
#
#   }



#=head2 ->from_algorithms( keyx => [...], enc => [...], mode => [...], mac => [...] );
#
#Selects all ciphers according to the given algorithms.
#
#=cut
#
#sub from_algorithms
#   {
#   my $self = shift;
#   $self = $self->new unless ref $self;
#
#   my %params = @ARG;
#
#   my @found_ciphers;
#   foreach my $mac ( @{ $params{mac} } )
#      {
#
#      foreach my $mode ( @{ $params{mode} } )
#         {
#         foreach my $enc ( @{ $params{enc} } )
#            {
#            foreach my $keyx ( @{ $params{keyx} } )
#               {
#               my $name = "${keyx}_WITH_${enc}_${mode}_$mac";
#               push @found_ciphers, ( $ciphers{$name} // croak "Cipher $name not found!" );
#               }
#            }
#         }
#      }
#   $self->ciphers( \@found_ciphers );
#
#   return $self;
#   } ## end sub from_algorithms



=head2 ->unique()

Removes duplicates from the cipher suites.


Old Version: B<Important:> this sub changes the order of the ciphers. 
They are in more or less random order!

New: order not changed


=cut

# TODO: write a test for the iana case

sub unique
   {
   my $self = shift;

   #   my %unique;
   #   foreach my $cipher ( @{ $self->ciphers } )
   #      {
   #      # don't overwrite, if a former cipher is an iana cipher: then this has priority, keep it
   #      $unique{ $cipher->{code} } = $cipher unless $unique{ $cipher->{code} }{iana};
   #      }
   #
   #   $self->ciphers( [ values %unique ] );

   #
   my %seen;
   my @unique;
   my $position = 0;

   foreach my $cipher ( @{ $self->ciphers } )
      {
      # already seen? Overwrite if there is a IANA cipher suite
      if ( defined $seen{ $cipher->{code} } )
         {
         $unique[ $seen{ $cipher->{code} } ] = $cipher if $cipher->{iana};
         }
      else
         {
         $unique[$position] = $cipher;
         $seen{ $cipher->{code} } = $position++;
         }
      }

   $self->ciphers( \@unique );

   return $self;
   } ## end sub unique



=head2 cipher_spec( [ $version ] )

Returns the SSL/TLS cipher_spec for the (internally stored) cipher list.
Returns the cipher_spec as binary string. 2 bytes per cipher, 
compatible with SSLv3 and TLS, NOT SSLv2. 

If optional argument is < 0x0300 (SSLv3), conitnues with cipher_spec_sslv2.

Dies, if there is a SSLv2 only cipher in SSLv3+ mode.


=cut

sub cipher_spec
   {
   my $self = shift;

   my $version = shift;
   return $self->cipher_spec_sslv2 if $version && $version < $SSL3;


   my $cipher_spec = "";
   foreach my $cipher ( @{ $self->ciphers } )
      {
      my $code = $cipher->{code};
      if ( length($code) == $CODE_V2_HEX_LEN )     # SSLv2 Cipher?
         {
         $code =~ s{^00}{}                         # try to remove leading 0
            or croak "Can't use SSLv2-only Cipher: $cipher->{name} ($code)";
         }
      elsif ( length($code) != $CODE_HEX_LEN )
         {
         croak "Wrong length of cipher Code: $code ($cipher->{name}";
         }
      $cipher_spec .= pack( "H4", $cipher->{code} );
      }

   return $cipher_spec;
   } ## end sub cipher_spec


=head2 cipher_spec_sslv2

Returns the SSL/TLS cipher_spec for the internal cipher list as SSLv2 cipher spec.

Returns the cipher_spec as binary string. 3 bytes per cipher,
compatible with SSLv2,  SSLv3/TLS.


=cut

sub cipher_spec_sslv2
   {
   my $self = shift;

   my $cipher_spec = "";
   foreach my $cipher ( @{ $self->ciphers } )
      {
      my $code = $cipher->{code};
      if ( length($code) == $CODE_HEX_LEN )        # SSLv3/TLS Cipher code? Convert to 3 bytes.
         {
         $code = "00$code";
         }
      elsif ( length($code) != $CODE_V2_HEX_LEN )
         {
         croak "Wrong length of cipher Code for SSLv2: $code ($cipher->{name}";
         }
      $cipher_spec .= pack( "H6", $code );
      }

   return $cipher_spec;
   } ## end sub cipher_spec_sslv2



=head2 new_by_cipher_spec($cipher_spec);

Returns the SSL/TLS ciphers for a binary cipher_spec.

Parameter: the cipher_spec as binary string, 3 bytes per cipher.

Returns a list of ciphers in list context, and an arrayref in scalar context.

=cut

sub new_by_cipher_spec
   {
   my $self        = shift;
   my $cipher_spec = shift;

   $self = $self->new unless ref $self;

   # may be faster, when using the code from new_by_code without extra call
   $self->new_by_code( map { uc } unpack( "(H4)*", $cipher_spec ) );

   return $self;
   }


=head2 new_by_cipher_spec_sslv2($cipher_spec);

The same as C<new_by_cipher_spec>, but with a SSLv2 cipher spec (3 bytes per cipher!)

=cut

sub new_by_cipher_spec_sslv2
   {
   my $self        = shift;
   my $cipher_spec = shift;

   $self = $self->new unless ref $self;

   my @ciphers;

   # because SSLv3/TLS Ciphers may be used with SSLv2
   # (see "if not found" below) don't use ->new_by_code here
   foreach my $code ( map { uc } unpack( "(H6)*", $cipher_spec ) )
      {

      if ( my $cipher = $ciphers_by_code{$code} )
         {
         push @ciphers, $cipher->[0];
         next;
         }

      # if not found:
      ( my $shortcode = $code ) =~ s{^00}{}x;
      my $cipher = $ciphers_by_code{$shortcode};
      croak "Cipher with Code $code does not exist" unless $cipher;
      push @ciphers, $cipher->[0];
      }

   $self->ciphers( \@ciphers );

   return $self;
   } ## end sub new_by_cipher_spec_sslv2



=head2 ->add( @ciphers | $ciphers_ref | $obj )

Takes one or more ciphers, refernces to a list of ciphers or cipher objects 
and adds them to the ciphers.

=cut

sub add
   {
   my $self = shift;

   push @{ $self->ciphers }, map { blessed($ARG) ? @{ $ARG->ciphers } : ref($ARG) eq "ARRAY" ? @$ARG : $ARG } @ARG;

   return $self;
   }

=head2 ->remove( @ciphers | $ciphers_ref | $obj )

Removes one or more ciphers from the ciphers list. Ciphers are identified by 
the code, so if there are duplicate ciphers by code with different 
name etc, they are removed too.

Ans all duplicates are removed too.

Takes one or more ciphers, refernces to a list of ciphers or cipher objects.


=cut

sub remove
   {
   my $self = shift;

   #   foreach my $remove ( map { blessed($ARG) ? @{ $ARG->ciphers } : ref($ARG) ? @$ARG : $ARG } @ARG )
   #      {
   #      $self->remove_all_by_code( $remove->{code} );
   #      }
   $self->remove_all_by_code(
      map {
              blessed($ARG)        ? ( map { $ARG->{code} } @{ $ARG->ciphers } )
            : ref($ARG) eq "ARRAY" ? ( map { $ARG->{code} } @$ARG )
            : $ARG->{code}
         } @ARG
   );

   return $self;
   }


=head2 ->remove_first_by_code( $code | @codes )

Removes the first cipher from the cipherlist, which matches a $code. 
Each code from the list is only removed one time!

# TODO: Check performance for most common cases!

=cut

# TODO: Check performance for most common cases!

sub remove_first_by_code
   {
   my $self = shift;
   my %codes = map { $ARG => 1 } @ARG;                # hash: we need to remove codes from the list!

   my $ciphers = $self->ciphers;

   CIPHERPOS: for my $pos ( 0 .. $#$ciphers )
      {
      if ( any { $ciphers->[$pos]{code} eq $ARG } keys %codes )
         {
         delete $codes{ $ciphers->[$pos]{code} };  # This code is done!
         splice @$ciphers, $pos, 1;
         last unless %codes;                       # All codes done?
         redo CIPHERPOS;
         }
      }

   return $self;
   }


=head2 ->remove_all_by_code( $code | @codes )

Removes all ciphers from the cipherlist, which matches a $code.

=cut

sub remove_all_by_code
   {
   my $self  = shift;
   my @codes = @ARG;

   my $ciphers = $self->ciphers;

   CIPHERPOS: for my $pos ( 0 .. $#$ciphers )
      {
      next unless defined $ciphers->[$pos];        # prevent autovivification!
      if ( any { $ciphers->[$pos]{code} eq $ARG } @codes )
         {
         splice @$ciphers, $pos, 1;
         redo CIPHERPOS;
         }
      }

   return $self;
   }


=head2 ->order_by_code

Orders the cipher list by the code.

TLS Ciphers (2 bytes) are prefixed with 00.

=cut

sub order_by_code
   {
   my $self = shift;

   $self->ciphers( [ sort { _order_by_code() } @{ $self->ciphers } ] );

   return $self;
   }

sub _order_by_code
   {
   my $ca = $a->{code};
   my $cb = $b->{code};

   $ca = "00$ca" if length $ca == $CODE_HEX_LEN;
   $cb = "00$cb" if length $cb == $CODE_HEX_LEN;

   # my $cmp = $ca cmp $cb;

   return $ca cmp $cb;
   }


=head2 ->names

Get all cipher Names.

In List context: returns an array of all names.

In Scalar context: returns all names, separated with space.

=cut

sub names
   {
   my $self = shift;

   my @names = map { $ARG->{name} } @{ $self->ciphers };

   return wantarray ? @names : join( " ", @names );

   }


=head2 ->split_into_parts( [ $ssl_version ] [, $max_bytes] )

Some (broken) SSL/TLS implementations recognize only a limited number of cipher suites 
in the handshake. To handle this, this method creates an array of CipherSuite-Objects 
with parts of the original list.

Optional parameter $ssl_version is the SSL-Version string; default is $SSL3 and up.

Optional parameter $max_bytes is the maximum number of bytes of a resulting cipher_spec; default: 146.

TODO: which default max bytes?

=cut

Readonly my $DEFAULT_MAX_BYTES => 146;

sub split_into_parts
   {
   my $self        = shift;
   my $ssl_version = shift // $SSL3;
   my $max_bytes   = shift // $DEFAULT_MAX_BYTES;

   my $max_ciphers = int( $max_bytes / ( $ssl_version < $SSL3 ? $CODE_V2_LEN : $CODE_LEN ) );

   my @ciphers = $self->all;

   my @splitted;
   while (@ciphers)
      {
      my @part = splice( @ciphers, 0, $max_ciphers );
      push @splitted, __PACKAGE__->new( ciphers => \@part );
      }

   return @splitted;
   }



1;



