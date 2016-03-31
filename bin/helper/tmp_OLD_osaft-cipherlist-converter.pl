#!/usr/bin/env perl

=head DESCRIPTION

Little helper skript, that converts O-Saft Cipher Lists to a better suitable format.

But after this conversion the comments and order should be the same ...


Therefore the O-Saft Ciphers List is included in the DATA section; 
cipher names are included as perl code.


=cut


use strict;
use warnings;

use List::Util qw(max);

use Data::Dumper;

use 5.010;


my %cipher_names = (

   # ADH_DES_192_CBC_SHA      # alias: DH_anon_WITH_3DES_EDE_CBC_SHA
   # ADH_DES_40_CBC_SHA       # alias: DH_anon_EXPORT_WITH_DES40_CBC_SHA
   # ADH_DES_64_CBC_SHA       # alias: DH_anon_WITH_DES_CBC_SHA
   # ADH_RC4_40_MD5           # alias: DH_anon_EXPORT_WITH_RC4_40_MD5
   # DHE_RSA_WITH_AES_128_SHA # alias: DHE_RSA_WITH_AES_128_CBC_SHA
   # DHE_RSA_WITH_AES_256_SHA # alias: DHE_RSA_WITH_AES_256_CBC_SHA
   #
   #!#----------+-------------------------------------+--------------------------+
   #!# constant =>     cipher suite name               cipher suite value
   #!#----------+-------------------------------------+--------------------------+
   '0x0300001B' => [qw(ADH-DES-CBC3-SHA                ADH_DES_192_CBC_SHA)],
   '0x03000019' => [qw(EXP-ADH-DES-CBC-SHA             ADH_DES_40_CBC_SHA)],
   '0x0300001A' => [qw(ADH-DES-CBC-SHA                 ADH_DES_64_CBC_SHA)],
   '0x03000018' => [qw(ADH-RC4-MD5                     ADH_RC4_128_MD5)],
   '0x03000017' => [qw(EXP-ADH-RC4-MD5                 ADH_RC4_40_MD5)],
   '0x030000A6' => [qw(ADH-AES128-GCM-SHA256           ADH_WITH_AES_128_GCM_SHA256)],
   '0x03000034' => [qw(ADH-AES128-SHA                  ADH_WITH_AES_128_SHA)],
   '0x0300006C' => [qw(ADH-AES128-SHA256               ADH_WITH_AES_128_SHA256)],
   '0x030000A7' => [qw(ADH-AES256-GCM-SHA384           ADH_WITH_AES_256_GCM_SHA384)],
   '0x0300003A' => [qw(ADH-AES256-SHA                  ADH_WITH_AES_256_SHA)],
   '0x0300006D' => [qw(ADH-AES256-SHA256               ADH_WITH_AES_256_SHA256)],
   '0x03000046' => [qw(ADH-CAMELLIA128-SHA             ADH_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000089' => [qw(ADH-CAMELLIA256-SHA             ADH_WITH_CAMELLIA_256_CBC_SHA)],
   '0x0300009B' => [qw(ADH-SEED-SHA                    ADH_WITH_SEED_SHA)],
   '0x020700c0' => [qw(DES-CBC3-MD5                    DES_192_EDE3_CBC_WITH_MD5)],
   '0x020701c0' => [qw(DES-CBC3-SHA                    DES_192_EDE3_CBC_WITH_SHA)],
   '0x02060040' => [qw(DES-CBC-MD5                     DES_64_CBC_WITH_MD5)],
   '0x02060140' => [qw(DES-CBC-SHA                     DES_64_CBC_WITH_SHA)],
   '0x02ff0800' => [qw(DES-CFB-M1                      DES_64_CFB64_WITH_MD5_1)],
   '0x03000063' => [qw(EXP1024-DHE-DSS-DES-CBC-SHA     DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA)],
   '0x03000065' => [qw(EXP1024-DHE-DSS-RC4-SHA         DHE_DSS_EXPORT1024_WITH_RC4_56_SHA)],
   '0x030000A2' => [qw(DHE-DSS-AES128-GCM-SHA256       DHE_DSS_WITH_AES_128_GCM_SHA256)],
   '0x03000032' => [qw(DHE-DSS-AES128-SHA              DHE_DSS_WITH_AES_128_SHA)],
   '0x03000040' => [qw(DHE-DSS-AES128-SHA256           DHE_DSS_WITH_AES_128_SHA256)],
   '0x030000A3' => [qw(DHE-DSS-AES256-GCM-SHA384       DHE_DSS_WITH_AES_256_GCM_SHA384)],
   '0x03000038' => [qw(DHE-DSS-AES256-SHA              DHE_DSS_WITH_AES_256_SHA)],
   '0x0300006A' => [qw(DHE-DSS-AES256-SHA256           DHE_DSS_WITH_AES_256_SHA256)],
   '0x03000044' => [qw(DHE-DSS-CAMELLIA128-SHA         DHE_DSS_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000087' => [qw(DHE-DSS-CAMELLIA256-SHA         DHE_DSS_WITH_CAMELLIA_256_CBC_SHA)],
   '0x0300CC15' => [qw(DHE-RSA-CHACHA20-POLY1305       DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)],
   '0x03000066' => [qw(DHE-DSS-RC4-SHA                 DHE_DSS_WITH_RC4_128_SHA)],
   '0x03000099' => [qw(DHE-DSS-SEED-SHA                DHE_DSS_WITH_SEED_SHA)],
   '0x0300009E' => [qw(DHE-RSA-AES128-GCM-SHA256       DHE_RSA_WITH_AES_128_GCM_SHA256)],
   '0x03000033' => [qw(DHE-RSA-AES128-SHA              DHE_RSA_WITH_AES_128_SHA)],
   '0x03000067' => [qw(DHE-RSA-AES128-SHA256           DHE_RSA_WITH_AES_128_SHA256)],
   '0x0300009F' => [qw(DHE-RSA-AES256-GCM-SHA384       DHE_RSA_WITH_AES_256_GCM_SHA384)],
   '0x03000039' => [qw(DHE-RSA-AES256-SHA              DHE_RSA_WITH_AES_256_SHA)],
   '0x0300006B' => [qw(DHE-RSA-AES256-SHA256           DHE_RSA_WITH_AES_256_SHA256)],
   '0x03000045' => [qw(DHE-RSA-CAMELLIA128-SHA         DHE_RSA_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000088' => [qw(DHE-RSA-CAMELLIA256-SHA         DHE_RSA_WITH_CAMELLIA_256_CBC_SHA)],
   '0x0300009A' => [qw(DHE-RSA-SEED-SHA                DHE_RSA_WITH_SEED_SHA)],
   '0x0300000D' => [qw(DH-DSS-DES-CBC3-SHA             DH_DSS_DES_192_CBC3_SHA)],
   '0x0300000B' => [qw(EXP-DH-DSS-DES-CBC-SHA          DH_DSS_DES_40_CBC_SHA)],
   '0x0300000C' => [qw(DH-DSS-DES-CBC-SHA              DH_DSS_DES_64_CBC_SHA)],
   '0x030000A4' => [qw(DH-DSS-AES128-GCM-SHA256        DH_DSS_WITH_AES_128_GCM_SHA256)],
   '0x03000030' => [qw(DH-DSS-AES128-SHA               DH_DSS_WITH_AES_128_SHA)],
   '0x0300003E' => [qw(DH-DSS-AES128-SHA256            DH_DSS_WITH_AES_128_SHA256)],
   '0x030000A5' => [qw(DH-DSS-AES256-GCM-SHA384        DH_DSS_WITH_AES_256_GCM_SHA384)],
   '0x03000036' => [qw(DH-DSS-AES256-SHA               DH_DSS_WITH_AES_256_SHA)],
   '0x03000068' => [qw(DH-DSS-AES256-SHA256            DH_DSS_WITH_AES_256_SHA256)],
   '0x03000042' => [qw(DH-DSS-CAMELLIA128-SHA          DH_DSS_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000085' => [qw(DH-DSS-CAMELLIA256-SHA          DH_DSS_WITH_CAMELLIA_256_CBC_SHA)],
   '0x03000097' => [qw(DH-DSS-SEED-SHA                 DH_DSS_WITH_SEED_SHA)],
   '0x03000010' => [qw(DH-RSA-DES-CBC3-SHA             DH_RSA_DES_192_CBC3_SHA)],
   '0x0300000E' => [qw(EXP-DH-RSA-DES-CBC-SHA          DH_RSA_DES_40_CBC_SHA)],
   '0x0300000F' => [qw(DH-RSA-DES-CBC-SHA              DH_RSA_DES_64_CBC_SHA)],
   '0x030000A0' => [qw(DH-RSA-AES128-GCM-SHA256        DH_RSA_WITH_AES_128_GCM_SHA256)],
   '0x03000031' => [qw(DH-RSA-AES128-SHA               DH_RSA_WITH_AES_128_SHA)],
   '0x0300003F' => [qw(DH-RSA-AES128-SHA256            DH_RSA_WITH_AES_128_SHA256)],
   '0x030000A1' => [qw(DH-RSA-AES256-GCM-SHA384        DH_RSA_WITH_AES_256_GCM_SHA384)],
   '0x03000037' => [qw(DH-RSA-AES256-SHA               DH_RSA_WITH_AES_256_SHA)],
   '0x03000069' => [qw(DH-RSA-AES256-SHA256            DH_RSA_WITH_AES_256_SHA256)],
   '0x03000043' => [qw(DH-RSA-CAMELLIA128-SHA          DH_RSA_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000086' => [qw(DH-RSA-CAMELLIA256-SHA          DH_RSA_WITH_CAMELLIA_256_CBC_SHA)],
   '0x03000098' => [qw(DH-RSA-SEED-SHA                 DH_RSA_WITH_SEED_SHA)],
   '0x0300C009' => [qw(ECDHE-ECDSA-AES128-SHA          ECDHE_ECDSA_WITH_AES_128_CBC_SHA)],
   '0x0300C02B' => [qw(ECDHE-ECDSA-AES128-GCM-SHA256   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)],
   '0x0300C023' => [qw(ECDHE-ECDSA-AES128-SHA256       ECDHE_ECDSA_WITH_AES_128_SHA256)],
   '0x0300C00A' => [qw(ECDHE-ECDSA-AES256-SHA          ECDHE_ECDSA_WITH_AES_256_CBC_SHA)],
   '0x0300C02C' => [qw(ECDHE-ECDSA-AES256-GCM-SHA384   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)],
   '0x0300C024' => [qw(ECDHE-ECDSA-AES256-SHA384       ECDHE_ECDSA_WITH_AES_256_SHA384)],
   '0x0300CC14' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305   ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)],
   '0x0300C008' => [qw(ECDHE-ECDSA-DES-CBC3-SHA        ECDHE_ECDSA_WITH_DES_192_CBC3_SHA)],
   '0x0300CC13' => [qw(ECDHE-RSA-CHACHA20-POLY1305     ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)],
   '0x0300C006' => [qw(ECDHE-ECDSA-NULL-SHA            ECDHE_ECDSA_WITH_NULL_SHA)],
   '0x0300C007' => [qw(ECDHE-ECDSA-RC4-SHA             ECDHE_ECDSA_WITH_RC4_128_SHA)],
   '0x0300C013' => [qw(ECDHE-RSA-AES128-SHA            ECDHE_RSA_WITH_AES_128_CBC_SHA)],
   '0x0300C02F' => [qw(ECDHE-RSA-AES128-GCM-SHA256     ECDHE_RSA_WITH_AES_128_GCM_SHA256)],
   '0x0300C027' => [qw(ECDHE-RSA-AES128-SHA256         ECDHE_RSA_WITH_AES_128_SHA256)],
   '0x0300C014' => [qw(ECDHE-RSA-AES256-SHA            ECDHE_RSA_WITH_AES_256_CBC_SHA)],
   '0x0300C030' => [qw(ECDHE-RSA-AES256-GCM-SHA384     ECDHE_RSA_WITH_AES_256_GCM_SHA384)],
   '0x0300C028' => [qw(ECDHE-RSA-AES256-SHA384         ECDHE_RSA_WITH_AES_256_SHA384)],
   '0x0300C012' => [qw(ECDHE-RSA-DES-CBC3-SHA          ECDHE_RSA_WITH_DES_192_CBC3_SHA)],
   '0x0300C010' => [qw(ECDHE-RSA-NULL-SHA              ECDHE_RSA_WITH_NULL_SHA)],
   '0x0300C011' => [qw(ECDHE-RSA-RC4-SHA               ECDHE_RSA_WITH_RC4_128_SHA)],
   '0x0300C004' => [qw(ECDH-ECDSA-AES128-SHA           ECDH_ECDSA_WITH_AES_128_CBC_SHA)],
   '0x0300C02D' => [qw(ECDH-ECDSA-AES128-GCM-SHA256    ECDH_ECDSA_WITH_AES_128_GCM_SHA256)],
   '0x0300C025' => [qw(ECDH-ECDSA-AES128-SHA256        ECDH_ECDSA_WITH_AES_128_SHA256)],
   '0x0300C005' => [qw(ECDH-ECDSA-AES256-SHA           ECDH_ECDSA_WITH_AES_256_CBC_SHA)],
   '0x0300C02E' => [qw(ECDH-ECDSA-AES256-GCM-SHA384    ECDH_ECDSA_WITH_AES_256_GCM_SHA384)],
   '0x0300C026' => [qw(ECDH-ECDSA-AES256-SHA384        ECDH_ECDSA_WITH_AES_256_SHA384)],
   '0x0300C003' => [qw(ECDH-ECDSA-DES-CBC3-SHA         ECDH_ECDSA_WITH_DES_192_CBC3_SHA)],
   '0x0300C001' => [qw(ECDH-ECDSA-NULL-SHA             ECDH_ECDSA_WITH_NULL_SHA)],
   '0x0300C002' => [qw(ECDH-ECDSA-RC4-SHA              ECDH_ECDSA_WITH_RC4_128_SHA)],
   '0x0300C00E' => [qw(ECDH-RSA-AES128-SHA             ECDH_RSA_WITH_AES_128_CBC_SHA)],
   '0x0300C031' => [qw(ECDH-RSA-AES128-GCM-SHA256      ECDH_RSA_WITH_AES_128_GCM_SHA256)],
   '0x0300C029' => [qw(ECDH-RSA-AES128-SHA256          ECDH_RSA_WITH_AES_128_SHA256)],
   '0x0300C00F' => [qw(ECDH-RSA-AES256-SHA             ECDH_RSA_WITH_AES_256_CBC_SHA)],
   '0x0300C032' => [qw(ECDH-RSA-AES256-GCM-SHA384      ECDH_RSA_WITH_AES_256_GCM_SHA384)],
   '0x0300C02A' => [qw(ECDH-RSA-AES256-SHA384          ECDH_RSA_WITH_AES_256_SHA384)],
   '0x0300C00D' => [qw(ECDH-RSA-DES-CBC3-SHA           ECDH_RSA_WITH_DES_192_CBC3_SHA)],
   '0x0300C00B' => [qw(ECDH-RSA-NULL-SHA               ECDH_RSA_WITH_NULL_SHA)],
   '0x0300C00C' => [qw(ECDH-RSA-RC4-SHA                ECDH_RSA_WITH_RC4_128_SHA)],
   '0x0300C018' => [qw(AECDH-AES128-SHA                ECDH_anon_WITH_AES_128_CBC_SHA)],
   '0x0300C019' => [qw(AECDH-AES256-SHA                ECDH_anon_WITH_AES_256_CBC_SHA)],
   '0x0300C017' => [qw(AECDH-DES-CBC3-SHA              ECDH_anon_WITH_DES_192_CBC3_SHA)],
   '0x0300C015' => [qw(AECDH-NULL-SHA                  ECDH_anon_WITH_NULL_SHA)],
   '0x0300C016' => [qw(AECDH-RC4-SHA                   ECDH_anon_WITH_RC4_128_SHA)],
   '0x03000013' => [qw(EDH-DSS-DES-CBC3-SHA            EDH_DSS_DES_192_CBC3_SHA)],
   '0x03000011' => [qw(EXP-EDH-DSS-DES-CBC-SHA         EDH_DSS_DES_40_CBC_SHA)],
   '0x03000012' => [qw(EDH-DSS-DES-CBC-SHA             EDH_DSS_DES_64_CBC_SHA)],
   '0x03000016' => [qw(EDH-RSA-DES-CBC3-SHA            EDH_RSA_DES_192_CBC3_SHA)],
   '0x03000014' => [qw(EXP-EDH-RSA-DES-CBC-SHA         EDH_RSA_DES_40_CBC_SHA)],
   '0x03000015' => [qw(EDH-RSA-DES-CBC-SHA             EDH_RSA_DES_64_CBC_SHA)],
   '0x0300001D' => [qw(FZA-FZA-SHA                     FZA_DMS_FZA_SHA)],     # FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
   '0x0300001C' => [qw(FZA-NULL-SHA                    FZA_DMS_NULL_SHA)],    # FORTEZZA_KEA_WITH_NULL_SHA
   '0x0300001e' => [qw(FZA-RC4-SHA                     FZA_DMS_RC4_SHA)]
   ,                                               # <== 1e so that it is its own hash entry in crontrast to 1E (duplicate constant definition in openssl)
   '0x02050080' => [qw(IDEA-CBC-MD5                    IDEA_128_CBC_WITH_MD5)],
   '0x03000023' => [qw(KRB5-DES-CBC3-MD5               KRB5_DES_192_CBC3_MD5)],
   '0x0300001F' => [qw(KRB5-DES-CBC3-SHA               KRB5_DES_192_CBC3_SHA)],
   '0x03000029' => [qw(EXP-KRB5-DES-CBC-MD5            KRB5_DES_40_CBC_MD5)],
   '0x03000026' => [qw(EXP-KRB5-DES-CBC-SHA            KRB5_DES_40_CBC_SHA)],
   '0x03000022' => [qw(KRB5-DES-CBC-MD5                KRB5_DES_64_CBC_MD5)],
   '0x0300001E' => [qw(KRB5-DES-CBC-SHA                KRB5_DES_64_CBC_SHA)],
   '0x03000025' => [qw(KRB5-IDEA-CBC-MD5               KRB5_IDEA_128_CBC_MD5)],
   '0x03000021' => [qw(KRB5-IDEA-CBC-SHA               KRB5_IDEA_128_CBC_SHA)],
   '0x0300002A' => [qw(EXP-KRB5-RC2-CBC-MD5            KRB5_RC2_40_CBC_MD5)],
   '0x03000027' => [qw(EXP-KRB5-RC2-CBC-SHA            KRB5_RC2_40_CBC_SHA)],
   '0x03000024' => [qw(KRB5-RC4-MD5                    KRB5_RC4_128_MD5)],
   '0x03000020' => [qw(KRB5-RC4-SHA                    KRB5_RC4_128_SHA)],
   '0x0300002B' => [qw(EXP-KRB5-RC4-MD5                KRB5_RC4_40_MD5)],
   '0x03000028' => [qw(EXP-KRB5-RC4-SHA                KRB5_RC4_40_SHA)],
   '0x02ff0810' => [qw(NULL                            NULL)],
   '0x02000000' => [qw(NULL-MD5                        NULL_WITH_MD5)],
   '0x03000000' => [qw(NULL-MD5                        NULL_WITH_NULL_NULL)],
   '0x0300008B' => [qw(PSK-3DES-EDE-CBC-SHA            PSK_WITH_3DES_EDE_CBC_SHA)],
   '0x0300008C' => [qw(PSK-AES128-CBC-SHA              PSK_WITH_AES_128_CBC_SHA)],
   '0x0300008D' => [qw(PSK-AES256-CBC-SHA              PSK_WITH_AES_256_CBC_SHA)],
   '0x0300008A' => [qw(PSK-RC4-SHA                     PSK_WITH_RC4_128_SHA)],
   '0x02010080' => [qw(RC4-MD5                         RC4_128_WITH_MD5)],
   '0x02020080' => [qw(EXP-RC4-MD5                     RC4_128_EXPORT40_WITH_MD5)],
   '0x02030080' => [qw(RC2-CBC-MD5                     RC2_128_CBC_WITH_MD5)],
   '0x02040080' => [qw(EXP-RC2-CBC-MD5                 RC2_128_CBC_EXPORT40_WITH_MD5)],
   '0x02080080' => [qw(RC4-64-MD5                      RC4_64_WITH_MD5)],
   '0x0300000A' => [qw(DES-CBC3-SHA                    RSA_DES_192_CBC3_SHA)],
   '0x03000008' => [qw(EXP-DES-CBC-SHA                 RSA_DES_40_CBC_SHA)],
   '0x03000009' => [qw(DES-CBC-SHA                     RSA_DES_64_CBC_SHA)],
   '0x03000062' => [qw(EXP1024-DES-CBC-SHA             RSA_EXPORT1024_WITH_DES_CBC_SHA)],
   '0x03000061' => [qw(EXP1024-RC2-CBC-MD5             RSA_EXPORT1024_WITH_RC2_CBC_56_MD5)],
   '0x03000060' => [qw(EXP1024-RC4-MD5                 RSA_EXPORT1024_WITH_RC4_56_MD5)],
   '0x03000064' => [qw(EXP1024-RC4-SHA                 RSA_EXPORT1024_WITH_RC4_56_SHA)],
   '0x03000007' => [qw(IDEA-CBC-SHA                    RSA_IDEA_128_SHA)],
   '0x03000001' => [qw(NULL-MD5                        RSA_NULL_MD5)],
   '0x03000002' => [qw(NULL-SHA                        RSA_NULL_SHA)],
   '0x03000006' => [qw(EXP-RC2-CBC-MD5                 RSA_RC2_40_MD5)],
   '0x03000004' => [qw(RC4-MD5                         RSA_RC4_128_MD5)],
   '0x03000005' => [qw(RC4-SHA                         RSA_RC4_128_SHA)],
   '0x03000003' => [qw(EXP-RC4-MD5                     RSA_RC4_40_MD5)],
   '0x0300009C' => [qw(AES128-GCM-SHA256               RSA_WITH_AES_128_GCM_SHA256)],
   '0x0300002F' => [qw(AES128-SHA                      RSA_WITH_AES_128_SHA)],
   '0x0300003C' => [qw(AES128-SHA256                   RSA_WITH_AES_128_SHA256)],
   '0x0300009D' => [qw(AES256-GCM-SHA384               RSA_WITH_AES_256_GCM_SHA384)],
   '0x03000035' => [qw(AES256-SHA                      RSA_WITH_AES_256_SHA)],
   '0x0300003D' => [qw(AES256-SHA256                   RSA_WITH_AES_256_SHA256)],
   '0x03000041' => [qw(CAMELLIA128-SHA                 RSA_WITH_CAMELLIA_128_CBC_SHA)],
   '0x03000084' => [qw(CAMELLIA256-SHA                 RSA_WITH_CAMELLIA_256_CBC_SHA)],
   '0x0300003B' => [qw(NULL-SHA256                     RSA_WITH_NULL_SHA256)],
   '0x03000096' => [qw(SEED-SHA                        RSA_WITH_SEED_SHA)],

   '0x0300002C' => [qw(PSK-SHA                         PSK_WITH_NULL_SHA)],
   '0x0300002D' => [qw(DHE-PSK-SHA                     DHE_PSK_WITH_NULL_SHA)],
   '0x0300002E' => [qw(RSA-PSK-SHA                     RSA_PSK_WITH_NULL_SHA)],
   '0x0300008E' => [qw(DHE-PSK-RC4-SHA                 DHE_PSK_WITH_RC4_128_SHA)],
   '0x0300008F' => [qw(DHE-PSK-3DES-SHA                DHE_PSK_WITH_3DES_EDE_CBC_SHA)],
   '0x03000090' => [qw(DHE-PSK-AES128-SHA              DHE_PSK_WITH_AES_128_CBC_SHA)],
   '0x03000091' => [qw(DHE-PSK-AES256-SHA              DHE_PSK_WITH_AES_256_CBC_SHA)],
   '0x03000092' => [qw(RSA-PSK-RC4-SHA                 RSA_PSK_WITH_RC4_128_SHA)],
   '0x03000093' => [qw(RSA-PSK-3DES-SHA                RSA_PSK_WITH_3DES_EDE_CBC_SHA)],
   '0x03000094' => [qw(RSA-PSK-AES128-SHA              RSA_PSK_WITH_AES_128_CBC_SHA)],
   '0x03000095' => [qw(RSA-PSK-AES256-SHA              RSA_PSK_WITH_AES_256_CBC_SHA)],
   '0x030000AA' => [qw(DHE-PSK-AES128-GCM-SHA256       DHE_PSK_WITH_AES_128_GCM_SHA256)],
   '0x030000AB' => [qw(DHE-PSK-AES256-GCM-SHA384       DHE_PSK_WITH_AES_256_GCM_SHA384)],
   '0x030000AC' => [qw(RSA-PSK-AES128-GCM-SHA256       RSA_PSK_WITH_AES_128_GCM_SHA256)],
   '0x030000AD' => [qw(RSA-PSK-AES256-GCM-SHA384       RSA_PSK_WITH_AES_256_GCM_SHA384)],
   '0x030000AE' => [qw(PSK-AES128-SHA256               PSK_WITH_AES_128_CBC_SHA256)],
   '0x030000AF' => [qw(PSK-AES256-SHA384               PSK_WITH_AES_256_CBC_SHA384)],
   '0x030000B0' => [qw(PSK-SHA256                      PSK_WITH_NULL_SHA256)],
   '0x030000B1' => [qw(PSK-SHA384                      PSK_WITH_NULL_SHA384)],
   '0x030000B2' => [qw(DHE-PSK-AES128-SHA256           DHE_PSK_WITH_AES_256_CBC_SHA256)],
   '0x030000B3' => [qw(DHE-PSK-AES256-SHA384           DHE_PSK_WITH_AES_256_CBC_SHA384)],
   '0x030000B4' => [qw(DHE-PSK-SHA256                  DHE_PSK_WITH_NULL_SHA256)],
   '0x030000B5' => [qw(DHE-PSK-SHA384                  DHE_PSK_WITH_NULL_SHA384)],
   '0x030000B6' => [qw(RSA-PSK-AES128-SHA256           RSA_PSK_WITH_AES_256_CBC_SHA256)],
   '0x030000B7' => [qw(RSA-PSK-AES256-SHA384           RSA_PSK_WITH_AES_256_CBC_SHA384)],
   '0x030000B8' => [qw(RSA-PSK-SHA256                  RSA_PSK_WITH_NULL_SHA256)],
   '0x030000B9' => [qw(RSA-PSK-SHA384                  RSA_PSK_WITH_NULL_SHA384)],

   '0x0300C09C' => [qw(RSA-AES128-CCM                  RSA_WITH_AES_128_CCM)],
   '0x0300C09D' => [qw(RSA-AES256-CCM                  RSA_WITH_AES_256_CCM)],
   '0x0300C09E' => [qw(DHE-RSA-AES128-CCM              DHE_RSA_WITH_AES_128_CCM)],
   '0x0300C09F' => [qw(DHE-RSA-AES256-CCM              DHE_RSA_WITH_AES_256_CCM)],
   '0x0300C0A4' => [qw(PSK-RSA-AES128-CCM              PSK_WITH_AES_128_CCM)],
   '0x0300C0A5' => [qw(PSK-RSA-AES256-CCM              PSK_WITH_AES_256_CCM)],
   '0x0300C0AC' => [qw(ECDHE-RSA-AES128-CCM            ECDHE_ECDSA_WITH_AES_128_CCM)],
   '0x0300C0AD' => [qw(ECDHE-RSA-AES256-CCM            ECDHE_ECDSA_WITH_AES_256_CCM)],
   '0x0300C0A0' => [qw(RSA-AES128-CCM-8                RSA_WITH_AES_128_CCM_8)],
   '0x0300C0A1' => [qw(RSA-AES256-CCM-8                RSA_WITH_AES_256_CCM_8)],
   '0x0300C0A2' => [qw(DHE-RSA-AES128-CCM-8            DHE_RSA_WITH_AES_128_CCM_8)],
   '0x0300C0A3' => [qw(DHE-RSA-AES256-CCM-8            DHE_RSA_WITH_AES_256_CCM_8)],
   '0x0300C0A8' => [qw(PSK-RSA-AES128-CCM-8            PSK_WITH_AES_128_CCM_8)],
   '0x0300C0A9' => [qw(PSK-RSA-AES256-CCM-8            PSK_WITH_AES_256_CCM_8)],
   '0x0300C0AE' => [qw(ECDHE-RSA-AES128-CCM-8          ECDHE_ECDSA_WITH_AES_128_CCM_8)],
   '0x0300C0AF' => [qw(ECDHE-RSA-AES256-CCM-8          ECDHE_ECDSA_WITH_AES_256_CCM_8)],
   '0x03005600' => [qw(SCSV                            TLS_FALLBACK_SCSV)]
   ,                                               # FIXME: according http://tools.ietf.org/html/draft-bmoeller-tls-downgrade-scsv-01
   '0x030000FF' => [qw(SCSV                            EMPTY_RENEGOTIATION_INFO_SCSV)],
   '0x0300C01C' => [qw(SRP-DSS-3DES-EDE-CBC-SHA        SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)],
   '0x0300C01F' => [qw(SRP-DSS-AES-128-CBC-SHA         SRP_SHA_DSS_WITH_AES_128_CBC_SHA)],
   '0x0300C022' => [qw(SRP-DSS-AES-256-CBC-SHA         SRP_SHA_DSS_WITH_AES_256_CBC_SHA)],
   '0x0300C01B' => [qw(SRP-RSA-3DES-EDE-CBC-SHA        SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)],
   '0x0300C01E' => [qw(SRP-RSA-AES-128-CBC-SHA         SRP_SHA_RSA_WITH_AES_128_CBC_SHA)],
   '0x0300C021' => [qw(SRP-RSA-AES-256-CBC-SHA         SRP_SHA_RSA_WITH_AES_256_CBC_SHA)],
   '0x0300C01A' => [qw(SRP-3DES-EDE-CBC-SHA            SRP_SHA_WITH_3DES_EDE_CBC_SHA)],
   '0x0300C01D' => [qw(SRP-AES-128-CBC-SHA             SRP_SHA_WITH_AES_128_CBC_SHA)],
   '0x0300C020' => [qw(SRP-AES-256-CBC-SHA             SRP_SHA_WITH_AES_256_CBC_SHA)],
   '0x0300FEE0' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
   '0x0300FEE1' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
   '0x0300FEFE' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
   '0x0300FEFF' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
   '0x03000080' => [qw(GOST94-GOST89-GOST89            GOSTR341094_WITH_28147_CNT_IMIT)],
   '0x03000081' => [qw(GOST2001-GOST89-GOST89          GOSTR341001_WITH_28147_CNT_IMIT)],
   '0x0300FF00' => [qw(GOST-MD5             -?-)], # ??
   '0x0300FF01' => [qw(GOST-GOST94          -?-)], # ??
   '0x0300FF00' => [qw(GOST94-NULL-GOST94   -?-)], # ??
   '0x0300FF01' => [qw(GOST2001-NULL-GOST94 -?-)], # ??

   # TODO:  following PCT...
   '0x00800001' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509)],
   '0x00800003' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509_CHAIN)],
   '0x00810001' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_MD5)],
   '0x00810003' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_SHA)],
   '0x00820003' => [qw(PCT_SSL_EXCH_TYPE               PCT1_EXCH_RSA_PKCS1)],
   '0x00823004' => [qw(PCT_SSL_CIPHER_TYPE_1ST_HALF    PCT1_CIPHER_RC4)],
   '0x00842840' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_40|PCT1_MAC_BITS_128)],
   '0x00848040' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_128|PCT1_MAC_BITS_128)],
   '0x008f8001' => [qw(PCT_SSL_COMPAT                  PCT_VERSION_1)],

   #!#----------+-------------------------------------+--------------------------+

);                                                 # %cipher_names

my %cipher_alias = (                               # TODO: list not yet used
                                                   #!#----------+-------------------------------------+--------------------------+
                                                   #!# constant =>     cipher suite name alias        # comment (where found)
                                                   #!#----------+-------------------------------------+--------------------------+
   '0x02030080' => [qw(RC2-MD5)],                  #
   '0x02040080' => [qw(EXP-RC2-MD5)],              # from sslaudit.ini
   '0x03000012' => [qw(EDH-DSS-CBC-SHA)],          # from sslaudit.ini and mozilla
   '0x0300001D' => [qw(FZA-FZA-CBC-SHA)],
   '0x03000032' => [qw(EDH-DSS-AES128-SHA)],       # from RSA BSAFE SSL-C
   '0x03000033' => [qw(EDH-RSA-AES128-SHA)],       # from RSA BSAFE SSL-C
   '0x03000038' => [qw(EDH-DSS-AES256-SHA)],       # from RSA BSAFE SSL-C
   '0x03000039' => [qw(EDH-RSA-AES256-SHA)],       # from RSA BSAFE SSL-C
   '0x03000062' => [qw(EXP-DES-56-SHA)],           # from RSA BSAFE SSL-C
   '0x03000063' => [qw(EXP-EDH-DSS-DES-56-SHA)],   # from RSA BSAFE SSL-C
   '0x03000064' => [qw(EXP-RC4-56-SHA)],           # from RSA BSAFE SSL-C
   '0x03000065' => [qw(EXP-EDH-DSS-RC4-56-SHA)],
   '0x03000066' => [qw(EDH-DSS-RC4-SHA)],          # from RSA BSAFE SSL-C
   '0x0300009B' => [qw(DHanon-SEED-SHA)],

   #!#----------+-------------------------------------+--------------------------+
                   );                              # %cipher_alias



# Check if all found …
$cipher_names{$_} or die "NOT FOUND: $_" foreach keys %cipher_alias;
say "All from alias hash found";


my $max_len_longname = max( map { length( $_->[1] ) } values %cipher_names );

my %ciphernames_with_constant = map {
   my ($const) = m{ 0x.. ( .{6} ) }x;
   die "Code not matched: $_" unless $1;
   $cipher_names{$_}[0] => [ $const, $cipher_names{$_}[1] ]
   }
   keys %cipher_names;


#print Dumper \%ciphernames_with_constant;
my %ciphers;

# print Dumper \%ciphers;

foreach my $line (@cipher_code)
   {

   if (    $line =~ m{ ^ \s*[#)] }x
        or $line !~ m{\w}
        or $line =~ s{\%ciphers = \(}{my \%ciphers = (} )
      {
      print $line;
      next;
      }


   my $WORD = qr{ (\S+|-\?-) }x;
   my ( $name, $sec, $ssl, $enc, $bits, $mac, $auth, $key, $score, $tags, $comment ) = $line =~ m{ 
        ^ \s*
        '([-\w]+)'         # code
        \s+ => \s*
        \[qw\( \s* 
        ($WORD)            # sec
        \s+
        ($WORD)            # ssl
        \s+
        ($WORD)            # enc
        \s+
        ($WORD)            # bits
        \s+
        ($WORD)            # mac
        \s+
        ($WORD)            # auth
        \s+
        ($WORD)            # key exchange
        \s+
        ($WORD)            # O-Saft-Score
        \s+
        ($WORD)            # O-Saft-Tags
        
        \s*
        \) \s* \] \s* ,
        
        \s*
        (?:\# \s* (.*) )?  # maybe comment
        
      }x;

   die "Not parsed line: $line" unless $name;
 
   say "# Not found in cipher-names: $name" unless $ciphernames_with_constant{$name};
   
   
   
   
   } ## end foreach my $line (@cipher_code...)


__DATA__

@ciphers = (

   #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
   #'head'                 => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
   #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
   #'ADH-AES128-SHA'        => [qw(  HIGH SSLv3 AES   128 SHA1 None  DH         11 "")],
   #'ADH-AES256-SHA'        => [qw(  HIGH SSLv3 AES   256 SHA1 None  DH         11 "")],
   #'ADH-DES-CBC3-SHA'      => [qw(  HIGH SSLv3 3DES  168 SHA1 None  DH         11 "")],
   #'ADH-DES-CBC-SHA'       => [qw(   LOW SSLv3 DES    56 SHA1 None  DH         11 "")],
   #'ADH-RC4-MD5'           => [qw(MEDIUM SSLv3 RC4   128 MD5  None  DH         11 "")],
   #'ADH-SEED-SHA'          => [qw(MEDIUM SSLv3 SEED  128 SHA1 None  DH         11 "")],
   #   above use anonymous DH and hence are vulnerable to MiTM attacks
   #   see openssl's `man ciphers' for details (eNULL and aNULL)
   #   so they are qualified   weak  here instead of the definition
   #   in  `openssl ciphers -v HIGH'
   #--------
   # values  -?-  are unknown yet
   #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
   #!# 'head'              => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
   #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
   # FIXME: perl hashes may not have multiple keys (have them for SSLv2 and SSLv3)
   'ADH-AES128-SHA'              => [qw(  weak SSLv3 AES   128 SHA1 None  DH          0 :)],
   'ADH-AES256-SHA'              => [qw(  weak SSLv3 AES   256 SHA1 None  DH          0 :)],
   'ADH-DES-CBC3-SHA'            => [qw(  weak SSLv3 3DES  168 SHA1 None  DH          0 :)],
   'ADH-DES-CBC-SHA'             => [qw(  weak SSLv3 DES    56 SHA1 None  DH          0 :)],
   'ADH-RC4-MD5'                 => [qw(  weak SSLv3 RC4   128 MD5  None  DH          0 :)],      # openssl: MEDIUM
   'ADH-SEED-SHA'                => [qw(  weak SSLv3 SEED  128 SHA1 None  DH          0 OSX)],    # openssl: MEDIUM
                                                   #
   'AECDH-AES128-SHA'            => [qw(  weak SSLv3 AES   128 SHA1 None  ECDH       11 :)],
   'AECDH-AES256-SHA'            => [qw(  weak SSLv3 AES   256 SHA1 None  ECDH       11 :)],
   'AECDH-DES-CBC3-SHA'          => [qw(  weak SSLv3 3DES  168 SHA1 None  ECDH       11 :)],
   'AECDH-NULL-SHA'              => [qw(  weak SSLv3 None    0 SHA1 None  ECDH        0 :)],
   'AECDH-RC4-SHA'               => [qw(  weak SSLv3 RC4   128 SHA1 None  ECDH       11 :)],      # openssl: MEDIUM
   'AES128-SHA'                  => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   RSA        80 :)],
   'AES256-SHA'                  => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   RSA       100 :)],
   'DES-CBC3-MD5'                => [qw(  HIGH SSLv2 3DES  168 MD5  RSA   RSA        80 :)],
   'DES-CBC3-SHA'                => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   RSA        80 :)],
   'DES-CBC3-SHA'                => [qw(  HIGH SSLv2 3DES  168 SHA1 RSA   RSA        80 :)],
   'DES-CBC-MD5'                 => [qw(   LOW SSLv2 DES    56 MD5  RSA   RSA        20 :)],
   'DES-CBC-SHA'                 => [qw(   LOW SSLv3 DES    56 SHA1 RSA   RSA        20 :)],
   'DES-CBC-SHA'                 => [qw(   LOW SSLv2 DES    56 SHA1 RSA   RSA        20 :)],
   'DES-CFB-M1'                  => [qw(  weak SSLv2 DES    64 MD5  RSA   RSA        20 :)],
   'DH-DSS-AES128-SHA'           => [qw(medium -?-   AES   128 SHA1 DSS   DH         81 :)],
   'DH-DSS-AES256-SHA'           => [qw(medium -?-   AES   256 SHA1 DSS   DH         81 :)],
   'DH-RSA-AES128-SHA'           => [qw(medium -?-   AES   128 SHA1 RSA   DH         81 :)],
   'DH-RSA-AES256-SHA'           => [qw(medium -?-   AES   256 SHA1 RSA   DH         81 :)],
   'DHE-DSS-AES128-SHA'          => [qw(  HIGH SSLv3 AES   128 SHA1 DSS   DH         80 :)],
   'DHE-DSS-AES256-SHA'          => [qw(  HIGH SSLv3 AES   256 SHA1 DSS   DH        100 :)],
   'DHE-DSS-RC4-SHA'             => [qw(  weak SSLv3 RC4   128 SHA1 DSS   DH         80 :)],      # FIXME: degrade this also?
   'DHE-DSS-SEED-SHA'            => [qw(MEDIUM SSLv3 SEED  128 SHA1 DSS   DH         81 OSX)],
   'DHE-RSA-AES128-SHA'          => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   DH         80 :)],
   'DHE-RSA-AES256-SHA'          => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   DH        100 :)],
   'DHE-RSA-SEED-SHA'            => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   DH         81 OSX)],
   'ECDH-ECDSA-AES128-SHA'       => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/ECDSA 91 :)],
   'ECDH-ECDSA-AES256-SHA'       => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/ECDSA 91 :)],
   'ECDH-ECDSA-DES-CBC3-SHA'     => [qw(  HIGH SSLv3 3DES  168 SHA1 ECDH  ECDH/ECDSA 11 :)],
   'ECDH-ECDSA-RC4-SHA'          => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/ECDSA 81 :)],      #openssl: MEDIUM
   'ECDH-ECDSA-NULL-SHA'         => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/ECDSA  0 :)],
   'ECDH-RSA-AES128-SHA'         => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/RSA   11 :)],
   'ECDH-RSA-AES256-SHA'         => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/RSA   11 :)],
   'ECDH-RSA-DES-CBC3-SHA'       => [qw(  HIGH SSLv3 3DES  168 SHA1 ECDH  ECDH/RSA   11 :)],
   'ECDH-RSA-RC4-SHA'            => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/RSA   81 :)],      #openssl: MEDIUM
   'ECDH-RSA-NULL-SHA'           => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/RSA    0 :)],
   'ECDHE-ECDSA-AES128-SHA'      => [qw(  HIGH SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)],
   'ECDHE-ECDSA-AES256-SHA'      => [qw(  HIGH SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)],
   'ECDHE-ECDSA-DES-CBC3-SHA'    => [qw(HIGH SSLv3 3DES  168 SHA1 ECDSA ECDH       11 :)],
   'ECDHE-ECDSA-NULL-SHA'        => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH        0 :)],
   'ECDHE-ECDSA-RC4-SHA'         => [qw(  weak SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)],      #openssl: MEDIUM
   'ECDHE-RSA-AES128-SHA'        => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   ECDH       11 :)],
   'ECDHE-RSA-AES256-SHA'        => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   ECDH       11 :)],
   'ECDHE-RSA-DES-CBC3-SHA'      => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)],
   'ECDHE-RSA-RC4-SHA'           => [qw(  weak SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)],      #openssl: MEDIUM
   'ECDHE-RSA-NULL-SHA'          => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH        0 :)],
   'EDH-DSS-DES-CBC3-SHA'        => [qw(  HIGH SSLv3 3DES  168 SHA1 DSS   DH         80 :)],
   'EDH-DSS-DES-CBC-SHA'         => [qw(   LOW SSLv3 DES    56 SHA1 DSS   DH          1 :)],
   'EDH-RSA-DES-CBC3-SHA'        => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   DH         80 :)],
   'EDH-RSA-DES-CBC-SHA'         => [qw(   LOW SSLv3 DES    56 SHA1 RSA   DH         20 :)],
   'EXP-ADH-DES-CBC-SHA'         => [qw(  weak SSLv3 DES    40 SHA1 None  DH(512)     0 export)],
   'EXP-ADH-RC4-MD5'             => [qw(  weak SSLv3 RC4    40 MD5  None  DH(512)     0 export)],
   'EXP-DES-CBC-SHA'             => [qw(  WEAK SSLv3 DES    40 SHA1 RSA   RSA(512)    2 export)],
   'EXP-EDH-DSS-DES-CBC-SHA'     => [qw(  WEAK SSLv3 DES    40 SHA1 DSS   DH(512)     2 export)],
   'EXP-EDH-RSA-DES-CBC-SHA'     => [qw(  WEAK SSLv3 DES    40 SHA1 RSA   DH(512)     2 export)],
   'EXP-RC2-CBC-MD5'             => [qw(  WEAK SSLv2 RC2    40 MD5  RSA   RSA(512)    2 export)],
   'EXP-RC2-CBC-MD5'             => [qw(  WEAK SSLv3 RC2    40 MD5  RSA   RSA(512)    2 export)],
   'EXP-RC4-MD5'                 => [qw(  WEAK SSLv2 RC4    40 MD5  RSA   RSA(512)    2 export)],
   'EXP-RC4-MD5'                 => [qw(  WEAK SSLv3 RC4    40 MD5  RSA   RSA(512)    2 export)],
   'EXP-RC4-64-MD5'              => [qw(  weak SSLv3 RC4    64 MD5  DSS   RSA         2 :)],      # (from RSA BSAFE SSL-C)
   'EXP-EDH-DSS-RC4-56-SHA'      => [qw(  WEAK SSLv3 RC4    56 SHA  DSS   DHE         2 :)],      # (from RSA BSAFE SSL-C)
   'EXP1024-DES-CBC-SHA'         => [qw(  WEAK SSLv3 DES    56 SHA1 RSA   RSA(1024)   2 export)],
   'EXP1024-DHE-DSS-RC4-SHA'     => [qw(  WEAK SSLv3 RC4    56 SHA1 DSS   DH(1024)    2 export)],
   'EXP1024-DHE-DSS-DES-CBC-SHA' => [qw(WEAK SSLv3 DES 56 SHA1 DSS  DH(1024)    2 export)],
   'EXP1024-RC2-CBC-MD5'         => [qw(  WEAK SSLv3 RC2    56 MD5  RSA   RSA(1024)   1 export)],
   'EXP1024-RC4-MD5'             => [qw(  WEAK SSLv3 RC4    56 MD5  RSA   RSA(1024)   1 export)],
   'EXP1024-RC4-SHA'             => [qw(  WEAK SSLv3 RC4    56 SHA1 RSA   RSA(1024)   2 export)],
   'IDEA-CBC-MD5'                => [qw(MEDIUM SSLv2 IDEA  128 MD5  RSA   RSA        80 :)],
   'IDEA-CBC-SHA'                => [qw(MEDIUM SSLv2 IDEA  128 SHA1 RSA   RSA        80 :)],
   'NULL'                        => [qw(  weak SSLv2 None    0 -?-  None  -?-         0 :)],      # openssl SSLeay testing
   'NULL-MD5'                    => [qw(  weak SSLv2 None    0 MD5  RSA   RSA(512)    0 :)],
   'NULL-MD5'                    => [qw(  weak SSLv3 None    0 MD5  RSA   RSA(512)    0 export)], # FIXME: same hash key as before
   'NULL-SHA'                    => [qw(  weak SSLv3 None    0 SHA1 RSA   RSA         0 :)],
   'PSK-3DES-EDE-CBC-SHA'        => [qw(  HIGH SSLv3 3DES  168 SHA1 PSK   PSK         1 :)],
   'PSK-AES128-CBC-SHA'          => [qw(  HIGH SSLv3 AES   128 SHA1 PSK   PSK         1 :)],
   'PSK-AES256-CBC-SHA'          => [qw(  HIGH SSLv3 AES   256 SHA1 PSK   PSK         1 :)],
   'PSK-RC4-SHA'                 => [qw(MEDIUM SSLv3 RC4   128 SHA1 PSK   PSK         1 :)],
   'RC2-CBC-MD5'                 => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        11 :)],
   'RC2-MD5'                     => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        80 :)],
   'RC4-64-MD5'                  => [qw(  weak SSLv2 RC4    64 MD5  RSA   RSA         3 :)],
   'RC4-MD5'                     => [qw(  weak SSLv2 RC4   128 MD5  RSA   RSA         8 :)],      #openssl: MEDIUM
   'RC4-MD5'                     => [qw(  weak SSLv3 RC4   128 MD5  RSA   RSA         8 :)],      #openssl: MEDIUM
   'RC4-SHA'                     => [qw(  weak SSLv3 RC4   128 SHA1 RSA   RSA         8 :)],      #openssl: MEDIUM
   'SEED-SHA'                    => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   RSA        11 OSX)],

   #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
   'ADH-CAMELLIA128-SHA'     => [qw(  weak SSLv3 CAMELLIA  128 SHA1 None  DH      0 :)],          #openssl: HIGH
   'ADH-CAMELLIA256-SHA'     => [qw(  weak SSLv3 CAMELLIA  256 SHA1 None  DH      0 :)],          #openssl: HIGH
   'CAMELLIA128-SHA'         => [qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   RSA    80 :)],
   'CAMELLIA256-SHA'         => [qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   RSA   100 :)],
   'DHE-DSS-CAMELLIA128-SHA' => [qw(  HIGH SSLv3 CAMELLIA  128 SHA1 DSS   DH     80 :)],
   'DHE-DSS-CAMELLIA256-SHA' => [qw(  HIGH SSLv3 CAMELLIA  256 SHA1 DSS   DH    100 :)],
   'DHE-RSA-CAMELLIA128-SHA' => [qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   DH     80 :)],
   'DHE-RSA-CAMELLIA256-SHA' => [qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   DH    100 :)],
   'GOST94-GOST89-GOST89'    => [qw(  -?-  SSLv3 GOST89 256 GOST89  GOST94 VKO    1 :)],
   'GOST2001-GOST89-GOST89'  => [qw(  -?-  SSLv3 GOST89 256 GOST89  GOST01 VKO    1 :)],
   'GOST94-NULL-GOST94'      => [qw(  -?-  SSLv3 None     0 GOST94  GOST94 VKO    1 :)],
   'GOST2001-NULL-GOST94'    => [qw(  -?-  SSLv3 None     0 GOST94  GOST01 VKO    1 :)],

   #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,

   # from openssl-1.0.1c
   #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
   #!# 'head'                      => [qw(  sec  ssl   enc   bits mac    auth  keyx    score tags)],
   #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
   'SRP-AES-128-CBC-SHA'           => [qw(  HIGH SSLv3 AES    128 SHA1   None  SRP        91 :)],    # openssl: HIGH
   'SRP-AES-256-CBC-SHA'           => [qw(  HIGH SSLv3 AES    256 SHA1   None  SRP        91 :)],    # openssl: HIGH
   'SRP-DSS-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   DSS   SRP        91 :)],
   'SRP-DSS-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   DSS   SRP        91 :)],
   'SRP-DSS-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   DSS   SRP        91 :)],
   'SRP-RSA-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   RSA   SRP        91 :)],
   'SRP-RSA-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   RSA   SRP        91 :)],
   'SRP-RSA-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   RSA   SRP        91 :)],
   'SRP-3DES-EDE-CBC-SHA'          => [qw(  HIGH SSLv3 3DES   168 SHA1   None  SRP        91 :)],    # openssl: HIGH
   'ADH-AES128-SHA256'             => [qw( weak TLSv12 AES    128 SHA256 None  DH         10 :)],    # openssl: HIGH
   'ADH-AES128-GCM-SHA256'         => [qw( weak TLSv12 AESGCM 128 AEAD   None  DH         10 :)],    # openssl: HIGH
   'ADH-AES256-GCM-SHA384'         => [qw( weak TLSv12 AESGCM 256 AEAD   None  DH         10 :)],    # openssl: HIGH
   'ADH-AES256-SHA256'             => [qw( weak TLSv12 AES    256 SHA256 None  DH         10 :)],    # openssl: HIGH
   'AES128-GCM-SHA256'             => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   RSA        91 :)],
   'AES128-SHA256'                 => [qw( HIGH TLSv12 AES    128 SHA256 RSA   RSA        91 :)],
   'AES256-GCM-SHA384'             => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   RSA        91 :)],
   'AES256-SHA256'                 => [qw( HIGH TLSv12 AES    256 SHA256 RSA   RSA        91 :)],
   'DHE-DSS-AES128-GCM-SHA256'     => [qw( HIGH TLSv12 AESGCM 128 AEAD   DSS   DH         91 :)],
   'DHE-DSS-AES128-SHA256'         => [qw( HIGH TLSv12 AES    128 SHA256 DSS   DH         91 :)],
   'DHE-DSS-AES256-GCM-SHA384'     => [qw( HIGH TLSv12 AESGCM 256 AEAD   DSS   DH         91 :)],
   'DHE-DSS-AES256-SHA256'         => [qw( HIGH TLSv12 AES    256 SHA256 DSS   DH         91 :)],
   'DHE-RSA-AES128-GCM-SHA256'     => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   DH         91 :)],
   'DHE-RSA-AES128-SHA256'         => [qw( HIGH TLSv12 AES    128 SHA256 RSA   DH         91 :)],
   'DHE-RSA-AES256-GCM-SHA384'     => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   DH         91 :)],
   'DHE-RSA-AES256-SHA256'         => [qw( HIGH TLSv12 AES    256 SHA256 RSA   DH         91 :)],
   'ECDH-ECDSA-AES128-GCM-SHA256'  => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDH  ECDH/ECDSA 91 :)],
   'ECDH-ECDSA-AES128-SHA256'      => [qw( HIGH TLSv12 AES    128 SHA256 ECDH  ECDH/ECDSA 91 :)],
   'ECDH-ECDSA-AES256-GCM-SHA384'  => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDH  ECDH/ECDSA 91 :)],
   'ECDH-ECDSA-AES256-SHA384'      => [qw( HIGH TLSv12 AES    256 SHA384 ECDH  ECDH/ECDSA 91 :)],
   'ECDHE-ECDSA-AES128-GCM-SHA256' => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDSA ECDH       91 :)],
   'ECDHE-ECDSA-AES128-SHA256'     => [qw( HIGH TLSv12 AES    128 SHA256 ECDSA ECDH       91 :)],
   'ECDHE-ECDSA-AES256-GCM-SHA384' => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDSA ECDH       91 :)],
   'ECDHE-ECDSA-AES256-SHA384'     => [qw( HIGH TLSv12 AES    256 SHA384 ECDSA ECDH       91 :)],
   'ECDHE-RSA-AES128-GCM-SHA256'   => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   ECDH       91 :)],
   'ECDHE-RSA-AES128-SHA256'       => [qw( HIGH TLSv12 AES    128 SHA256 RSA   ECDH       91 :)],
   'ECDHE-RSA-AES256-GCM-SHA384'   => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   ECDH       91 :)],
   'ECDHE-RSA-AES256-SHA384'       => [qw( HIGH TLSv12 AES    256 SHA384 RSA   ECDH       91 :)],
   'ECDH-RSA-AES128-GCM-SHA256'    => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDH  ECDH/RSA   91 :)],
   'ECDH-RSA-AES128-SHA256'        => [qw( HIGH TLSv12 AES    128 SHA256 ECDH  ECDH/RSA   91 :)],
   'ECDH-RSA-AES256-GCM-SHA384'    => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDH  ECDH/RSA   91 :)],
   'ECDH-RSA-AES256-SHA384'        => [qw( HIGH TLSv12 AES    256 SHA384 ECDH  ECDH/RSA   91 :)],
   'NULL-SHA256'                   => [qw( weak TLSv12 None     0 SHA256 RSA   RSA         0 :)],

   #-------------------------------------+------+-----+------+---+------+-----+--------+----+--------,
   # from http://tools.ietf.org/html/rfc6655
   'RSA-AES128-CCM'         => [qw( high TLSv12 AESCCM 128 AEAD   RSA   RSA        91 :)],
   'RSA-AES256-CCM'         => [qw( high TLSv12 AESCCM 256 AEAD   RSA   RSA        91 :)],
   'DHE-RSA-AES128-CCM'     => [qw( high TLSv12 AESCCM 128 AEAD   RSA   DH         91 :)],
   'DHE-RSA-AES256-CCM'     => [qw( high TLSv12 AESCCM 256 AEAD   RSA   DH         91 :)],
   'PSK-RSA-AES128-CCM'     => [qw( high TLSv12 AESCCM 128 AEAD   PSK   PSK        91 :)],
   'PSK-RSA-AES256-CCM'     => [qw( high TLSv12 AESCCM 256 AEAD   PSK   PSK        91 :)],
   'ECDHE-RSA-AES128-CCM'   => [qw( high TLSv12 AESCCM 128 AEAD   ECDSA ECDH       91 :)],
   'ECDHE-RSA-AES256-CCM'   => [qw( high TLSv12 AESCCM 256 AEAD   ECDSA ECDH       91 :)],
   'RSA-AES128-CCM-8'       => [qw( high TLSv12 AESCCM 128 AEAD   RSA   RSA        91 :)],
   'RSA-AES256-CCM-8'       => [qw( high TLSv12 AESCCM 256 AEAD   RSA   RSA        91 :)],
   'DHE-RSA-AES128-CCM-8'   => [qw( high TLSv12 AESCCM 128 AEAD   RSA   DH         91 :)],
   'DHE-RSA-AES256-CCM-8'   => [qw( high TLSv12 AESCCM 256 AEAD   RSA   DH         91 :)],
   'PSK-RSA-AES128-CCM-8'   => [qw( high TLSv12 AESCCM 128 AEAD   PSK   PSK        91 :)],
   'PSK-RSA-AES256-CCM-8'   => [qw( high TLSv12 AESCCM 256 AEAD   PSK   PSK        91 :)],
   'ECDHE-RSA-AES128-CCM-8' => [qw( high TLSv12 AESCCM 128 AEAD   ECDSA ECDH       91 :)],
   'ECDHE-RSA-AES256-CCM-8' => [qw( high TLSv12 AESCCM 256 AEAD   ECDSA ECDH       91 :)],

   # from: http://botan.randombit.net/doxygen/tls__suite__info_8cpp_source.html
   #/ RSA_WITH_AES_128_CCM           (0xC09C, "RSA",   "RSA",  "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
   #/ RSA_WITH_AES_256_CCM           (0xC09D, "RSA",   "RSA",  "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
   #/ DHE_RSA_WITH_AES_128_CCM       (0xC09E, "RSA",   "DH",   "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
   #/ DHE_RSA_WITH_AES_256_CCM       (0xC09F, "RSA",   "DH",   "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
   #/ PSK_WITH_AES_128_CCM           (0xC0A5, "",      "PSK",  "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
   #/ PSK_WITH_AES_256_CCM           (0xC0A4, "",      "PSK",  "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
   #/ ECDHE_ECDSA_WITH_AES_128_CCM   (0xC0AC, "ECDSA", "ECDH", "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
   #/ ECDHE_ECDSA_WITH_AES_256_CCM   (0xC0AD, "ECDSA", "ECDH", "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
   #/ RSA_WITH_AES_128_CCM_8         (0xC0A0, "RSA",   "RSA",  "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
   #/ RSA_WITH_AES_256_CCM_8         (0xC0A1, "RSA",   "RSA",  "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
   #/ DHE_RSA_WITH_AES_128_CCM_8     (0xC0A2, "RSA",   "DH",   "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
   #/ DHE_RSA_WITH_AES_256_CCM_8     (0xC0A3, "RSA",   "DH",   "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
   #/ PSK_WITH_AES_128_CCM_8         (0xC0A8, "",      "PSK",  "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
   #/ PSK_WITH_AES_256_CCM_8         (0xC0A9, "",      "PSK",  "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
   #/ ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE, "ECDSA", "ECDH", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
   #/ ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xC0AF, "ECDSA", "ECDH", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
   #-------------------------------------+------+-----+------+---+------+-----+--------+----+--------,
   # from openssl-1.0.1g
   'KRB5-DES-CBC3-MD5'    => [qw(  HIGH SSLv3 3DES   168 MD5    KRB5  KRB5      100 :)],
   'KRB5-DES-CBC3-SHA'    => [qw(  HIGH SSLv3 3DES   168 SHA1   KRB5  KRB5      100 :)],
   'KRB5-IDEA-CBC-MD5'    => [qw(MEDIUM SSLv3 IDEA   128 MD5    KRB5  KRB5       80 :)],
   'KRB5-IDEA-CBC-SHA'    => [qw(MEDIUM SSLv3 IDEA   128 SHA1   KRB5  KRB5       80 :)],
   'KRB5-RC4-MD5'         => [qw(  weak SSLv3 RC4    128 MD5    KRB5  KRB5        0 :)],
   'KRB5-RC4-SHA'         => [qw(  weak SSLv3 RC4    128 SHA1   KRB5  KRB5        0 :)],
   'KRB5-DES-CBC-MD5'     => [qw(   LOW SSLv3 DES     56 MD5    KRB5  KRB5       20 :)],
   'KRB5-DES-CBC-SHA'     => [qw(   LOW SSLv3 DES     56 SHA1   KRB5  KRB5       20 :)],
   'EXP-KRB5-DES-CBC-MD5' => [qw(  WEAK SSLv3 DES     40 MD5    KRB5  KRB5        0 export)],
   'EXP-KRB5-DES-CBC-SHA' => [qw(  WEAK SSLv3 DES     40 SHA1   KRB5  KRB5        0 export)],
   'EXP-KRB5-RC2-CBC-MD5' => [qw(  WEAK SSLv3 RC2     40 MD5    KRB5  KRB5        0 export)],
   'EXP-KRB5-RC2-CBC-SHA' => [qw(  WEAK SSLv3 RC2     40 SHA1   KRB5  KRB5        0 export)],
   'EXP-KRB5-RC4-MD5'     => [qw(  WEAK SSLv3 RC4     40 MD5    KRB5  KRB5        0 export)],
   'EXP-KRB5-RC4-SHA'     => [qw(  WEAK SSLv3 RC4     40 SHA1   KRB5  KRB5        0 export)],

   # from ssl/s3_lib.c
   'FZA-NULL-SHA'          => [qw(  weak SSLv3 None     0 SHA1   KEA   FZA        11 :)],
   'FZA-FZA-SHA'           => [qw(MEDIUM SSLv3 FZA      0 SHA1   KEA   FZA        81 :)],
   'FZA-RC4-SHA'           => [qw(  WEAK SSLv3 RC4    128 SHA1   KEA   FZA        11 :)],
   'RSA-FIPS-3DES-EDE-SHA' => [qw(  high SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS  99 :)],
   'RSA-FIPS-3DES-EDE-SHA' => [qw(  high SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS  99 :)],
   'RSA-FIPS-DES-CBC-SHA'  => [qw(   low SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS  20 :)],
   'RSA-FIPS-DES-CBC-SHA'  => [qw(   low SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS  20 :)],

   # from ...
   'DHE-RSA-CHACHA20-POLY1305'     => [qw(   -?- -?-   ChaCha20-Poly1305 -?- RSA   -?- DH    1 :)],
   'ECDHE-RSA-CHACHA20-POLY1305'   => [qw(   -?- -?-   ChaCha20-Poly1305 -?- RSA   -?- ECDH  1 :)],
   'ECDHE-ECDSA-CHACHA20-POLY1305' => [qw(   -?- -?-   ChaCha20-Poly1305 -?- ECDSA -?- ECDH  1 :)],

   # FIXME: all following
   'EXP-DH-DSS-DES-CBC-SHA'    => [qw( weak  SSLv3 DES    40 SHA1    DSS   DH(512)    0 export)],
   'EXP-DH-RSA-DES-CBC-SHA'    => [qw( weak  SSLv3 DES    40 SHA1    RSA   DH(512)    0 export)],
   'DH-DSS-DES-CBC-SHA'        => [qw(  low  SSLv3 DES    56 SHA1    DSS   DH         20 :)],
   'DH-RSA-DES-CBC-SHA'        => [qw(  low  SSLv3 DES    56 SHA1    RSA   DH         20 :)],
   'DH-DSS-DES-CBC3-SHA'       => [qw( high  SSLv3 3DES   168 SHA1   DSS   DH         80 :)],
   'DH-RSA-DES-CBC3-SHA'       => [qw( high  SSLv3 3DES   168 SHA1   RSA   DH         80 :)],
   'DH-DSS-AES128-SHA256'      => [qw( high TLSv12 AES    128 SHA256 DSS   DH         91 :)],
   'DH-RSA-AES128-SHA256'      => [qw( high TLSv12 AES    128 SHA256 RSA   DH         91 :)],
   'DH-DSS-CAMELLIA128-SHA'    => [qw( high  SSLv3 CAMELLIA 128 SHA1 DSS   DH         81 :)],
   'DH-RSA-CAMELLIA128-SHA'    => [qw( high  SSLv3 CAMELLIA 128 SHA1 DSS   DH         81 :)],
   'DH-DSS-AES256-SHA256'      => [qw( high TLSv12 AES    256 SHA256 DSS   DH         91 :)],
   'DH-RSA-AES256-SHA256'      => [qw( high TLSv12 AES    256 SHA256 RSA   DH         91 :)],
   'DH-DSS-CAMELLIA256-SHA'    => [qw( high  SSLv3 CAMELLIA 256 SHA1 DSS   DH         91 :)],
   'DH-RSA-CAMELLIA256-SHA'    => [qw( high  SSLv3 CAMELLIA 256 SHA1 RSA   DH         91 :)],
   'DH-DSS-SEED-SHA'           => [qw(medium SSLv3 SEED   128 SHA1   DSS   DH         81 :)],
   'DH-RSA-SEED-SHA'           => [qw(medium SSLv3 SEED   128 SHA1   RSA   DH         81 :)],
   'DH-RSA-AES128-GCM-SHA256'  => [qw( high TLSv12 AESGCM 128 AEAD   RSA   DH         91 :)],
   'DH-RSA-AES256-GCM-SHA384'  => [qw( high TLSv12 AESGCM 256 AEAD   RSA   DH         91 :)],
   'DH-DSS-AES128-GCM-SHA256'  => [qw( high TLSv12 AESGCM 128 AEAD   DSS   DH         91 :)],
   'DH-DSS-AES256-GCM-SHA384'  => [qw( high TLSv12 AESGCM 256 AEAD   DSS   DH         91 :)],
   'DHE-PSK-SHA'               => [qw(   -?- -?-   -?-    -?- SHA1   PSK   DHE         1 :)],
   'RSA-PSK-SHA'               => [qw(   -?- -?-   -?-    -?- SHA1   PSK   RSA         1 :)],
   'DHE-PSK-RC4-SHA'           => [qw(   -?- -?-   RC4    -?- SHA1   PSK   PSK         1 :)],
   'DHE-PSK-3DES-SHA'          => [qw(   -?- -?-   3DES   -?- SHA1   PSK   PSK         1 :)],
   'DHE-PSK-AES128-SHA'        => [qw(   -?- -?-   AES    128 SHA1   PSK   PSK         1 :)],
   'DHE-PSK-AES256-SHA'        => [qw(   -?- -?-   AES    256 SHA1   PSK   PSK         1 :)],
   'RSA-PSK-RC4-SHA'           => [qw(   -?- -?-   RC4    -?- SHA1   PSK   PSK         1 :)],
   'RSA-PSK-3DES-SHA'          => [qw(   -?- -?-   3DES   -?- SHA1   PSK   PSK         1 :)],
   'RSA-PSK-AES128-SHA'        => [qw(   -?- -?-   AES    128 SHA1   PSK   PSK         1 :)],
   'RSA-PSK-AES256-SHA'        => [qw(   -?- -?-   AES    256 SHA1   PSK   PSK         1 :)],
   'DHE-PSK-AES128-GCM-SHA256' => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
   'DHE-PSK-AES256-GCM-SHA384' => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
   'RSA-PSK-AES128-GCM-SHA256' => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
   'RSA-PSK-AES256-GCM-SHA384' => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
   'PSK-AES128-SHA256'         => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
   'PSK-AES256-SHA384'         => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
   'PSK-SHA256'                => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
   'PSK-SHA384'                => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],
   'DHE-PSK-AES128-SHA256'     => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
   'DHE-PSK-AES256-SHA384'     => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
   'DHE-PSK-SHA256'            => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
   'DHE-PSK-SHA384'            => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],
   'RSA-PSK-AES128-SHA256'     => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
   'RSA-PSK-AES256-SHA384'     => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
   'RSA-PSK-SHA256'            => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
   'RSA-PSK-SHA384'            => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],

   

);                                                 # %ciphers
   
