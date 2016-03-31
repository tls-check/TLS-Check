#!/usr/bin/env perl

use 5.010;
use strict;

use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::Deep;
use Test::Differences;

use List::Util;


use English qw( -no_match_vars );


use Data::Dumper;


# plan tests => 1234;

use_ok("Net::SSL::CipherSuites");
can_ok(
    "Net::SSL::CipherSuites" => qw(new_with_all new_by_name new_by_tag unique add remove remove_first_by_code remove_all_by_code )
);

# Bettercrypto A:
#      DHE-RSA-AES256-GCM-SHA384
#      DHE-RSA-AES256-SHA256
#      ECDHE-RSA-AES256-GCM-SHA384
#      ECDHE-RSA-AES256-SHA384

# TODO: Review the tests.
# They are hacky (because adapted from old procedural interface)

my $bc_a  = Net::SSL::CipherSuites->new_by_tag("bettercrypto_a")->ciphers;
my $bc_a2 = Net::SSL::CipherSuites->new()->new_by_tag("bettercrypto_a")->ciphers;

cmp_deeply( $bc_a, bag(@$bc_a2), "Ciphers by Tag: explicit new and implizit new are the same" )
   or diag Dumper( $bc_a, $bc_a2 );
is( scalar @$bc_a, 4, "via Tag: 4 Bettercrypto A ciphers" );
cmp_deeply( [ map { $_->{shortname} } @$bc_a ],
            bag(qw(ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 DHE-RSA-AES256-SHA256 DHE-RSA-AES256-GCM-SHA384)),
            "Bettercrypto A via Tag" );

my $ciphers = Net::SSL::CipherSuites->new();

isa_ok( $ciphers, "Net::SSL::CipherSuites" );

my $bc_b = $ciphers->new_by_tag("bettercrypto_b")->ciphers;

is( scalar @$bc_b, 18, "via Tag: 18 Bettercrypto B ciphers" );

cmp_deeply( [ map { $_->{shortname} } @$bc_b ],
            superbagof(qw(ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 DHE-RSA-AES256-SHA256 DHE-RSA-AES256-GCM-SHA384)),
            "Bettercrypto B (via Tag) contains all A" );

my $unique = $ciphers->new_by_tag("bettercrypto_b")->unique->ciphers;
is( scalar @$unique, 18, "Bettercrypto B still 18 after unique" );

# ->unique changes internally and returns a copy of obj reference
cmp_deeply( $bc_b, bag(@$unique), "unique is the same as BC B" );

$ciphers = Net::SSL::CipherSuites->new_by_tag(qw(bettercrypto_a bettercrypto_b));

is( scalar $ciphers->count, 22, "both bettercrypto lists with duplicates count 22" );
$ciphers->unique;
is( scalar $ciphers->count, 18, "both bettercrypto lists without duplicates count 18" );

cmp_deeply( $ciphers->ciphers, bag(@$bc_b), "After unique: BC A and BC B is the same as BC B" ),


   my $onecipher = Net::SSL::CipherSuites->new_by_name("ECDHE-RSA-AES256-GCM-SHA384");
is( $onecipher->count,              1,      "found 1 cipher ECDHE-RSA-AES256-GCM-SHA384 by short name" );
is( $onecipher->ciphers->[0]{code}, "C030", "Code for ECDHE-RSA-AES256-GCM-SHA384 is C030" );

my $onecipher2 = Net::SSL::CipherSuites->new->new_by_name("ECDHE_RSA_WITH_AES_256_GCM_SHA384");
is( $onecipher2->count,              1,      "found 1 cipher ECDHE_RSA_WITH_AES_256_GCM_SHA384 by full name" );
is( $onecipher2->ciphers->[0]{code}, "C030", "Code for ECDHE_RSA_WITH_AES_256_GCM_SHA384 is C030" );

cmp_deeply( $onecipher->ciphers, $onecipher2->ciphers, "search for short and long name are the same" );

# not found ciphers
my $nocipher = $ciphers->new_by_name("I am no cipher");
is( $nocipher->count, 0, "no cipher found by name" );
cmp_deeply( $nocipher->ciphers, [], "empty cipher list by name" );

$nocipher = $ciphers->new_by_tag("I am no cipher");
is( $nocipher->count, 0, "no cipher found by tag" );
cmp_deeply( $nocipher->ciphers, [], "empty cipher list by tag" );

$onecipher = $ciphers->new_by_name( "ECDHE-RSA-AES256-GCM-SHA384", "no cipher name" );
is( $onecipher->count,              1,      "find cipher with one not found element after real cipher" );
is( $onecipher->ciphers->[0]{code}, "C030", "Code for ECDHE-RSA-AES256-GCM-SHA384 is C030" );

$onecipher = $ciphers->new_by_name( "no cipher name", "ECDHE-RSA-AES256-GCM-SHA384" );
is( $onecipher->count,              1,      "find cipher with one not found element" );
is( $onecipher->ciphers->[0]{code}, "C030", "Code for ECDHE-RSA-AES256-GCM-SHA384 is still C030" );


# empty tag
$ciphers = Net::SSL::CipherSuites->new_by_tag(qw(bettercrypto_a this-is-no-tag bettercrypto_b))->unique;
is( $ciphers->count, 18, "search for tags with a not found tag" );
cmp_deeply( $ciphers->ciphers, bag( @{$bc_b} ), "search for tags with a not found tag, but found some content" );



$ciphers->new_by_name(qw(ECDHE-RSA-AES256-GCM-SHA384 no cipher names ECDHE_RSA_WITH_AES_256_GCM_SHA384))->unique;
is( $ciphers->count,              1,      "unique and array" );
is( $ciphers->ciphers->[0]{code}, "C030", "unique and array with correct code" );


my $expected_total               = 455;
my $expected_total_unique        = 362;
my $expected_v2_ciphers          = 14;
my $expected_v3_ciphers          = 123;            # 124-1 SSLv3 Ciphers (001E is duplicate!)
my $expected_v3_or_later_ciphers = $expected_total_unique - $expected_v2_ciphers - 9;


my $all = $ciphers->new_with_all();
is( $all->count, $expected_total, "Total number of all ciphers, with duplicates: $expected_total" );


$all->unique;
is( $all->count,
    $expected_total_unique, "Total number of all ciphers, without duplicates (except 00xxxx SSLv2): $expected_total_unique" );


my ( $cipher_spec, $cipher_spec_sslv2 );

lives_ok sub { $cipher_spec = Net::SSL::CipherSuites->new_by_tag("bettercrypto_a")->order_by_code->cipher_spec; },
   "Generate TLS Cipher Spec";
lives_ok sub { $cipher_spec_sslv2 = Net::SSL::CipherSuites->new_by_tag("bettercrypto_a")->order_by_code->cipher_spec_sslv2; },
   "Generate SSLv2 Cipher Spec";

is( length($cipher_spec),       4 * 2, "Cipher Spec has correct length" );
is( length($cipher_spec_sslv2), 4 * 3, "Cipher Spec for SSLv2 has correct length" );


# 006b DHE-RSA-AES256-SHA256
# 009f DHE-RSA-AES256-GCM-SHA384
# c028 ECDHE-RSA-AES256-SHA384
# c030 ECDHE-RSA-AES256-GCM-SHA384

sub to_hex
   {
   return join( " ", map { sprintf "%02X", $ARG } unpack( "C*", shift ) );
   }

is( $cipher_spec, "\x00\x6b\x00\x9f\xc0\x28\xc0\x30", "TLS Cipher Spec OK" )
   or diag( "Is: " . to_hex($cipher_spec) );
is( $cipher_spec_sslv2, "\x00\x00\x6b\x00\x00\x9f\x00\xc0\x28\x00\xc0\x30", "SSLv2 Cipher Spec OK" )
   or diag( "Is: " . to_hex($cipher_spec_sslv2) );

throws_ok sub { $cipher_spec = Net::SSL::CipherSuites->new_by_tag("SSLv2")->cipher_spec; },
   qr(Can't use SSLv2-only Cipher),
   "SSLv3/TLS can't use 3 byte ciphers";

undef $ciphers;

throws_ok( sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec("\x12\x34\x56\x67\x90\xff\xf1\x23"); },
           qr(Cipher 1234 not found),
           "Ciphers from cipher-spec: wrong cipher!" );

lives_ok( sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec("\x00\x6b\x00\x9f\xc0\x28\xc0\x30"); },
          "Ciphers from cipher-spec" );
isa_ok( $ciphers, "Net::SSL::CipherSuites", "cipher object created by cipher_spec" );

is( $ciphers->count, 4, "4 ciphers from cipher-spec" );

cmp_deeply( [ map { $ARG->{shortname} } @{ $ciphers->ciphers } ],
            [qw(DHE-RSA-AES256-SHA256 DHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-AES256-GCM-SHA384)],
            "Found Ciphers correct from spec" );

#
# Test with SSLv2 Cipher-Spec
# Usually SSLv2 does not support this ciphers; but the cipher spec is OK
#
undef $ciphers;

throws_ok( sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec_sslv2("\x12\x34\x56\x67\x90\xff\xf1\x23\x01"); },
           qr(Cipher with Code 123456 does not exist),
           "Ciphers from SSLv2 cipher-spec: wrong cipher!" );

lives_ok(
          sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec_sslv2("\x00\x00\x6b\x00\x00\x9f\x00\xc0\x28\x00\xc0\x30"); }
          ,
          "Ciphers from SSLv2 cipher-spec"
        );
isa_ok( $ciphers, "Net::SSL::CipherSuites", "cipher object created by SSLv2 cipher_spec" );

is( $ciphers->count, 4, "4 ciphers from SSLv2 cipher-spec" );

cmp_deeply( [ map { $ARG->{shortname} } @{ $ciphers->ciphers } ],
            [qw(DHE-RSA-AES256-SHA256 DHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-AES256-GCM-SHA384)],
            "Found Ciphers correct from SSLv2 cipher-spec" );

#
# Convert SSLv2 cipher spec ackwards
#

undef $cipher_spec;
undef $ciphers;
my $sslv2_ciphers;
lives_ok sub { $sslv2_ciphers = Net::SSL::CipherSuites->new_by_tag("SSLv2")->order_by_code; }, "All SSLv2 Cipher";
is( $sslv2_ciphers->count, $expected_v2_ciphers, "14 SSLv2 Ciphers" );

lives_ok( sub { $cipher_spec = $sslv2_ciphers->cipher_spec_sslv2 }, "Get the Cipher-Spec from All SSLv2 Ciphers" );
lives_ok( sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec_sslv2($cipher_spec) },
          "Cipher-Obj from all SSLv2 Ciphers as Cipher-Spec" );
cmp_deeply( $ciphers->ciphers, $sslv2_ciphers->ciphers, "SSLv2 Cipher list is the same after converting via cipher spec" );


undef $cipher_spec;
undef $ciphers;
my $sslv3_ciphers;
lives_ok sub { $sslv3_ciphers = Net::SSL::CipherSuites->new_by_tag("SSLv3")->unique->order_by_code; }, "All SSLv3 Ciphers";
is( $sslv3_ciphers->count, $expected_v3_ciphers, "124-1 SSLv3 Ciphers (001E is duplicate!)" );

lives_ok( sub { $cipher_spec = $sslv3_ciphers->cipher_spec }, "Get the Cipher-Spec from All SSLv3 Ciphers" );
lives_ok( sub { $ciphers = Net::SSL::CipherSuites->new_by_cipher_spec($cipher_spec) },
          "Cipher-Obj from all SSLv3 Ciphers as Cipher-Spec" );

# Remove problematic ciphers with duplicate code
# TODO: maybe change internal cipherlist, FF00 and FF01 are duplicates and should be merged

$ciphers->remove_all_by_code(qw(FF00 FF01));
$sslv3_ciphers->remove_all_by_code(qw(FF00 FF01));



cmp_deeply(
            [ map         { $ARG->{name} } @{ $ciphers->ciphers } ],
            subbagof( map { $ARG->{name} } @{ $sslv3_ciphers->ciphers } ),
            "SSLv3 Cipher list from cipher spec contains all ciphers"
          );

$ciphers->unique->order_by_code;
cmp_deeply( $ciphers->ciphers, $sslv3_ciphers->ciphers,
            "SSLv3 Cipher list is the same after converting via cipher spec and unique+order" );


# Tests for adding ciphers


# 4
my @names_a = qw(
   ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
   );

# 5
my @names_b = qw(
   ADH_WITH_AES_128_SHA256
   ADH_WITH_AES_256_SHA256
   RSA_WITH_AES_128_GCM_SHA256
   RSA_WITH_AES_256_GCM_SHA384
   DHE_RSA_WITH_AES_128_GCM_SHA256
   );

# 7
my @names_c = qw(
   RSA_WITH_ARIA_256_CBC_SHA384
   DH_DSS_WITH_ARIA_256_CBC_SHA384
   DH_RSA_WITH_ARIA_128_CBC_SHA256
   DH_RSA_WITH_ARIA_256_CBC_SHA384
   DHE_DSS_WITH_ARIA_256_CBC_SHA384
   DHE_RSA_WITH_ARIA_128_CBC_SHA256
   DHE_RSA_WITH_ARIA_256_CBC_SHA384
   );

$ciphers = Net::SSL::CipherSuites->new;

lives_ok( sub { $ciphers->add( Net::SSL::CipherSuites->new_by_name(@names_a) ); }, "lives add via object" );
is( $ciphers->count, 4, "->add (via object): 4 ciphers after add A to empty" );

lives_ok( sub { $ciphers->add( Net::SSL::CipherSuites->new_by_name(@names_b)->ciphers ); }, "lives add via arrayref" );
is( $ciphers->count, 9, "->add (via arrayref): 9  ciphers after add B" );

lives_ok( sub { $ciphers->add( @{ Net::SSL::CipherSuites->new_by_name(@names_c)->ciphers } ); }, "lives add via array" );
is( $ciphers->count, 16, "->add (via array): 16 ciphers after add C" );

lives_ok(
   sub {
      $ciphers->add(
                     @{ Net::SSL::CipherSuites->new_by_name(@names_a)->ciphers },
                     Net::SSL::CipherSuites->new_by_name(@names_b)->ciphers,
                     Net::SSL::CipherSuites->new_by_name(@names_a),
                   );
   },
   "lives add via mixed"
        );

# added all correct? (A B C A B A)
is( $ciphers->count, 29, "->add (via array): 16 ciphers after add C" );
eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ],
            [ @names_a, @names_b, @names_c, @names_a, @names_b, @names_a, ],
            "Added correct ciphers" );


# And remove

lives_ok( sub { $ciphers->remove_first_by_code(qw(C023 C02B C024 C02C)); }, "remove first by code" );
is( $ciphers->count, 25, "->remove_first_by_code: count" );

eq_or_diff(
            [ map { $ARG->{name} } @{ $ciphers->ciphers } ],
            [ @names_b, @names_c, @names_a, @names_b, @names_a, ],
            "remove_first: Removed correct ciphers"
          );

lives_ok( sub { $ciphers->remove_all_by_code(qw(C023 C02B C024 C02C)); }, "remove first by code" );
is( $ciphers->count, 17, "->remove_all_by_code: count" );

eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ],
            [ @names_b, @names_c, @names_b, ],
            "remove_all: Removed correct ciphers" );


lives_ok( sub { $ciphers->remove( Net::SSL::CipherSuites->new_by_name(@names_b) ); }, "remove by object" );
is( $ciphers->count, 7, "->remove: count" );

eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ], [@names_c], "remove: Removed all B ciphers via object" );


lives_ok(
   sub {
      $ciphers->add( Net::SSL::CipherSuites->new_by_name(@names_a),
                     Net::SSL::CipherSuites->new_by_name(@names_b),
                     Net::SSL::CipherSuites->new_by_name(@names_c),
                   );
   },
   "Add again some ciphers for later removing ..."
        );

is( $ciphers->count, 23, "->add agains: count" );

eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ], [ @names_c, @names_a, @names_b, @names_c ], "added again OK" );

lives_ok(
   sub {
      $ciphers->remove( Net::SSL::CipherSuites->new_by_name(@names_b)->ciphers,
                        @{ Net::SSL::CipherSuites->new_by_name(@names_c)->ciphers, } );
   },
   "remove ciphers arrayref, array"
        );
is( $ciphers->count, 4, "after ->remove: count available ciphers (A!)" );

eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ], [@names_a], "removed OK, only A remains" );


lives_ok(
   sub {
      $ciphers->remove( Net::SSL::CipherSuites->new_by_name(@names_b)->ciphers,
                        @{ Net::SSL::CipherSuites->new_by_name(@names_c)->ciphers, } );
   },
   "Try to remove already removed ciphers again ..."
        );
is( $ciphers->count, 4, "still the same ciphers there (count)" );
eq_or_diff( [ map { $ARG->{name} } @{ $ciphers->ciphers } ], [@names_a], "still the same ciphers there (names)" );


lives_ok(
   sub {
      $ciphers->remove( Net::SSL::CipherSuites->new_by_name(@names_a),
                        Net::SSL::CipherSuites->new_by_name(@names_b),
                        Net::SSL::CipherSuites->new_by_name(@names_c),
                      );
   },
   "Remove A, B, C -- from a cipher list with only A ..."
        );

is( $ciphers->count, 0, "Empty Cipher list." );


lives_ok(
   sub {
      $ciphers->remove( Net::SSL::CipherSuites->new_by_name(@names_a),
                        Net::SSL::CipherSuites->new_by_name(@names_b),
                        Net::SSL::CipherSuites->new_by_name(@names_c),
                      );
   },
   "Try to remove from empty list"
        );

is( $ciphers->count, 0, "Still empty Cipher list." );



#
# Checks for split_ciphers
#

undef $ciphers;
lives_ok(
   sub {
      $ciphers = Net::SSL::CipherSuites->new_by_tag("sslv3_or_later")->unique->order_by_code;
   },
   "new by tag sslv3_or_later"
        );

is( $ciphers->count, $expected_v3_or_later_ciphers, "# of ciphers to start with" );

my @parts = $ciphers->split_into_parts();
is(scalar @parts, 5, "all v3 ciphers are splitted into 4 parts by default");
is($parts[0]->count, 73, "96 Ciphers in part 1");


undef $ciphers;
lives_ok(
   sub {
      $ciphers = Net::SSL::CipherSuites->new_with_all()->unique;
   },
   "new with all for split"
        );

is( $ciphers->count, $expected_total_unique, "# of ciphers to start with" );

@parts = $ciphers->split_into_parts();
is(scalar @parts, 5, "all ciphers are splitted into 5 parts by default");
is($parts[0]->count, 73, "73 Ciphers in part 1 ");

@parts = $ciphers->split_into_parts(2); # sslv2 split ...
is(scalar @parts, 8, "all ciphers are splitted into 8 parts for v2-Cipher-spec and default bytes");
is($parts[0]->count, 48, "48 Ciphers in part 1");


@parts = $ciphers->split_into_parts(2, 50); # sslv2, 50 bytes ... (results in max 48 byte spec!)
is(scalar @parts, 23, "all ciphers are splitted into 23 parts for v2-Cipher-spec and max 50 bytes");
is($parts[0]->count, 16, "16 Ciphers in part 1");

@parts = $ciphers->split_into_parts(0x0301, 50); # TLSv1.0, 50 bytes ...
is(scalar @parts, 15, "all ciphers are splitted into 15 parts for v3+-Cipher-spec and max 50 bytes");
is($parts[0]->count, 25, "25 Ciphers in part 1");

@parts = $ciphers->split_into_parts(0x0301); # TLSv1.0, default bytes ...
is(scalar @parts, 5, "all ciphers are splitted into 5 parts for v3+-Cipher-spec and default bytes");
is($parts[0]->count, 73, "73 Ciphers in part 1");



done_testing();

