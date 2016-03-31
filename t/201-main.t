#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use FindBin qw($Bin);
use English qw( -no_match_vars );

use Test::More;
use Test::Exception;
use Test::File;
use Test::Differences;


#plan tests => 15;


use_ok("Security::TLSCheck::App");
use_ok("Security::TLSCheck");
can_ok( "Security::TLSCheck", qw(domain timeout user_agent_name) );



my $tc;
lives_ok( sub { $tc = Security::TLSCheck->new( domain => "test.example" ) }, "Can create an tls-check-object" );
isa_ok( $tc, "Security::TLSCheck" );

# moved to the checks!
# is( $tc->www, "www.test.example", "-> is www.test.example" );


#
# Logging Test
#
# clean old logs
unlink glob("$Bin/logs/*");
rmdir "$Bin/logs";

ok( ( not -d "$Bin/logs" ), "Test cleaned log dir" );


mkdir "$Bin/logs";

lives_ok(
   sub {
      $tc = Security::TLSCheck::App->new( log_config => "$Bin/log-test.properties" );
   },
   "Can create an tls-check-object with extra logging"
        );

dir_exists_ok( "$Bin/logs", "new log dir exists" );
file_exists_ok( "$Bin/logs/trace.log", "trace log exists" );
file_contains_like(
                    "$Bin/logs/trace.log",
                    qr(Logging initialised with non-default config),
                    "trace log contains log conf message"
                  );


#
# run_all_checks
#

my $dummy_figures = [
                      {
                         name        => "Length of domain",
                         type        => "int",
                         source      => "get_length",
                         description => "Length of the domain name.",
                         pos         => 0,
                      },
                      {
                         name        => "Top Level Domain",
                         type        => "group",
                         source      => "get_tld",
                         description => "Top level domains.",
                         pos         => 1
                      },
                      { name => "TLD is .de", type => "flag", source => "is_de", description => "Is the TLD .de?", pos => 2, },
                    ];



throws_ok(
   sub {
      $tc = Security::TLSCheck->new( domain => "crash.example",
                                     app    => Security::TLSCheck::App->new( checks => [qw(Nonexistent)] ) );
   },
   qr(Can't locate Security/TLSCheck/Checks/Nonexistent.pm),
   "Crashes when try to use nonexistent check"
         );
$tc = Security::TLSCheck->new( domain => "test.example", app => Security::TLSCheck::App->new( checks => [qw(Dummy)] ) );
my @result = $tc->run_all_checks;
my $result = $tc->run_all_checks;
my $expected = [
   [
      { info => $dummy_figures->[0], value => 12, },
      { info => $dummy_figures->[1], value => "example", },
      { info => $dummy_figures->[2], value => 0,, },

   ],
];

my @check_results           = map { $ARG->{result} } @result;
my @check_names             = map { $ARG->{name} } @result;
my @check_results_from_aref = map { $ARG->{result} } @$result;

# TODO: check for the (new) results in ->{check}
# isa_ok( $result[0]{check},   "Security::TLSCheck::Checks::Dummy", "ISA of arrayref result" );
# isa_ok( $result->[0]{check}, "Security::TLSCheck::Checks::Dummy", "ISA of array result" );
is( scalar @result, scalar @$result, "count of array and arrayref result is the same" );
eq_or_diff( \@check_results, \@check_results_from_aref, "result array and arrayref are the same" );

eq_or_diff( \@check_results, $expected, "result as expected for test.example" );
eq_or_diff( \@check_names, [qw(Dummy)], "result as expected for test.example" );



$tc = Security::TLSCheck->new( domain => "my-tls-check.nonexistent-example.de",
                               app    => Security::TLSCheck::App->new( checks => [qw(Dummy)] ) );
@check_results = map { $ARG->{result} } $tc->run_all_checks;
$expected = [
   [
      { info => $dummy_figures->[0], value => 35, },
      { info => $dummy_figures->[1], value => "de", },
      { info => $dummy_figures->[2], value => 1, },

   ],
];

eq_or_diff( \@check_results, $expected, "arrayref result for my-tls-check.nonexistent-example.de" );



#
# Todo: mehr wenn mehr da!
#


done_testing();

