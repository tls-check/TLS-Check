#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::MockObject;

use Time::HiRes qw(time);

plan tests => 19;


#
# fake check for testing
#

package MyTest::Checks;

use Moose;

extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

has call_runtime => ( is => "rw", isa => "Bool" );

sub run_check
   {
   my $self = shift;

   $self->runtime if $self->call_runtime;

   return $self;

   }


#
# use the fake check
#

package main;


my $mock = Test::MockObject->new();
my $mock_with_domain = Test::MockObject->new();
$mock_with_domain->set_always( domain => "test.example" );


dies_ok( sub { my $check = MyTest::Checks->new(); }, "without instance object" );
# The domain attibute is now directly delegated from instance and not build manually ...
#throws_ok( sub { my $domain = MyTest::Checks->new( instance => $mock )->domain; }, qr(Missing domain), "without domain in instance object" );

my $check;
lives_ok( sub { $check = MyTest::Checks->new( instance => $mock_with_domain ); }, "with domain in instance object" );
is($check->domain, "test.example", "Domain korrekt");
is($check->www(), "www.test.example", "WWW korrekt");



$check = MyTest::Checks->new( instance => $mock, call_runtime => 1 );

isa_ok( $check, "MyTest::Checks" );
can_ok( $check, qw(run_check runtime start_time end_time) );

is( $check->start_time, undef, "Start time undef before start" );
is( $check->end_time,   undef, "End time undef before start" );

dies_ok( sub { $check->runtime }, "runtime dies before start" );
like( $@, qr{No start time}, "runtime dies before start message" );

dies_ok( sub { $check->run_check }, "runtime dies inside run_check" );
like( $@, qr{No end time}, "runtime dies inside run_check message" );



$check->call_runtime(0);

lives_ok( sub { $check->run_check }, "call run_check" );
lives_ok( sub { $check->runtime },   "call runtime now ok" );

ok( $check->start_time > ( time - 1 ), "Start time is not older then 1 second" );
ok( $check->end_time > $check->start_time, "end time is after start time" );
ok( $check->end_time < time,               "End time is before now" );
ok( $check->runtime < 1,                   "Runtime below 1 second" );

is( $check->name, "MyTest::Checks", "->name" );



