#!perl

use strict;
use warnings;

use Test::More;

use FindBin qw($Bin);

#unless ( $ENV{RELEASE_TESTING} || $ENV{TEST_AUTHOR} )
#   {
#   plan( skip_all => "Author tests not required for installation (set TEST_AUTHOR)" );
#   }

BEGIN
{

   eval "use Test::Perl::Critic; use Perl::Critic::Utils;";
   if ($@)
      {
      Test::More::plan( skip_all => "Test::Perl::Critic required for testing PBP compliance" );
      }
}

#if ( $INC{'Devel/Cover.pm'} )
#   {
#   Test::More::plan( skip_all => "Perl::Critic tests are too slow with 'testcover'!" );
#   }


# TODO:
# Move this into perlcriticrc

Test::Perl::Critic->import(
   -profile  => "$Bin/perlcriticrc",
   -severity => 1,
   -verbose  => $ENV{PC_VERBOSE} // 11,
   -exclude  => [
      qw(
         RequirePodSections
         RequirePodAtEnd

         Documentation::PodSpelling

         ValuesAndExpressions::ProhibitConstantPragma
         ValuesAndExpressions::ProhibitInterpolationOfLiterals
         ValuesAndExpressions::RequireInterpolationOfMetachars
         ValuesAndExpressions::ProhibitEmptyQuotes
         ValuesAndExpressions::RequireConstantVersion

         RegularExpressions::RequireDotMatchAnything
         RegularExpressions::RequireLineBoundaryMatching

         References::ProhibitDoubleSigils

         CodeLayout::ProhibitTrailingWhitespace
         CodeLayout::ProhibitParensWithBuiltins

         ControlStructures::ProhibitPostfixControls
         ControlStructures::ProhibitUnlessBlocks


         Modules::RequireVersionVar
         Miscellanea::ProhibitUnrestrictedNoCritic

         )
   ]
);


# exclude helpers, external scripts etc
my @files = grep { not m{ (?: auto/share | (?:bin|script)/(?:test|helper) ) }x } all_perl_files("$Bin/../blib");

plan tests => scalar @files;


my @failed;

foreach my $file (@files)
   {
   SKIP:
      {
      skip "check_ciphers_single_domains must be rewritten", 1 if $file =~ m{check_ciphers_single_domains}x;
      critic_ok($file) or push @failed, $file;
      }
   }


foreach my $failed (@failed)
   {
   diag "  Perl::Critic failed for: $failed";
   }


