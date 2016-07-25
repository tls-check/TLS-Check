package Security::TLSCheck::Checks::Dummy;

#
# Eech check is usually a Moose class, extending Security::TLSCheck::Checks
# Or in other words: a subclass of Security::TLSCheck::Checks
#                    or inheriting Security::TLSCheck::Checks
#
# Security::TLSCheck::Checks has the base methods for getting all results.
#
# And each check should use the Role Security::TLSCheck::Checks::Helper::Timing,
# Which sets start and end time for the check automatically.
#
# Othervise the check MUST set start_time and end_time manually.
#

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;


=head1 NAME

Security::TLSCheck::Checks::Dummy - Simple dummy check as example

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 658 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

  tls-check.pl --checks=Dummy [...]


=head1 DESCRIPTION

This test does not much; it is only a dummy example for testing and presentsation.

=cut

#<<<

#
# An info block with all sub tests
# All tests have a name and description, a data type of the result and the 
# source method. The method with the name of the source will be called to 
# get the result of each key figure.
#

{
my $key_figures = 
   [
   { name => "Length of domain", type => "int",   source => "get_length", description => "Length of the domain name.", }, 
   { name => "Top Level Domain", type => "group", source => "get_tld",    description => "Top level domains.", }, 
   { name => "TLD is .de",       type => "flag",  source => "is_de",      description => "Is the TLD .de?" }, 
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "Dummy Checks" );

#>>>

#
# This example check has NO C<run_check> method, it uses this from the
# base class C<Security::TLSCheck::Checks>. This only calls the result
# method, and this collects everything from the methods given in the
# above defined key figures.
# THe C<run_check> method can be used to initiate some states or whatever,
# but in this example this is not necessary.
#

=head1 METHODS

Here are the methods, used by the key figures of this test.

=head2 get_length

gets the length of the domain name

=cut

sub get_length
   {
   my $self = shift;
   return length( $self->domain );
   }


=head2 get_tld

gets the tld

=cut

sub get_tld
   {
   my $self = shift;
   my ($tld) = $self->domain =~ m{ ([^.]+) $ }x;
   return $tld;
   }


=head2 is_de

returns true, if the TLD is .de

=cut

sub is_de
   {
   my $self = shift;
   return 1 if $self->get_tld eq "de";
   return 0;
   }


__PACKAGE__->meta->make_immutable;

1;
