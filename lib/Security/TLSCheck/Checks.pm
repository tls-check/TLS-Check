package Security::TLSCheck::Checks;

use 5.010;
use strict;
use warnings;

use Carp;
use Scalar::Util qw(blessed);
use English qw( -no_match_vars );

use Moose;

use Log::Log4perl::EasyCatch;


=head1 NAME

Security::TLSCheck::Checks - Base class for all checks

=encoding utf8

=cut

#<<<
my $BASE_VERSION = "1.0"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 658 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

As check subclass:

 package Security::TLSCheck::Checks::MyCheck
 
 use Moose;
 extends 'Security::TLSCheck::Checks'

 has '+description' => ( default => "Checking my checks");

 
As caller:

 use Security::TLSCheck::Checks::MyCheck;
 
 my $check = Security::TLSCheck::Checks::MyCheck->new();
 say "Check Name:        " . $check->name;
 say "Check Description: " . $check->description;

 my @results = $check->run_check;
 
 say "Check runtime: " . $check->runtime;


=head1 DESCRIPTION

Base class for all checks. Defines all common attributes, and helper methods.

For a project overview, see the README.md of the Distribution.



=cut


#<<<

has name        => ( is => 'ro', isa => 'Str', lazy_build => 1, );
has class       => ( is => 'ro', isa => 'Str', lazy_build => 1, );
has www         => ( is => "ro", isa => "Str", lazy_build => 1, );
has description => ( is => 'ro', isa => 'Str', default    => "no description" );
has error       => ( is => 'rw', isa => 'Str', );

has key_figures => ( is => "ro", isa => "ArrayRef[HashRef[Str]]", auto_deref => 1, default => sub { [] } );

has instance    => ( is => 'rw', isa => 'Object', required => 1, handles => [qw(domain category timeout user_agent_name my_hostname other_check)], predicate => "has_instance", clearer => "clear_instance",);

has start_time  => ( is => 'rw', isa => 'Num' );
has end_time    => ( is => 'rw', isa => 'Num' );

#>>>


=head1 METHODS

=head2 BUILD



=cut

sub BUILD
   {
   my $self = shift;

   # Mark position in key_figures with their own number
   # with this info the key figure data in the result can be
   # replaces by a ref to the all-time same key_figure
   # in fork mode, this may save much memory
   my $key_figures = $self->key_figures;

   for my $pos ( 0 .. $#{$key_figures} )
      {
      $key_figures->[$pos]{pos} = $pos;
      }

   return $self;
   }


=head2 _build_name

Default name is name of the package, without the basename.

=cut

sub _build_name
   {
   my $self = shift;

   ( my $name = $self->class ) =~ s{Security::TLSCheck::Checks::}{}x;

   return $name;

   }

=head2 _build_class

Default name is name of the package, without the basename.

=cut

sub _build_class
   {
   return blessed(shift);
   }

=head2 _build_www

generaters "www.domain" from domain.

Very simple at the moment: only prepends www.

=cut

sub _build_www
   {
   my $self = shift;

   return "www." . $self->domain;
   }


=head2 ->runtime

Returns the runtime in seconds of this check.

=cut


sub runtime
   {
   my $self = shift;

   defined $self->start_time or croak "No start time set!";
   defined $self->end_time   or croak "No end time set!";

   return $self->end_time - $self->start_time;
   }


=head2 ->run_check

Default for runing all tests: the tests are started via the method calls 
of key_figures in the result method.

So, this method only calls the result method and returns its return value.

For more complex runs override run_check.

=cut


sub run_check
   {
   my $self = shift;

   return $self->result;
   }



=head2 result

calculates the result, according to the C<key_figures> attribute.

Returns a array(ref) of hashrefs:

  [
     {
     info  => { name => "My Name", type => "flag", ... },
     value => 3,
     },
  
  ]

=cut

sub result
   {
   my $self = shift;

   DEBUG "build result for " . $self->name . ", domain " . $self->domain;
   my @result = map { $self->_get_value($ARG) } $self->key_figures;
   DEBUG "OK, result built for " . $self->name . ", domain " . $self->domain;

   return \@result;                                # wantarray ? @result : \@result;
   }


sub _get_value
   {
   my $self       = shift;
   my $key_figure = shift;

   my $source_method = $key_figure->{source};
   my $value         = $self->$source_method;

   # temp, until we handle more types
   # when it is only a flag, then switch to 1 or 0
   $value = $value ? 1 : 0 if $key_figure->{type} eq "flag";

   return {
      #            name  => $key_figure->{name},
      #            type  => $key_figure->{type},
      value => $value,
      info  => $key_figure,
   };

   }


#=head2 key_figure_info_by_name
#
#Gets an key_figure info hash(ref) by the name of the check
#
#=cut
#
#sub key_figure_info_by_name
#   {
#   my $self = shift;
#
#
#
#   }


__PACKAGE__->meta->make_immutable;

1;
