package Security::TLSCheck::Checks::AgeDE;

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;

use LWP::UserAgent;


=head1 NAME

Security::TLSCheck::Checks::AgeDE - Checks, if a host has an age-de.xml file

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 662 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION

This test looks for a file named age-de.xml in the root directory and parses it if exists.

age-de.xml is a german standard for age labeling for child protection filter programs. 
It's very rarely used but will be a standard by german law.

The ages are:   0, 6, 12, 16, 18

XML parsing not really started, it's only simple regexes

TODO: Parse XML

=cut

#<<<

{
my $key_figures = 
   [
   { name => "Has age-de.xml",        type => "flag",   source => "has_age_de_xml",      description => "A file /age-de.xml file exists, but maybe redirected", lazy_build => 1, }, 
   { name => "Looks like age-de.xml", type => "flag",   source => "has_age_declaration", description => "Content looks like a real age-de.xml",    }, 
   { name => "Default age",           type => "group",  source => "default_age",         description => "The default age from age-de.xml", }, 
   { name => "Min age",               type => "group",  source => "min_age",             description => "The minimum age, from age-de.xml" }, 
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "Checks if a site supports german age rating labels 'age-de.xml'" );

has age_de_xml      => (is => "rw", isa => "Str",  );

#>>>


=head1 METHODS

=head2 run_check

runs the main check 

Here: tries to get the age-de.xml file and stores it's content in attribute 
C<age_de_xml>.


=cut

sub run_check
   {
   my $self = shift;

   my $www = $self->www;

   unless ( $self->other_check("Security::TLSCheck::Checks::Web")->http_active )
      {
      DEBUG "Skipped AgeDE tests for $www because no HTTP active";
      return;
      }

   # build user agent (instead of LWP::Simple or IO::All),
   # because we need to set agent and timeout etc ...
   my $ua = LWP::UserAgent->new( timeout => $self->timeout, agent => $self->user_agent_name, );
   my $response = $ua->get("http://$www/age-de.xml");

   $self->age_de_xml( $response->decoded_content ) if $response->is_success;


   return $self->result;

   } ## end sub run_check

=head2 has_age_de_xml

Returns true if there is a age_de_xml. 

Since redirects are accepted, this might be the start page 
or an error page (when no error code is set) etc. So, this does not mean, 
that there is really an age-de.xml!

=cut

sub has_age_de_xml
   {
   my $self = shift;
   return 1 if $self->age_de_xml;
   return;
   }


=head2 has_age_declaration

A simple check, if there is really an age-de.xml.

=cut

sub has_age_declaration
   {
   my $self = shift;
   if ( ( $self->age_de_xml // "" ) =~ m{<age-declaration}ix )
      {
      TRACE "FOUND age-Declaration for " . $self->www;    # Debug
      return 1;
      }
   return;
   }

=head2 default_age

Gets the default age from an existing age-de.xml or undef;

=cut

sub default_age
   {
   my $self = shift;
   my ($default_age) = ( $self->age_de_xml // "" ) =~ m{ <default-age>\s* (\d+) }sx;
   TRACE "FOUND default-age '$default_age' for " . $self->www if defined $default_age;
   return $default_age;
   }


=head2 min_age

Gets the minage from an existing age-de.xml or undef;

=cut

sub min_age
   {
   my $self = shift;
   my ($min_age) = ( $self->age_de_xml // "" ) =~ m{ <min-age>\s* (\d+) }sx;
   TRACE "FOUND min-age '$min_age' for " . $self->www if defined $min_age;
   return $min_age;
   }



__PACKAGE__->meta->make_immutable;

1;
