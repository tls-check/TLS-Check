package MooseX::ListAttributes;

use Moose::Role;

use 5.010;
use English qw( -no_match_vars );
use Data::Dumper;

# use Readonly;

has show_options => ( is => "ro", isa => "Bool", default => 0,         documentation => "List all Options" );
has undef_string => ( is => "ro", isa => "Str",  default => "<undef>", documentation => "String for undef with show_options" );

=head1 SYNOPSIS

  with 'MooseX::ListAttributes';
  
  # later, inside a method
  $self->usage if $self->show_options;
  
=head1 DESCRIPTION

Adds an after modifier to an existing usage method

=head1 METHODS

=head2 list_attributes

Lists all attributes of this class.

=cut

# Readonly my $UNDEF => "<undef>";

sub list_attributes
   {
   my $self = shift;

   print "\n $PROGRAM_NAME wurde mit den folgenden Werten gestartet:\n\n";
   print "   Attribut/Option    | Aktueller Wert                 | Default \n";
   print "----------------------+--------------------------------+--------------------------\n";

   # alle Attribute durchsuchen ...
   foreach my $attr ( sort { $a->name cmp $b->name } $self->meta->get_all_attributes )
      {
      next unless $attr->documentation;
      my $attr_name = $attr->name;

      next if $attr_name =~ m{^_}x;

      my $value = $self->$attr_name // $self->undef_string;
      $value = "[" . join( ", ", @$value ) . "]" if ref $value eq "ARRAY";

      my $default = $attr->default // $self->undef_string;
      $default = &$default() if ref $default eq "CODE";    # for hash/array-Ref-Defaults
      $default = "[" . join( ", ", @$default ) . "]" if ref $default eq "ARRAY";

      $value = "<like default>" if $value eq $default;

      printf " %-20s | %-30s | %-30s\n", "--$attr_name", $value, $default;
      }

   print "\n";
   print "Uebergebene CLI-Parameter beim Aufruf: ", join( " ", @{ $self->ARGV } ) . "\n\n";

   return;
   };                                              ## end after usage



1;
