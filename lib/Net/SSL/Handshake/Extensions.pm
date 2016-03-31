package Net::SSL::Handshake::Extensions;

=encoding utf8

=head1 NAME

Net::SSL::Handshake::Extensions - Base class for TLS handshake extensions

=head1 VERSION

Version 0.2.x, $Revision: 640 $


=cut


=head1 SYNOPSIS

  extends "Net::SSL::Handshake::Extensions";
  sub BUILD 
     {
     my $self = shift;
     $self->add($pack_pattern, @data);
     }

=head1 DESCRIPTION

The base class for TLS extensions. Used by each extension Class. 

For example see Net::SSL::Handshake::Extensions::EllipticCurves or 
Net::SSL::Handshake::Extensions::ECPointFormats.



=cut


use Moose;


has extension_template => (
                            is      => "ro",
                            isa     => "Str",
                            traits  => ['String'],
                            default => "",
                            handles => { add_extension_template => "append", clear_extension_template => "clear", }
                          );
has _extension_data => (
                       is      => "ro",
                       isa     => "ArrayRef",
                       traits  => ['Array'],
                       default => sub { [] },
                       handles => { add_extension_data => "push", clear_extension_data => "clear", extension_data => "elements", }
);

has type => ( is => "ro", isa => "Int", default => sub { die "Subclass must set default value!" }, );


=head2 ->data

Returns the binary string for this extension.

=cut

sub data
   {
   my $self = shift;
   my $extension_data = pack( $self->extension_template,$self->extension_data );
   return pack( "n n a*",  $self->type, length($extension_data), $extension_data );
   }

=head2 ->add($pattern, @data)

Adds the data for this extension.

=cut

sub add
   {
   my $self     = shift;
   my $template = shift;
   $self->add_extension_data(@_);

   $self->add_extension_template($template);

   return $self;
   }


1;
