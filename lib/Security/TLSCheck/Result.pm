package Security::TLSCheck::Result;

use Moose::Role;
use 5.010;


=head1 NAME

Security::TLSCheck::Result -- Result storage, aggregation and output

=head1 VERSION

Version 0.2.x

=cut

#<<<
my $BASE_VERSION = "1.0"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 626 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8


=head1 DESCRIPTION


=cut

use English qw( -no_match_vars );
use FindBin qw($Bin);
use Data::Dumper;

use Log::Log4perl::EasyCatch;


has results => (
                 is      => "ro",
                 isa     => "HashRef[Any]",
                 default => sub { {} },
                 traits  => ['Hash'],
                 handles => {
                              result_categories   => "keys",
                              result_for_category => "get",
                            },
               );



=head1 METHODS


=head2 add_result_for_category( $category => $result )

Helper method for adding a result.

=cut

sub add_result_for_category
   {
   my $self     = shift;
   my $category = shift;
   my $result   = shift;

   push @{ $self->results->{$category} }, @$result;
   push @{ $self->results->{"All Categories (Summary)"} }, @$result;

   return;
   }


=head2 aggregate

Aggregates all values for output


%result is:

   (
   Name => 
      {
      class      => "Security::TLSCheck::Checks::Name",
      aggregates => 
      count      => 
      },
   OtherName => .....
   )


=cut

my %agg_functions = (
                      flag  => \&_agg_flag,
                      count => \&_agg_count,
                      int   => \&_agg_count,
                      num   => \&_agg_count,
                      group => \&_agg_group,
                      set   => \&_agg_set,
                    );

sub _agg_flag
   {
   my $agg   = shift;
   my $value = shift;

   $agg->{sum}++ if $value;
   $agg->{count}++;

   return;
   }

sub _agg_count
   {
   my $agg   = shift;
   my $value = shift;

   $agg->{sum} += $value // 0;
   push @{ $agg->{values} }, $value;               # for median
   $agg->{count}++;

   return;
   }

sub _agg_group
   {
   my $agg = shift;
   my $value = shift // "<undef>";

   $agg->{group}{$value}++;
   $agg->{count}++;

   return;
   }

sub _agg_set
   {
   my $agg = shift;
   my $value = shift // "<undef>";

   $agg->{group}{$ARG}++ foreach split(/:/, $value);
   $agg->{count}++;

   return;
   }




sub aggregate
   {
   my $self     = shift;
   my $category = shift;

   my %result;
   
   foreach my $check ( @{ $self->result_for_category($category) } )
      {

      my $class = $check->{check}{class};

      # no, this is TOO noisy! 
      # TRACE "Aggregate check $check->{name} in class $class";

      # check exists in result?
      if ( $result{ $check->{name} } )
         {
         die
            "Class name of test $check->{name} does not match: $class vs. $result{$check->{name}}{class} -- duplicate check names?\n"
            if $class ne $result{ $check->{name} }{class};
         }
      else
         {
         $result{ $check->{name} }{class}       = $class;
         $result{ $check->{name} }{description} = $check->{check}{description};
         }

      $result{ $check->{name} }{count}++;
      $result{ $check->{name} }{runtime} += $check->{check}{runtime};

      # next unless $check->{result};
      for my $pos ( 0 .. $#{ $check->{result} } )
         {
         die "Name of check #$pos in $check->{name} differs!\n"
            if $result{ $check->{name} }{aggregates}[$pos]
            and $result{ $check->{name} }{aggregates}[$pos]{name} ne $check->{result}[$pos]{info}{name};

         $result{ $check->{name} }{aggregates}[$pos]{name}        //= $check->{result}[$pos]{info}{name};
         $result{ $check->{name} }{aggregates}[$pos]{description} //= $check->{result}[$pos]{info}{description};
         $result{ $check->{name} }{aggregates}[$pos]{type}        //= $check->{result}[$pos]{info}{type};

         my $agg_func = $agg_functions{ $check->{result}[$pos]{info}{type} }
            or die "No aggregate function for type $check->{result}[$pos]{info}{type}\n";

         &$agg_func( $result{ $check->{name} }{aggregates}[$pos], $check->{result}[$pos]{value} );

         }


      } ## end foreach my $check ( @{ $self...})


   return \%result;
   } ## end sub aggregate


=head2 output

Prints the result.

A subcluss usually overrides this with some more special output (CSV, ...)

=cut

sub output
   {
   my $self = shift;

   foreach my $category ( $self->result_categories )
      {
      DEBUG "Running Aggregation for Category $category";
      INFO "Category: $category ", Dumper( $self->aggregate($category) );
      }

   return;
   }

#__PACKAGE__->meta->make_immutable;

1;                                                 # End of TLS::Check
