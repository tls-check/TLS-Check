package Security::TLSCheck::Result::CSV;

use Moose::Role;
use 5.010;

with "Security::TLSCheck::Result";

=head1 NAME

Security::TLSCheck::Result::CSV -- CSV output role

=head1 VERSION

Version 0.2.x

=cut

#<<<
my $BASE_VERSION = "1.0"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 612 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8


=head1 DESCRIPTION


=cut

use English qw( -no_match_vars );
use List::Util qw(sum);
use POSIX qw(ceil);

use Text::CSV_XS;
use IO::All -utf8;

use Log::Log4perl::EasyCatch;


has outfile => ( is => "ro", isa => "Str", default => q{-}, documentation => "Output file name; - for STDOUT (default)" );


=head1 METHODS

=head2 output 

CSV Output method

Result:

  Category  Module   Class               Class-Description  Runtime   Name        Description         Type   All sum avg median group
  1
            Dummy    ...::Checks::Dummy  Dummy Checks      0.000123    
                                                                     "Test Name" "Test Description"  count  50  150 3   2
                                                                     
=cut


sub output
   {
   my $self = shift;

   INFO "Output: CSV. File: " . $self->outfile;

   my $csv = Text::CSV_XS->new( { binary => 1, sep_char => $self->separator, } );
   my $io = io( $self->outfile );

   $csv->combine(
      qw( Category
         Module Class Class-Description Runtime
         Name Description Type All Sum Mean Percent Median Group )
   );

   $io->println( $csv->string );

   foreach my $category ( sort $self->result_categories )
      {
      DEBUG "Running Aggregation for Category $category";

      $io->println("");
      $io->println("Category $category");

      my $aggregate = $self->aggregate($category);

      foreach my $check_name ( sort keys %$aggregate )
         {
         my $check = $aggregate->{$check_name};

         $csv->combine( undef, $check_name, $check->{class}, $check->{description}, $check->{runtime} )
            or die "Error while creating CSV; broken input: '" . $csv->error_input . "', error: " . $csv->error_diag . "\n";
         $io->println( $csv->string );

         foreach my $result ( @{ $check->{aggregates} } )
            {
            my $group;
            if ( $result->{group} )
               {
               $group = join( ", ",
                              map  { "$ARG => $result->{group}{$ARG}" }
                              sort { $result->{group}{$b} <=> $result->{group}{$a} } keys %{ $result->{group} } );
               }
            else
               {
               $result->{sum} //= 0;
               }

            # TODO: beautify ;) and hash slice instead of map (make a sub with complete array)
            $csv->combine(
                           undef,
                           undef,
                           undef,
                           undef,
                           undef,
                           ( map { $result->{$ARG} } qw(name description type count sum) ),
                           defined $result->{sum} ? $result->{sum} / $result->{count} : undef,
                           defined( $result->{sum} and $result->{type} eq "flag" )
                           ? ( ( $result->{sum} / $result->{count} ) * 100 ) . "%"
                           : undef,
                           $result->{values} ? median( $result->{values} ) : undef,
                           $group,
                         )
               or die "Error while creating CSV; broken input: '" . $csv->error_input . "', error: " . $csv->error_diag . "\n";
            $io->println( $csv->string );
            } ## end foreach my $result ( @{ $check...})

         } ## end foreach my $check_name ( sort...)

      # INFO "Category: $category ", Dumper(  );
      } ## end foreach my $category ( sort...)

   INFO "Output Finished.";

   return;
   } ## end sub output

=head2 median

calculates the median.

=cut

sub median
   {
   my $numbers = shift;
   return unless @$numbers;

   return sum( ( sort { $a <=> $b } map { $ARG // 0 } @$numbers )[ int( $#$numbers / 2 ), ceil( $#$numbers / 2 ) ] ) / 2;
   }

#__PACKAGE__->meta->make_immutable;

1;
