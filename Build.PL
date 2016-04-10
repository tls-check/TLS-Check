use 5.016;
use strict;
use warnings FATAL => 'all';
use Module::Build;

my $builder = Module::Build->new(
   module_name        => 'Security::TLSCheck',
   license            => 'artistic_2',
   dist_author        => q{Alvar C.H. Freude <alvar@a-blast.org>},
   dist_version_from  => 'lib/Security/TLSCheck.pm',
   release_status     => 'testing',
   configure_requires => {
                           'Module::Build' => 0,
                         },
   test_requires => {
                      'Test::More'           => 0,
                      'Test::Exception'      => 0.25,
                      'Test::MockObject'     => 1.20140408,
                      'Test::LWP::UserAgent' => 0.025,
                      'Test::File'           => 1.41,
                      'Test::Differences'    => 0.62,
                      'Test::Deep'           => 0.113,
                      'Test::Perl::Critic'   => 1.03,
                      'Test::Pod::Coverage'  => 1.10,
                      'Test::Pod'            => 1.22,
                      'IPC::Run'             => 0.90,
                      'Pod::Coverage'        => 0.22,
                    },

   share_dir => {
      module => {
                  'Net::SSL::CipherSuites'                => [ 'files/CipherSuites', ],
                  'Security::TLSCheck::App::DomainFilter' => [ 'files/DomainFilter', ],
                  'Security::TLSCheck'                    => [ 'conf', 'bin/ext', ],
                },

      #dist => [ 'conf', ],

                },

   #   config_files => {
   #      '' => '',
   #   },


   # TODO:
   # Check minimal required versions!
   # this versions are set to my installed versions at writing time ...
   # usually it should work with older versions of this modules, but this
   # is not tested.
   requires => {
                 'Moose'                 => 2.1213,
                 'MooseX::Getopt'        => 0.65,
                 'MooseX::SimpleConfig'  => 0.10,
                 'Net::DNS'              => 0.80,
                 'Log::Log4perl'         => 1.44,
                 'Net::LibIDN'           => 0.12,             # Needed by Net::DNS
                 'Net::DNS::RR::DS'      => 0.20,
                 'LWP::Protocol::https'  => 6.06,
                 'Text::CSV_XS'          => 1.11,
                 'IO::All'               => 0.79,
                 'Config::General'       => 2.56,
                 'Readonly'              => 2,
                 'Mozilla::CA'           => 20141217,
                 'Net::SMTP'             => 3.04,
                 'IO::Socket::Timeout'   => 0.29,
                 'File::ShareDir'        => 1.102,
                 'IO::Socket::SSL'       => 2.016,
                 'LWP::UserAgent'        => 6.06,
                 'PerlIO::via::Timeout'  => 0.30,
                 'Parallel::ForkManager' => 1.11,             # make this OPTIONAL!
                 'File::HomeDir'         => 1.0,
                 'Net::IDN::Encode'      => 2.202,            # maybe replace by Net::LibIDN
                 'autodie'               => 2.23,             # at least version from Perl 5.20, because of sleep bugs
               },
   add_to_cleanup     => ['Security-TLSCheck-*'],
   create_makefile_pl => 'traditional',
                                );

$builder->create_build_script();


# FreeBSD Ports:
# portmaster devel/p5-Config-General devel/p5-IO-All www/p5-libwww www/p5-LWP-Protocol-https devel/p5-Log-Log4perl devel/p5-Moose devel/p5-MooseX-Getopt devel/p5-MooseX-SimpleConfig dns/p5-Net-DNS dns/p5-Net-DNS-RR-SRV-Helper dns/p5-Net-LibIDN textproc/p5-Text-CSV_XS devel/p5-Test-Exception devel/p5-Test-File devel/p5-Test-MockObject
