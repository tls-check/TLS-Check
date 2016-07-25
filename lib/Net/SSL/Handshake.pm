package Net::SSL::Handshake;

use Moose;

use English qw( -no_match_vars );
use IO::Socket::INET;
use IO::Socket::Timeout qw(IO::Socket::INET);
use Net::IDN::Encode qw(domain_to_ascii);
use Readonly;
use Carp qw(croak);

use 5.010;

use Net::SSL::CipherSuites;
use Net::SSL::Handshake::Extensions::ServerName;
use Net::SSL::Handshake::Extensions::EllipticCurves;
use Net::SSL::Handshake::Extensions::ECPointFormats;


#
# TODO: move all SSL/TLS Constants in extra module
#

use Exporter qw(import);

my @ssl_versions = qw($SSLv2 $SSLv3 $TLSv1 $TLSv11 $TLSv12);

our @EXPORT_OK = ( @ssl_versions, qw(%CONTENT_TYPE) );
our %EXPORT_TAGS = ( all => \@EXPORT_OK, ssl_versions => \@ssl_versions, );

Readonly my $MT_CLIENT_HELLO => 1;
Readonly my $MT_SERVER_HELLO => 4;


Readonly our $SSLv2  => 0x0002;
Readonly our $SSLv3  => 0x0300;
Readonly our $TLSv1  => 0x0301;
Readonly our $TLSv11 => 0x0302;
Readonly our $TLSv12 => 0x0303;

Readonly our %CONTENT_TYPE => (
                                change_cipher_spec => 20,
                                alert              => 21,
                                handshake          => 22,
                                application_data   => 23,
                                early_handshake    => 25,
                              );


Readonly our %HANDSHAKE_TYPE => (
                                  client_hello         => 1,
                                  server_hello         => 2,
                                  session_ticket       => 4,
                                  hello_retry_request  => 6,
                                  encrypted_extensions => 8,
                                  certificate          => 11,
                                  certificate_request  => 13,
                                  certificate_verify   => 15,
                                  server_configuration => 17,
                                  finished             => 20,
                                );



Readonly our %ALERT_LEVEL => (
                               warning => 1,
                               fatal   => 2,
                             );

Readonly our %ALERT_LEVEL_REVERSE => reverse %ALERT_LEVEL;

Readonly our %ALERT_DESCRIPTION => (
                                     close_notify                    => 0,
                                     unexpected_message              => 10,
                                     bad_record_mac                  => 20,
                                     decryption_failed_RESERVED      => 21,
                                     record_overflow                 => 22,
                                     decompression_failure_RESERVED  => 30,
                                     handshake_failure               => 40,
                                     no_certificate_RESERVED         => 41,
                                     bad_certificate                 => 42,
                                     unsupported_certificate         => 43,
                                     certificate_revoked             => 44,
                                     certificate_expired             => 45,
                                     certificate_unknown             => 46,
                                     illegal_parameter               => 47,
                                     unknown_ca                      => 48,
                                     access_denied                   => 49,
                                     decode_error                    => 50,
                                     decrypt_error                   => 51,
                                     export_restriction_RESERVED     => 60,
                                     protocol_version                => 70,
                                     insufficient_security           => 71,
                                     internal_error                  => 80,
                                     inappropriate_fallback          => 86,
                                     user_canceled                   => 90,
                                     no_renegotiation_RESERVED       => 100,
                                     missing_extension               => 109,
                                     unsupported_extension           => 110,
                                     certificate_unobtainable        => 111,
                                     unrecognized_name               => 112,
                                     bad_certificate_status_response => 113,
                                     bad_certificate_hash_value      => 114,
                                     unknown_psk_identity            => 115,
                                   );

Readonly our %ALERT_DESCRIPTION_REVERSE => reverse %ALERT_DESCRIPTION;


# not exported: no vars, constant
Readonly my $BIT_15        => 2**15;               # or 0x8000
Readonly my $BITS_01111111 => 0x7f;


=encoding utf8

=head1 NAME

Net::SSL::Handshake - SSL Handshake on an existing connection or open a new one

=head1 VERSION

Version 0.1.x, $Revision: 658 $

=cut

use version; our $VERSION = qv( "v0.1." . ( sprintf "%d", q$Revision: 658 $ =~ /(\d+)/xg ) );



=head1 SYNOPSIS

=encoding utf8

 my $handshake = Net::SSL::Handshake->new( 
   socket   => $socket, 
   timeout  => $timeout, 
   host     => $hostname, 
   port     => $port,
   ciphers  => $ciphers,
   ); 
 $handshake->hello;
 
 
   
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
=head1 DESCRIPTION


Attributes:

  Tieouts for IO::Socket::Timeout (read, write)
  Default: read from socket obj???? or 30 seconds? or whatelse!
  
  socket
  
  version
  
  random and other parameters to ssl etc (default random)

+++ IDN via Net::IDN::Encode (for SNI)

Modules:

  Net::SSL::StartTLS::SMTP, ...
  
 
 
 Peter Mosman openssl: https://github.com/PeterMosmans/openssl/
 
 
# Build OpenSSL TEST!

  git clone https://github.com/PeterMosmans/openssl.git --depth 1 -b 1.0.2-chacha openssl-chacha
  
  # config, make & Inst
  CFLAGS="-O3 -fno-strict-aliasing -pipe -march=native -mtune=native  -fstack-protector"  ./Configure darwin64-x86_64-cc --prefix=/Users/alvar/Documents/Code/externes/openssl-chacha/installdir --openssldir=/Users/alvar/Documents/Code/externes/openssl-chacha/installdir/openssl   enable-asm threads shared zlib enable-ssl2 enable-ssl3 enable-md2 enable-rc5 no-gmp no-rfc3779 enable-ec_nistp_64_gcc_128 zlib no-shared experimental-jpake enable-md2 enable-rc5 enable-rfc3779 enable-gost enable-static-engine 
  make depend && make && make test && make report && make install
  
  # Via: https://github.com/jvehent/cipherscan

# cert list

  openssl ciphers -l -V ALL:eNULL:aNULL 
  /Users/alvar/Documents/Code/externes/openssl-chacha/installdir/bin/openssl ciphers -l -V ALL:eNULL:aNULL 



# Self singned cert:
openssl req -new -newkey rsa:2048 -days 36500 -nodes -x509 -keyout server.pem -out server.pem

# Server: man s_server

# Install openssl with SSLv2 and SSLv3 etc

  CFLAGS="-O3 -fno-strict-aliasing -pipe -march=native -mtune=native  -fstack-protector"  ./Configure darwin64-x86_64-cc --prefix=/Users/alvar/Documents/Code/externes/openssl-1.0.2d/installdir --openssldir=/Users/alvar/Documents/Code/externes/openssl-1.0.2d/installdir/openssl   enable-asm threads shared zlib zlib-dynamic  enable-ssl2 enable-ssl3 enable-md2 enable-rc5 no-gmp no-rfc3779 enable-ec_nistp_64_gcc_128
  make depend
  make && make test && make install


# Start server

  Users/alvar/Documents/Code/externes/openssl-1.0.2d/installdir/bin/openssl s_server -HTTP -accept 443

# oder mit www



# Standard TLS/SSL handshake
handshake_pkts = {
"TLS v1.3": '\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20',
"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
"SSL v2.0": '\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
}

https://github.com/iphelix/sslmap/blob/master/sslmap.py

=head2 SSL Handshake


https://github.com/iphelix/sslmap/blob/master/sslmap.py

https://labs.portcullis.co.uk/tools/ssl-cipher-suite-enum/

https://github.com/drwetter/testssl.sh
https://testssl.sh


pack types:

  C unsigned 8 bit char
  n unsigned short, 16 bit, network order
  a binary string, NULL padded





=head3 SSLv2 


Client sends 


Client hello max 256 bytes for F5! (Bug) https://code.google.com/p/chromium/issues/detail?id=245500
Fixed at least since 09/29/2011


Client-Hello SSLv2:

  #  Header
  n  Message len | 0x8000
   
  # Data. len: message len
  C  Message Type: SSL_MT_CLIENT_HELLO
  n  Client-Version
  n  Cipher spec len
  n  Session-ID len   => 0
  n  challenge len
  a* cipher spec data
  a* session id data  => empty
  a* challenge data

alternative header (3 bytes):

  #  Header
  n  Message len 
  C  Padding (number of bytes added at the end of data part!)



=head3 SSLv3 and TLS 




  
  C     record Type      / SSL record type = 22 (SSL3_RT_HANDSHAKE)
  n     SSL Version      
  n     Record len
  
  # Record:
  C     Message Type     / Handshake type
  C     0x00             / Length of data to follow in this record (3 Bytes!)
  n     Message len      / Length rest
  
  ## Data
  n     SSL/TLS Version
  a[32] challenge
  C     session ID len
  n     cipher spec len
  a*    cipher spec
  C     compression method len (1)
  C*    compression method  (0x00)
  n     length extensions
  a*    extensions data 


  ## Extensions: SNI, 
  



  # Hello Extensions format:

  n  extension type
  n  Length extension data
  a* data
  
  
  # data for hello extension sni:
  
  n  len of list (bytes)
  C  Nametype (host_name: 0x00)
  n  len host name
  a* hostname (IDN!)


      $clientHello_extensions = pack(
                                      "n n n C n a[$clientHello{'extension_sni_len'}]",
                                      $clientHello{'extension_type_server_name'},          #n
                                      $clientHello{'extension_len'},            #n
                                      $clientHello{'extension_sni_list_len'},   #n
                                      $clientHello{'extension_sni_type'},       #C
                                      $clientHello{'extension_sni_len'},        #n
                                      $clientHello{'extension_sni_name'},       #a[$clientHello{'extension_sni_len'}]
                                    );


  





         "n a[32] C n a[$clientHello{'cipher_spec_len'}] C C[$clientHello{'compression_method_len'}] a[$clientHello{'extensions_total_len'}]",
         $clientHello{'version'},                  # n
         $clientHello{'challenge'},                # A[32] = gmt + random [4] + [28] Bytes
         $clientHello{'session_id_len'},           # C
         $clientHello{'cipher_spec_len'},          # n
         $clientHello{'cipher_spec'},              # A[$clientHello{'cipher_spec_len'}]
         $clientHello{'compression_method_len'},   # C (0x01)
         $clientHello{'compression_method'},       # C[len] (0x00)
         $clientHello_extensions                   # optional
                             );



https://www-01.ibm.com/support/knowledgecenter/#!/SSB23S_1.1.0.10/com.ibm.ztpf-ztpfdf.doc_put.10/gtps5/s5rcd.html?cp=SSB23S_1.1.0.10%2F0-1-8-2-3


possible handshake types:

   SSL3_MT_HELLO_REQUEST            0   (x'00')
   SSL3_MT_CLIENT_HELLO             1   (x'01')
   SSL3_MT_SERVER_HELLO             2   (x'02')
   SSL3_MT_CERTIFICATE             11   (x'0B')
   SSL3_MT_SERVER_KEY_EXCHANGE     12   (x'0C')
   SSL3_MT_CERTIFICATE_REQUEST     13   (x'0D')
   SSL3_MT_SERVER_DONE             14   (x'0E')
   SSL3_MT_CERTIFICATE_VERIFY      15   (x'0F')
   SSL3_MT_CLIENT_KEY_EXCHANGE     16   (x'10')
   SSL3_MT_FINISHED                20   (x'14') 





      $clientHello{'msg_len'}    = length($clientHello_tmp);
      $clientHello{'record_len'} = $clientHello{'msg_len'} + 4;

      $clientHello = pack(
                           "C n n C C n a*",
                           $clientHello{'record_type'},              # C
                           $clientHello{'record_version'},           # n
                           $clientHello{'record_len'},               # n
                           $clientHello{'msg_type'},                 # C
                           0x00,                                     # C (0x00)
                           $clientHello{'msg_len'},                  # n
                           $clientHello_tmp                          # a
                         );





Server-Hello:

  




The SSL Handshake Protocol defines the following errors:

NO-CIPHER-ERROR
This error is returned by the client to the server when it cannot find a cipher or key size that it supports that is also supported by the server. 
This error is not recoverable.



=cut


has record_template => (
                         is      => "ro",
                         isa     => "Str",
                         traits  => ['String'],
                         default => "",
                         handles => { add_record_template => "append", clear_record_template => "clear", },
                       );
has _record_data => (
                      is      => "ro",
                      isa     => "ArrayRef",
                      traits  => ['Array'],
                      default => sub { [] },
                      handles => { add_record_data => "push", clear_record_data => "clear", record_data => "elements", },
                    );

#<<<


has socket           => ( is => "ro", isa => "Object",                 handles => [qw(send recv )], lazy => 1, builder => "_build_socket", clearer => "close", );
has host             => ( is => "ro", isa => "Str", );
has port             => ( is => "ro", isa => "Int",                    default => 443, );
has error            => ( is => "rw", isa => "Int",                    default => 0, );
has ciphers          => ( is => "ro", isa => "Net::SSL::CipherSuites", required => 1, );
has accepted_ciphers => ( is => "rw", isa => "Net::SSL::CipherSuites", default => sub { Net::SSL::CipherSuites->new });
has timeout          => ( is => "ro", isa => "Int",                    default => 60, );
has ssl_version      => ( is => "ro", isa => "Int",                    default => $TLSv12, );
has sni              => ( is => "ro", isa => "Bool",                   default => 1, );

# Server messages
has server_version   => ( is => "rw", isa => "Int", ); 
has server_cert      => ( is => "rw", isa => "Str", );

has ok               => (is => "ro",  isa => "Bool", writer => "_ok", );


# TODO: readonly with private writer!
has alert             => ( is => "rw", isa => "Bool", );
has no_cipher_found   => ( is => "rw", isa => "Bool", );
has alert_level       => ( is => "rw", isa => "Str", );
has alert_description => ( is => "rw", isa => "Str", );

#>>>

sub _build_socket
   {
   my $self = shift;

   die __PACKAGE__ . ": need parameter socket or host!\n" unless $self->host;

   my $idn_host = domain_to_ascii( $self->host );

   my $socket = IO::Socket::INET->new( Timeout => $self->timeout, PeerAddr => $idn_host, PeerPort => $self->port )
      // die __PACKAGE__ . ": Can't connect to ${ \$self->host }:${ \$self->port }: $OS_ERROR\n";

   IO::Socket::Timeout->enable_timeouts_on($socket);
   $socket->read_timeout( $self->timeout );
   $socket->write_timeout( $self->timeout );

   return $socket;
   }

# for some Debug
#sub _to_hex
#   {
#   return join( " ", map { sprintf "%02X", $ARG } unpack( "C*", shift ) );
#   }
#

=head2 send_record

sends the record to the server

=cut

sub send_record
   {
   my $self = shift;
   my $content_type = shift // $CONTENT_TYPE{handshake};

   # say _to_hex( $self->record_as_string($content_type) );

   $self->send( $self->record_as_string($content_type) ) // croak "Error while sending data";

   # TODO: TImeout check!

   $self->clear_record;                            # oder beim aufruf?

   return;
   }


=head2 add_to_record

adds a template and some data to a record


=cut

sub add_to_record
   {
   my $self    = shift;
   my $pattern = shift;
   my @data    = @ARG;

   $self->add_record_template($pattern);
   $self->add_record_data(@data);

   return $self;
   }


=head2 record_as_string

returns the record as a string; checks for SSLv2/ SSLv3 / TLS

=cut


sub record_as_string
   {
   my $self         = shift;
   my $content_type = shift;

   my $record_data = pack( $self->record_template, $self->record_data );

   my $record_header;

   if ( $self->ssl_version == $SSLv2 )
      {
      $record_header = pack( "n", length($record_data) | $BIT_15 );
      }
   else
      {
      $record_header = pack( "C n n", $content_type, $self->ssl_version == $SSLv3 ? $SSLv3 : $TLSv1, length($record_data), );
      }

   return $record_header . $record_data;

   } ## end sub record_as_string

=head2 clear_record

clears the template etc

=cut

sub clear_record
   {
   my $self = shift;
   $self->clear_record_template;
   $self->clear_record_data;
   return $self;
   }

=head2 challenge

generate some random ...

=cut

sub challenge
   {
   return
      pack( "NC[28]", time, ( map { int( rand(256) ) } ( 1 .. 28 ) ) );  ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
   }


=head2 close_notify

send a "close notify" alert

=cut

sub close_notify
   {
   my $self = shift;

   $self->add_to_record( "CC", 1, 0 );
   $self->send_record( $CONTENT_TYPE{alert} );

   return $self;
   }

=head2 ->hello

Send client hello, receive and parse server hello.

...

=cut

sub hello
   {
   my $self = shift;

   $self->build_client_hello;
   $self->send_record;
   $self->receive_record;

   $self->close_notify unless $self->ssl_version == $SSLv2;
   $self->close;

   return $self;
   }


=head2 build_client_hello

build client hello message

=cut

sub build_client_hello
   {
   my $self = shift;

   my $cipher_spec = $self->ciphers->cipher_spec( $self->ssl_version );

   if ( $self->ssl_version == $SSLv2 )
      {
      #  C  Message Type: SSL_MT_CLIENT_HELLO
      #  n  Client-Version
      #  n  Cipher spec len
      #  n  Session-ID len   => 0
      #  n  challenge len (usually 32)
      #  a* cipher spec data
      #  a* session id data  => empty
      #  a* challenge data

      $self->add_to_record(
                            "Cnnnna*a[0]a[32]", $MT_CLIENT_HELLO,           $self->ssl_version, length($cipher_spec),
                            0,                  length( $self->challenge ), $cipher_spec,       "",
                            $self->challenge
                          );
      }
   else
      {

      #   uint8 CipherSuite[2];    /* Cryptographic suite selector */
      #
      #   enum { null(0), (255) } CompressionMethod;
      #
      #   struct {
      #       ProtocolVersion client_version = { 3, 4 };    /* TLS v1.3 */
      #       Random random;
      #       SessionID session_id;
      #       CipherSuite cipher_suites<2..2^16-2>;
      #       CompressionMethod compression_methods<1..2^8-1>;
      #       Extension extensions<0..2^16-1>;
      #   } ClientHello;
      #

      # von außen: erst record, dann handshare-record, dann client-hello.

      # build ClientHello
      my $cipher_spec_len = length($cipher_spec);

      my $extensions = $self->build_extensions;
      my $client_hello = pack(
                               "n a[32] C n a[$cipher_spec_len] C C a*",
                               $self->ssl_version,
                               $self->challenge,
                               0,
                               length($cipher_spec),
                               $cipher_spec,
                               1,                                        # compression len
                               0,                                        # compression type
                               $extensions,
                             );

      #
      #         struct {
      #       HandshakeType msg_type;    /* handshake type */
      #       uint24 length;             /* bytes in message */
      #       select (HandshakeType) {
      #           case client_hello:        ClientHello;
      #           case server_hello:        ServerHello;
      #           case hello_retry_request: HelloRetryRequest;
      #           case encrypted_extensions: EncryptedExtensions;
      #           case server_configuration:ServerConfiguration;
      #           case certificate:         Certificate;
      #           case certificate_request: CertificateRequest;
      #           case certificate_verify:  CertificateVerify;
      #           case finished:            Finished;
      #           case session_ticket:      NewSessionTicket;
      #       } body;
      #   } Handshake;


      $self->add_to_record(
                            "C C n a*",
                            $HANDSHAKE_TYPE{client_hello},
                            0,                                        # first byte length (type C)
                            length($client_hello),
                            $client_hello,
                          );


      } ## end else [ if ( $self->ssl_version...)]

   return $self;
   } ## end sub build_client_hello


=head2 ->build_extensions

Builds the hello extensions

=cut

sub build_extensions
   {
   my $self = shift;

   my $extensions = "";

   $extensions .= Net::SSL::Handshake::Extensions::ServerName->new( hostname => $self->host )->data if $self->sni;
   $extensions .= Net::SSL::Handshake::Extensions::ECPointFormats->new()->data;
   $extensions .= Net::SSL::Handshake::Extensions::EllipticCurves->new()->data;

   # $extensions .= ...

   return pack( "n a*", length($extensions), $extensions );
   }



=head2 receive_record

receive and parse server record ...

=cut

sub receive_record
   {
   my $self = shift;

   my $data;
   $self->recv( $data, 1 );
   croak "Nothing received!" unless length($data);

   my $content_type = unpack( "C", $data );

   # return $self->sslv2_server_hello($data) if $content_type & 0x80;    # = $MT_SERVER_HELLO;

   $content_type &= $BITS_01111111;                # 0x7f -- remove highest bit of 1 byte type
   return $self->sslv2_server_hello($content_type) if $content_type == $MT_SERVER_HELLO;

   undef $data;
   $self->recv( $data, 2 + 2 );                    # protocol version and record length (à 16 bit)
   croak "no protocol-version/length received" unless length($data);

   my ( $protocol_version, $record_lenght ) = unpack( "nn", $data );

   $self->server_version($protocol_version);

   undef $data;
   $self->recv( $data, $record_lenght ) // die "FATAL: No data!\n";

   return $self->parse_handshake($data) if $content_type == $CONTENT_TYPE{handshake};
   return $self->parse_alert($data)     if $content_type == $CONTENT_TYPE{alert};
   die "Ups, the Server sent a NOT IMPLEMENTED ContentType: $content_type\n";
   } ## end sub receive_record


=head2 parse_handshake($data)

Parse SSLv3+ Handshake


=cut


sub parse_handshake
   {
   my $self = shift;
   my $data = shift;

   my ( $msg_type, $zero, $length, $rest ) = unpack( "C C n a*", $data );

   die "Expected server_hello, got $msg_type\n" if $msg_type != $HANDSHAKE_TYPE{server_hello};



   # TLS 1.3!!!
   #  struct {
   #       ProtocolVersion server_version;
   #       Random random;
   #       CipherSuite cipher_suite;
   #       select (extensions_present) {
   #           case false:
   #               struct {};
   #           case true:
   #               Extension extensions<0..2^16-1>;
   #       };
   #   } ServerHello;

   # SSLv3 ==> TLS 1.2:
   #      struct {
   #          ProtocolVersion server_version;
   #          Random random;
   #          SessionID session_id;
   #          CipherSuite cipher_suite;
   #          CompressionMethod compression_method;
   #          select (extensions_present) {
   #              case false:
   #                  struct {};
   #              case true:
   #                  Extension extensions<0..2^16-1>;
   #          };
   #      } ServerHello;

   my ( $server_version, $random, $session_id_len, $rest2 ) = unpack( "n a[32] C a*", $rest );
   my ( $session_id, $cipher_suite, $compression_method, $extensions ) = unpack( "a[$session_id_len] a[2] C a*", $rest2 );

   $self->server_version($server_version);

   if ( length($cipher_suite) )
      {
      $self->accepted_ciphers->add( Net::SSL::CipherSuites->new_by_cipher_spec($cipher_suite) );
      $self->_ok(1);
      }


   return $self;
   } ## end sub parse_handshake


=head2 sslv2_server_hello


SERVER-HELLO (Phase 1; Sent in the clear)

   0 char MSG-SERVER-HELLO
   1 char SESSION-ID-HIT
   2 char CERTIFICATE-TYPE
   3 char SERVER-VERSION-MSB
   4 char SERVER-VERSION-LSB
   5 char CERTIFICATE-LENGTH-MSB
   6 char CERTIFICATE-LENGTH-LSB
   7 char CIPHER-SPECS-LENGTH-MSB
   8 char CIPHER-SPECS-LENGTH-LSB
   9 char CONNECTION-ID-LENGTH-MSB
  10 char CONNECTION-ID-LENGTH-LSB
    char CERTIFICATE-DATA[MSB<<8|LSB]
    char CIPHER-SPECS-DATA[MSB<<8|LSB]
    char CONNECTION-ID-DATA[MSB<<8|LSB]


=cut

Readonly my $SERVER_HELLO_HEAD_LEN => 11;

sub sslv2_server_hello
   {
   my $self       = shift;
   my $first_byte = shift;


   my $data;
   $self->recv( $data, 1 );

   my $record_len = unpack( "n", "$first_byte$data" );

   undef $data;
   $self->recv( $data, $record_len );

   die "Not enough Data for SSLv2 record!\n" unless length($data);

   #
   # all received; parse data ...
   #

   my ( $msg, $session_id_hit, $cert_type, $server_version, $cert_len, $cipher_spec_len, $connection_id_len, $rest )
      = unpack( "C C C n n n n a*", $data );

   die "Got no cert len at unpack SSLv2 server hello; got not enough data?\n" unless $cert_len;

   my ( $cert_data, $cipher_spec, $connection_id ) = unpack( "a[$cert_len] a[$cipher_spec_len] a[$connection_id_len]", $rest );


   $self->server_version($server_version);
   $self->server_cert($cert_data);

   die "Wrong Server Version: $server_version\n" if $server_version != $SSLv2;

   if ( length($cipher_spec) )
      {
      $self->accepted_ciphers->add( Net::SSL::CipherSuites->new_by_cipher_spec_sslv2($cipher_spec) );
      $self->_ok(1);
      }

   return $self;
   } ## end sub sslv2_server_hello


=head2 parse_alert

parse alert message

=cut

# TODO: what should be the API? ;-)

sub parse_alert
   {
   my $self = shift;
   my $data = shift;

   $self->alert(1);
   my ( $alert_level, $alert_description ) = unpack( "CC", $data );

   $self->alert_level( $ALERT_LEVEL_REVERSE{$alert_level} );
   $self->alert_description( $ALERT_DESCRIPTION_REVERSE{$alert_description} );

   $self->no_cipher_found(1) if $self->alert_level eq "fatal" and $self->alert_description eq "handshake_failure";

   # say "ALERT-ZEUG:  " . _to_hex($data);

   return $self;
   }

1;

