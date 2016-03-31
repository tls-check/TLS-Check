# TLS-Check – Collect information about domains and their servers

TLS-Check is 

1. a modular framework for collecting and summarizing arbitrary key figures for a lot of domains and their running servers (usually Web- and Mailserver) 
2. a software for analyzing and summarizing the security and encryption of given domains, e.g. supported SSL/TLS-Versions and cipher suites.

Its primary goal is to get key figures about SSL/TLS connections. It can count how many servers support encryption or not, good or weak SSL/TLS-Versions, good or weak cipher suites, how many websites or mailservers are vulnerable to security problems like Heartbleed, how many support IPv6, how many support all recommendations of the BSI or Bettercrypto project and much much more.

TLS-Check comes with a lot of checks. But it is very easy to add more tests. It is highly modular and each part of the code can be replaced (e.g. input or output).

Development contracted by Chamber of Commerce and Industry of the Stuttgart (Germany) Region and its committee of information technology, information services and telecommunication.


## Why writing another SSL/TLS testing tool? What are the primary goals?

There are a lot of tools, which check servers for their SSL/TLS capabilities (e.g. SSLyze, O-Saft and much more). But none meets all our requirements at starting with TLS-Check in 2014:

* We need a flexible and extensible tool to check every possible key figure for a given domain – e.g. from counting how many servers support IPv6 or the different top level domains to counting how many supports the really old SSLv2 protocol.
* The most important subtests in TLS-Check are SSL/TLS checks. We wrote our own SSL/TLS handshake implementation, because wo found no acceptable other solution. Some of the tools for checking SSL/TLS cipher suites are really ugly hacks, violating all best practice rules, have no or very few automated tests, are unmaintainable and buggy. TLS-Check is not free of errors, but tries to have testable, extendable, maintainable code.
* It should allow to check every known or unknown cipher suite, not limited to e.g. the cipher suites supported by OpenSSL. Because TLS-Check uses it's own code for SSL/TLS Handshake, it supports every possible ciphersuite. It knows about 362 different cipher suites, 455 with duplicates.
* It should be easy to add new checks: *It makes easy things easy and hard things possible – reliable, testable.*
* Tests must run in parallel to reduce the runtime.
* We have some limitations because of privacy reasons.

## Installation

…

## Example Usage

…

## Bugs




## Author

TLS-Check is written by [Alvar C.H. Freude](http://alvar.a-blast.org/).

Development contracted by Chamber of Commerce and Industry of the Stuttgart (Germany) Region and its committee of information technology, information services and telecommunication.

## License 

TLS-Check is licensed under the Artistic License 2.0 or the European Public Licence 1.1 (EUPL).

