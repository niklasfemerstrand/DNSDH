# DNSDH

DNSDH is a protocol for exchanging cryptographic keys using the [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
algorithm. Instead of exchanging keys traditionally, the clients speak to a
bogus DNS server to initiate an encrypted session in an existing channel of
communication. The cryptographically relevant packets travel through a data path
that appear to be normal domain name resolve queries to remain stealth and
effective even behind limited and surveillanced networks. Please understand that
the DNS server is only pretending to be a server for performing name lookups
by using its language but performing different tasks.

The bogus DNS server is the center of the key exchange. It uses memcached to
store data in memory and deletes any output after it’s been delivered to its
recipient. The point of DNSDH is to establish a reliable network enabling
anything that can perform a DNS request to exchange cryptographic keys using
discrete bogus domain name queries. The nodes communicating, Alice and Bob,
could possibly be two cellphones, IRC clients or even death stars. It’s also
a great blast to teasingly merge cryptographic key exchanges with traffic that
is rarely looked at by network administrators unless they want to censor or
monitor you.

## Example flow

* **ALICE:**
	* `Declare p, g, alice_private`
	* `alice_public = g^alice_private mod p`
	* $ dig @127.0.0.1 A dnsdhinit.p.g.alice_public
* **DNS:**
	* sessionid.699659
* **ALICE:**
	* ->BOB DNSDH_INIT: 699659
* **BOB:**
	* $ dig @127.0.0.1 A sessionid.699659
* **DNS:**
	* p.g.alice_public
* **BOB:**
	* `Declare bob_private`
	* `bob_public = g^bob_private mod p`
	* `shared_secret = alice_public^bob_private mod p`
	* $ dig @127.0.0.1 A dnsdhinit.bob_public
* **DNS:**
	* sessionid.800565
* **BOB:**
	* ->ALICE DNSDH_FINISH: 800565
* **ALICE:**
	* $ dig sessionid.800565
* **DNS:**
	* bob_public
* **ALICE:**
	* `shared_secret = bob_public^alice_secret mod p`

## Usage

perl dnsdhd.pl
perl client.example.pl 1338 1337
perl client.example.pl 1337 1338 init
