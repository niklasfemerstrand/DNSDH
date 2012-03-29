#!/usr/bin/perl
# Copyright (c) 2012 Niklas A. Femerstrand, http://qnrq.se/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

use strict;
use warnings;
use diagnostics;
use IO::Socket::INET;
use Net::DNS;
use Crypt::DH;
use Crypt::DH::GMP qw(-compat);
package main;

our $| = 1;
my $local = new IO::Socket::INET->new(LocalPort=>$ARGV[0],Proto=>'udp');
my $remote = new IO::Socket::INET->new(PeerAddr=>'127.0.0.1',PeerPort=>$ARGV[1],Proto=>'udp');

my $res = Net::DNS::Resolver->new(
	nameservers => [qw(127.0.0.1)],
	port        => 53,
	recurse     => 0,
#	debug       => 1,
);

# ALICE
if(defined($ARGV[2]) && $ARGV[2] eq 'init')
{
	printf("[+] Generating keys...\n");
	$main::aliceP = 23;
	$main::aliceG = 5;
	my $dh = Crypt::DH::GMP->new(p => $main::aliceP, g => $main::aliceG);
	$dh->generate_keys;
	$main::alice_priv = $dh->priv_key;
	printf("[+] alice_pub_key: %s\n[+] alice_priv_key: %s\n", $dh->pub_key, $main::alice_priv);

	# A dnsdhinit.p.g.alice_public
	printf("[+] Query dnsdhinit.%s.%s.%s\n", $main::aliceP, $main::aliceG, $dh->pub_key);
	if(my $a_query = $res->search("dnsdhinit.".$main::aliceP.".".$main::aliceG.".".$dh->pub_key, "A"))
	{
		foreach my $rr ($a_query->answer)
		{
			if($rr->name =~ /sessionid\.(.*)/)
			{
				printf("[+] SEND DNSDH_INIT: %s\n", $1);
				$remote->send("DNSDH_INIT: ".$1);
				last;
			}
		}
	}
}

while(1)
{
	my $recieved_data;
	$local->recv($recieved_data,1024);
	my $peer_address = $local->peerhost();
	my $peer_port = $local->peerport();
	printf("[%s:%s]: %s\n", $peer_address, $peer_port, $recieved_data);

	# BOB
	if($recieved_data =~ /^DNSDH_INIT: (.*)/)
	{
		# A sessionid.$1
		printf("[+] Query sessionid.%s\n", $1);
		if(my $a_query = $res->search("sessionid.".$1, "A"))
		{
			my $sessionid = $1;
			foreach my $rr ($a_query->answer)
			{
				# p.g.alice_public
				if($rr->name =~ /^(.*)\.(.*)\.(.*)$/)
				{
					printf("[+] p: %s\n[+] g: %s\n[+] alice_public: %s\n", $1, $2, $3);
					printf("[+] Generating keys...\n");
					my $dh = Crypt::DH::GMP->new(p => $1, g => $2);
					sleep(10);
					$dh->generate_keys;
					printf("[+] bob_pub_key: %s\n[+] bob_priv_key: %s\n", $dh->pub_key, $dh->priv_key);
					my $shared_secret = $dh->compute_secret($3);
					printf("[+] Shared secret: %s\n", $shared_secret);
					printf("[+] Query dnsdhinit.%s\n", $dh->pub_key);
					if(my $b_query = $res->search("dnsdhinit.".$dh->pub_key, "A"))
					{
						foreach my $rrr ($b_query->answer)
						{
							if($rrr->name =~ /sessionid\.(.*)/)
							{
								printf("[+] SEND DNSDH_FINISH: %s\n", $1);
								$remote->send("DNSDH_FINISH: ".$1);
								last;
							}
						}
					}
					last;
				}
			}
		}
	}
	# ALICE
	elsif($recieved_data =~ /^DNSDH_FINISH: (.*)$/)
	{
		printf("[+] Query sessionid.%s\n", $1);
		if(my $a_query = $res->search("sessionid.".$1, "A"))
		{
			foreach my $rr ($a_query->answer)
			{
				# bob_public
				printf("[+] p: %s\n[+] g: %s\n[+] bob_public: %s\n", $main::aliceP, $main::aliceG, $rr->name);
				my $dh = Crypt::DH::GMP->new(p => $main::aliceP, g => $main::aliceG, priv_key => $main::alice_priv);
				my $sharedsecret = $dh->compute_secret($rr->name);
				printf("[+] Shared secret: %s\n", $sharedsecret);
				last;
			}
		}
	}
}
