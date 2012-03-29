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
use Net::DNS::Nameserver;
use Cache::Memcached;

my $memd = new Cache::Memcached( 
	'servers' => ["127.0.0.1:11211"],
	'debug' => 0,
	'compress_threshold' => 10_000,
) || die "couldn't create memcached object\n";

my $ns = new Net::DNS::Nameserver(
	LocalPort    => 53,
	ReplyHandler => \&reply_handler,
	Verbose      => 1,
) || die "couldn't create nameserver object\n";

sub reply_handler
{
	my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
	if($qname =~ /^dnsdhinit\.(.*)/)
	{
		while(1)
		{
			my $sessionid = int(rand(9999999)); # Good enough for now
			if(!$memd->get($sessionid))
			{
				print("\n[+] sessionid $sessionid\n");
				if($memd->add($sessionid, $1))
				{
					$qname = "sessionid.".$sessionid;
					$rcode = "NOERROR";
				}
				last;
			}
		}
	}
	elsif($qname =~ /^sessionid\.(.*)/)
	{
		if(my $val = $memd->get($1))
		{
			$qname = $val;
			$rcode = "NOERROR";
			$memd->delete($1);
		}
	}

	print "Received query from $peerhost to ". $conn->{sockhost}. "\n";
	$query->print;

	my ($ttl, $rdata) = (1337, "127.0.0.1");
	my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
	push @ans, $rr;

	return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

# TODO: Threading
while(1)
{
	$ns->loop_once(10);
}
