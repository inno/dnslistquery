#!/usr/bin/env perl

use strict;
use warnings;
use POE;
use POE::Component::Client::DNS;
use JSON::XS;

# GetOpts::Long doesn't seem to work for me at the moment..

open CONF, '<', 'lists.json' or die "Missing lists.json!\n";
my $conf_raw = join "\n", <CONF>;
close CONF;

my $conf = JSON::XS->new()->ascii->decode($conf_raw);

my $ip = shift;
die "Syntax: $0 IPADDRESS\n" unless $ip;
chomp $ip;

my $type = shift || '(?:blacklist|)';
chomp $type;

my $fail_on = '(?:blacklisted)';

my $rev_ip = join '.', reverse split /\./, $ip;

my @hosts = ();
my $response_handler = {};
my $retcode = 0;

# restructure conf
foreach my $service (keys %{$conf}) {
    foreach my $zone (keys %{$conf->{$service}}) {
        next if $zone =~ /^comments?$/o;
        if (defined $conf->{$service}{$zone}{'type'}) {
            next unless grep {/^$type$/o} @{$conf->{$service}{$zone}{'type'}};
        }
        push @hosts, "$rev_ip.$zone";
        $response_handler->{$zone} = $conf->{$service}{$zone};
    }
}

sub responder {
    my ($host, $response) = @_;

    # Scrape off IP
    $host =~ s/^$rev_ip\.//o;

    if (defined $response_handler->{$host}{$response}) {
        # Query returned a known "noop", nothing to see here
        if ($response_handler->{$host}{$response} eq 'noop') {
            return 'ok';
        }
        return $response_handler->{$host}{$response};
    }
    elsif ($response eq 'none') {
        return 'ok';
    }
    elsif (defined $response_handler->{$host}{'default'}) {
        return $response_handler->{$host}{'default'};
    }
    elsif ($response eq '127.0.0.2') {
        return 'blacklisted';
    }
    else {
        return "FAILED!  No response defined for '$response' from $host";
    }
}

POE::Component::Client::DNS->spawn(
    Alias       => 'resolver',
    Timeout     => '20',
);


POE::Session->create(
    inline_states => {
        _start => sub {
            my ($kernel, $heap) = @_[KERNEL, HEAP];

            $heap->{answers}   = 0;
            $heap->{timeouts}  = 0;
            $heap->{results}  = {};
            $heap->{start_time}         = time();

            for (1 .. 20) {
                $kernel->yield('query_next');
            }

        },

        _stop => sub {
            my $heap         = $_[HEAP];
            my $elapsed_time = time() - $heap->{start_time};
            warn(
              "Elapsed time: $elapsed_time second(s).\n",
              "$heap->{timeouts} resolver timeouts.\n",
              "$heap->{answers} resolver answers.\n"
            );

            foreach my $type (keys %{$heap->{results}}) {
                if ($type =~ /$fail_on/o) {
                    $retcode = 1;
                }
                foreach my $host (@{$heap->{results}{$type}}) {
                    print "$type\t$host";
                    if (defined $heap->{result_notes}{$host}) {
                        print "\t$heap->{result_notes}{$host}";
                    }
                    print "\n";
                }
            }

        },

        query_txt => sub {
            my ($kernel, $heap) = @_[KERNEL, HEAP];
            my ($hostname) = $_[ARG0];

            return unless defined $hostname;

            $kernel->post(
                'resolver' =>
                    'resolve' =>
                        'response' =>
                            $hostname => 'TXT'
            );
        },


        query_next => sub {
            my ($kernel, $heap) = @_[KERNEL, HEAP];

            my $hostname = pop @hosts;
            return unless defined $hostname;

            $kernel->post(
                'resolver' =>
                    'resolve' =>
                        'response' =>
                            $hostname => 'A'
            );
        },

        response => sub {
            my ($kernel, $heap) = @_[KERNEL, HEAP];
            my ($request, $response) = @_[ARG0, ARG1];
            my ($query, $error) = @$response;

            my $request_address = $request->[0];

            unless (defined $query) {
                warn ("$request_address: error ($error)\n");
                $heap->{timeouts}++;

                $kernel->yield('query_next');
                return;
            }

            my @answers = $query->answer();

            unless (@answers) {
                my $result = responder($request_address, 'none');
                push @{$heap->{results}{$result}}, $request_address;
                $heap->{answers}++;

                $kernel->yield('query_next');
                return;
            }

            foreach my $answer (@answers) {
                if ($answer->type eq 'TXT') {
                    if (defined $answer->rdatastr()) {
                        $heap->{'result_notes'}{$request_address} = $answer->rdatastr();
                    }
                    next;
                }
                elsif ($answer->type ne 'A') {
                    warn "Unexpected type: ".$answer->type."\n";
                }
                $heap->{answers}++;

                my $result = responder($request_address, $answer->rdatastr());
                push @{$heap->{results}{$result}}, $request_address;
                if ($result !~ /ok$/o) {
                    $kernel->yield("query_txt", $request_address);
                }
            }

            $kernel->yield('query_next');
        },
    }
);

$poe_kernel->run();

exit $retcode;
