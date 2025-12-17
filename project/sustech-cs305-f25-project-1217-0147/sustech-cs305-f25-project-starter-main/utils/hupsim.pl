#!/usr/bin/perl
use strict;

# use warnings;

my $QUEUE_MAX       = 10;
my $MAP_FILE        = "topo.map";
my $NODE_FILE       = "nodes.map";
my $PACKET_SIZE_MAX = 2048;

package NSQueue;

sub new ($) {

    my $self = {};

    my $class = shift;
    $self->{'route_ref'} = shift;
    my $rate_bps = shift;
    $self->{'rate'}    = int( $rate_bps / 8 );
    $self->{'latency'} = shift;
    $self->{'max'}     = shift || $QUEUE_MAX;

    $self->{'size'}    = 0;
    $self->{'verbose'} = 0;
    $self->{'dropped'} = 0;

    $self->{'queue'} = [];

    bless( $self, $class );
    return $self;
}

sub set_verbose($) {
    my $self = shift;
    $self->{'verbose'} = shift;
}

sub reset_dropped() {
    my $self = shift;
    $self->{'dropped'} = 0;
}

sub get_dropped() {
    my $self = shift;
    return $self->{'dropped'};
}

sub enq ($$) {

    my $self   = shift;
    my $pkt    = shift;
    my $v_time = shift;
    my $queue  = $self->{'queue'};

    if ( @$queue >= $self->{'max'} ) {

        # drop the packet
        if ( $self->{'verbose'} > 1 ) {
            print "Dropping packet bound for "
              . $self->{'route_ref'}->{'id'}
              . ": queue max is "
              . scalar(@$queue) . "\n";
        }
        $self->{'dropped'}++;
    }
    else {
        my $pack_size = length($$pkt);
        my $tx_time =
          $self->{'latency'} + ( $pack_size / $self->{'rate'} ) + $v_time;
        if ( @$queue > 0 ) {

            # $tx_time += $queue->[0]->[1];
            $tx_time += $self->{'size'} / $self->{'rate'};
        }
        if ( $self->{'verbose'} > 2 ) {
            print "Enqueued packet bound for "
              . $self->{'route_ref'}->{'id'}
              . ", $tx_time\n";
        }
        push( @$queue, [ $pkt, $tx_time ] );
        $self->{'size'} += $pack_size;
    }
}

package NSRouter;

my $INFINITY = 65535;     # must be bigger than # of routers
my $MICRO    = 1000000;

use IO::Socket::INET;
use Time::HiRes qw(gettimeofday);

sub vec_to_string ($) {
    my $ip_addr = shift;
    return
        vec( $ip_addr, 0, 8 ) . "."
      . vec( $ip_addr, 1, 8 ) . "."
      . vec( $ip_addr, 2, 8 ) . "."
      . vec( $ip_addr, 3, 8 );
}

sub new ($) {

    my $self  = {};
    my $class = shift;

    $self->{'id'}     = shift;
    $self->{'routes'} = [];
    $self->{'nodes'}  = shift;
    my $node_key_string = shift;
    $self->{'sock'} =
      IO::Socket::INET->new( Proto => 'udp', PeerAddr => $node_key_string )
      || die("Couldn't open router send socket on $node_key_string: $!");

    $self->{'verbose'}    = 0;
    $self->{'bytes_sent'} = 0;

    bless( $self, $class );
    return $self;
}

sub set_verbose($) {
    my $self = shift;
    $self->{'verbose'} = shift;
}

sub reset_dropped() {
    my $self = shift;
    for my $queue ( @{ $self->{'routes'} } ) {
        if ( defined($queue) ) {
            $queue->reset_dropped();
        }
    }
}

sub get_dropped() {
    my $self    = shift;
    my $dropped = 0;
    for my $queue ( @{ $self->{'routes'} } ) {
        if ( defined($queue) ) {
            $dropped += $queue->get_dropped();
        }
    }
    return $dropped;
}

sub reset_bytes_sent() {
    my $self = shift;
    $self->{'bytes_sent'} = 0;
}

sub get_bytes_sent() {
    my $self = shift;
    return $self->{'bytes_sent'};
}

sub add_route ($$$$) {

    my $self      = shift;
    my $route_ref = shift;
    my $rate      = shift;
    my $latency   = shift;
    my $max       = shift;

    $self->{'routes'}->[ $route_ref->{'id'} ] =
      new NSQueue( $route_ref, $rate, $latency, $max );
    $self->{'routes'}->[ $route_ref->{'id'} ]
      ->set_verbose( $self->{'verbose'} );
    if ( $self->{'verbose'} > 0 ) {
        print "New queue added to "
          . $self->{'id'}
          . ": $rate/$latency/max($max) to "
          . $route_ref->{'id'} . "\n";
    }
}

sub recv($$$) {

    my $self        = shift;
    my $pkt         = shift;
    my $v_time      = shift;
    my $run_routers = shift;

    my ( $src_id, $src_ip, $dest_ip, $src_port, $dest_port ) =
      unpack( "NNNnn", $$pkt );
    if ( inet_ntoa( pack( "N", $src_ip ) ) eq "0.0.0.0" ) {
        $src_ip = unpack( "N", inet_aton("127.0.0.1") );
    }
    if ( inet_ntoa( pack( "N", $dest_ip ) ) eq "0.0.0.0" ) {
        $dest_ip = unpack( "N", inet_aton("127.0.0.1") );
    }
    my $dest = $self->{'nodes'}->{ pack( "Nn", $dest_ip, $dest_port ) };

    if ( $self->{'verbose'} > 2 ) {
        print "Router "
          . $self->{'id'}
          . ": recv pkt at $v_time dest for "
          . inet_ntoa( pack( "N", $dest_ip ) )
          . ":$dest_port (node '$dest')\n";
    }
    unless ( defined($dest) ) {
        if ( $self->{'verbose'} > 1 ) {
            print("Received packet has no destination node, dropping...\n");
        }
        return;
    }

    if ( $dest == $self->{'id'} ) {
        if ( $self->{'verbose'} > 2 ) {
            print "Sending packet from router "
              . $self->{'id'} . " to "
              . inet_ntoa( pack( "N", $dest_ip ) )
              . ":$dest_port\n";
        }
        $self->{'sock'}->send($$pkt);
        $self->{'bytes_sent'} += ( length($$pkt) - 16 );
    }
    else {
        my $queue = $self->get_q($dest);
        if ( defined($queue) ) {
            $queue->enq( $pkt, $v_time );
            push( @$run_routers, $self );

            # print "Packet just enqueued in "
            #   . $self->{'id'}
            #   . ", run_routers length is "
            #   . scalar(@$run_routers) . "\n";
        }
        else {
            die("Unable to locate queue for packet with dest $dest");
        }
    }
}

sub get_q($) {
    my $self = shift;
    my $dest = shift;

    return $self->{'routing_table'}->[$dest];
}

sub run($) {

    my $self        = shift;
    my $run_routers = shift;

    my ( $seconds, $micro_sec );

    my $wait = undef;

    for my $route ( @{ $self->{'routes'} } ) {
        next unless defined($route);
        my $queue = $route->{'queue'};
        if ( $self->{'verbose'} > 3 ) {
            print "Router "
              . $self->{'id'} . "->"
              . $route->{'route_ref'}->{'id'}
              . " run: "
              . scalar(@$queue)
              . " items, head is "
              . $queue->[0]->[1] . "\n"
              if ( @$queue > 0 );
        }

        # print "Router "
        #   . $self->{'id'} . "->"
        #   . $route->{'route_ref'}->{'id'}
        #   . " run: "
        #   . scalar(@$queue)
        #   . " items, head is "
        #   . $queue->[0]->[1] . "\n"
        #   if ( @$queue > 0 );

        # slightly imprecise subsecond counter
        ( $seconds, $micro_sec ) = gettimeofday;
        while (( @$queue > 0 )
            && ( $queue->[0]->[1] <= ( $seconds + ( $micro_sec / $MICRO ) ) ) )
        {
            my ( $pkt, $p_time ) = @{ shift(@$queue) };
            $route->{'size'} -= length($$pkt);
            ( $seconds, $micro_sec ) = gettimeofday;
            $route->{'route_ref'}
              ->recv( $pkt, ( $seconds + ( $micro_sec / $MICRO ) ),
                $run_routers );
        }
        if ( @$queue > 0 ) {
            my $pack_time =
              $queue->[0]->[1] - ( $seconds + ( $micro_sec / $MICRO ) );
            if ( defined($wait) ) {
                $wait = $pack_time if ( $wait > $pack_time );
            }
            else {
                $wait = $pack_time;
            }
        }
    }
    return $wait;
}

sub create_table($) {

    # creates routing table for all nodes using Dijkstra's
    # must be run before passing packets!

    my $self     = shift;
    my $vertexes = shift;    # array of routers; index is router id

    $self->{'routing_table'} = [];

    # set up base state for all vertexes
    for my $vertex (@$vertexes) {
        next unless defined($vertex);
        $vertex->{'done'} = 0;
        if ( $vertex->{'id'} == $self->{'id'} ) {
            $vertex->{'distance'} = 0;
        }
        else {
            $vertex->{'distance'} = $INFINITY;
        }
    }

    for my $vertex (@$vertexes) {
        next unless defined($vertex);
        my $next;
        my $min = $INFINITY + 1;

        # figure out which vertex to visit next
        for my $vertex_next (@$vertexes) {
            next unless defined($vertex_next);
            if (  !( $vertex_next->{'done'} )
                && ( $vertex_next->{'distance'} < $min ) )
            {
                $next = $vertex_next;
                $min  = $vertex_next->{'distance'};
            }
        }

        for my $edge ( @{ $next->{'routes'} } ) {
            next unless defined($edge);

            # WEIGHT FUNCTION AS 1/{bitrate}
            # my $weight = $next->{'distance'} + (1/$edge->{'rate'});
            # WEIGHT FUNCTION AS UNIT WEIGHT
            my $weight = $next->{'distance'} + 1;
            if ( $edge->{'route_ref'}->{'distance'} > $weight ) {
                $edge->{'route_ref'}->{'distance'}    = $weight;
                $edge->{'route_ref'}->{'predecessor'} = $next;
            }
        }
        $next->{'done'}++;
    }
    for my $vertex (@$vertexes) {
        next unless defined($vertex);
        next if ( $vertex->{'id'} == $self->{'id'} );
        my $start_route = $vertex;
        while ( $start_route->{'predecessor'}->{'id'} != $self->{'id'} ) {
            die("route with no pred")
              unless ( defined( $start_route->{'predecessor'} ) );
            $start_route = $start_route->{'predecessor'};
        }

        if ( $self->{'verbose'} > 3 ) {
            print "Router "
              . $vertex->{'id'}
              . " accessible via "
              . $start_route->{'id'} . "\n";
        }
        die( "No queue for " . $vertex->{'id'} )
          unless defined( $self->{'routes'}->[ $start_route->{'id'} ] );
        $self->{'routing_table'}->[ $vertex->{'id'} ] =
          $self->{'routes'}->[ $start_route->{'id'} ];
    }
}

sub DESTROY() {

    my $self = shift;
    $self->{'sock'}->close() if ( defined( $self->{'sock'} ) );
}

package main;

use FileHandle;
use Data::Dumper;
use Getopt::Std;
use IO::Socket;
use IO::Select;
use Time::HiRes qw(gettimeofday usleep);
use strict;

# use warnings;

$| = 1;

sub get_micro_time() {
    my ( $seconds, $micro_sec ) = gettimeofday();
    my $MICRO = 1000000;
    return $seconds + ( $micro_sec / $MICRO );
}

my $prof_time = get_micro_time();    # profiling time
my @routers;

$SIG{'HUP'} = sub {
    print "Last time: $prof_time\n";
    my $cur_prof_time = get_micro_time();
    for my $router (@routers) {
        if ( defined($router) ) {
            print "Router "
              . $router->{'id'} . ": "
              . ( $router->get_bytes_sent() / ( $cur_prof_time - $prof_time ) )
              . " bytes/sec\n";
            $router->reset_bytes_sent();
            for my $route ( @{ $router->{'routes'} } ) {
                next unless defined($route);
                my $queue = $route->{'queue'};
                print "Queue "
                  . $router->{'id'} . "->"
                  . $route->{'route_ref'}->{'id'} . ": "
                  . $route->get_dropped()
                  . " packets dropped, "
                  . scalar(@$queue)
                  . " still in queue\n";
                $route->reset_dropped();
            }
        }
    }

    print "Current time: $cur_prof_time\n";
    $prof_time = $cur_prof_time;
};

sub main() {
    my %opts;
    getopts( 'p:m:n:i:v:', \%opts );
    my $port      = $opts{'p'} || 30148;
    my $i_addr    = $opts{'i'} || 'localhost';
    my $map_file  = $opts{'m'} || $MAP_FILE;
    my $node_file = $opts{'n'} || $NODE_FILE;
    my $verbose   = $opts{'v'} || 0;

    my $fh;

    $fh = new FileHandle($node_file) || die("Can't read $node_file");
    my %nodes;
    my %node_keys;

    for my $line (<$fh>) {
        next if ( $line =~ m/^\#/ );
        chomp($line);
        my ( $node, $ip, $port ) = split( /\s+/, $line );
        my $node_key = gethostbyname($ip) . pack( "n", $port );
        $nodes{$node_key} = $node;
        $node_keys{$node} = "$ip:$port";
    }
    $fh->close();

    $fh = new FileHandle($map_file) || die("Can't read $map_file!");

    # my @routers = ();

    for my $line (<$fh>) {
        next if ( $line =~ m/^\#/ );
        chomp($line);
        my ( $from, $to, $rate, $latency, $queue_max ) = split( /\s+/, $line );
        unless ( defined( $routers[$to] ) ) {
            if ( $verbose > 0 ) { print "Creating new router $to\n"; }
            $routers[$to] = new NSRouter( $to, \%nodes, $node_keys{$to} );
            $routers[$to]->set_verbose($verbose);
        }
        unless ( defined( $routers[$from] ) ) {
            if ( $verbose > 0 ) { print "Creating new router $from\n"; }
            $routers[$from] = new NSRouter( $from, \%nodes, $node_keys{$from} );
            $routers[$from]->set_verbose($verbose);
        }

        $routers[$to]
          ->add_route( $routers[$from], $rate, $latency, $queue_max );
        $routers[$from]
          ->add_route( $routers[$to], $rate, $latency, $queue_max );
    }
    $fh->close();

    for my $router (@routers) {
        next unless defined($router);
        $router->create_table( \@routers );
    }

    # ok, topology is set up, start listening for packets

    my $sleep_seconds = undef;

    my $sock = IO::Socket::INET->new(
        Proto     => 'udp',
        LocalAddr => $i_addr,
        LocalPort => $port
    ) || die("Couldn't open socket:  $!");
    my $sel = new IO::Select($sock);

    my ( $seconds, $micro_sec );
    my $sys_time_sec;

    my @run_routers;

    print "Listening on $port...\n";
    while (1) {
        ( $seconds, $micro_sec ) = gettimeofday();
        $sys_time_sec = sprintf( "%d.%06d", $seconds, $micro_sec );
        if ( $verbose > 3 ) { print "Time is $sys_time_sec.\n"; }
        if ( my ($sel_sock) = $sel->can_read($sleep_seconds) ) {

            # if (my ($sel_sock) = $sel->can_read(0)) {
            my $pkt;
            $sel_sock->recv( $pkt, $PACKET_SIZE_MAX );
            if ( $verbose > 3 ) { print "Got a packet\n"; }
            my ( $port, $ip_addr ) = sockaddr_in( $sel_sock->peername );

            my ( $src_id, $src_ip, $dest_ip, $src_port, $dest_port ) =
              unpack( "NNNnn", $pkt );
            if ( inet_ntoa( pack( "N", $src_ip ) ) eq "0.0.0.0" ) {
                $src_ip = unpack( "N", inet_aton("127.0.0.1") );
            }
            if ( inet_ntoa( pack( "N", $dest_ip ) ) eq "0.0.0.0" ) {
                warning_snake_case_constants $dest_ip =
                  unpack( "N", inet_aton("127.0.0.1") );
            }
            if ( $verbose > 3 ) {
                print "spiffy_header src: "
                  . NSRouter::inet_ntoa( pack( "N", $src_ip ) )
                  . ":$src_port\n";
                print "spiffy_header dst: "
                  . NSRouter::inet_ntoa( pack( "N", $dest_ip ) )
                  . ":$dest_port\n";
                print "packet contents: " . Dumper( substr( $pkt, 16 ) );
            }

            my $node_id = unpack( "N", $pkt );
            if ( $verbose > 2 ) { print "spiffy_header node_id: $node_id\n"; }
            if ( defined( $routers[$node_id] ) ) {
                if ( $verbose > 3 ) {
                    print "Inserting packet at node $node_id\n";
                }
                ( $seconds, $micro_sec ) = gettimeofday();
                $routers[$node_id]
                  ->recv( \$pkt, ( $seconds + ( $micro_sec / $MICRO ) ),
                    \@run_routers );
            }
        }
        $sleep_seconds = undef;

        # $sleep_seconds = 5;
        my $wait;

        for my $router (@routers) {
            if ( defined($router) ) {
                push @run_routers, $router;
            }
        }

        # for my $router (@routers) {
        while ( my $router = shift(@run_routers) ) {
            $wait = $router->run( \@run_routers );
            if ( $verbose > 3 ) {
                print "router " . $router->{'id'} . " waits $wait\n";
            }
            if ( defined($sleep_seconds) ) {
                $sleep_seconds = $wait
                  if ( defined($wait) && ( $wait < $sleep_seconds ) );
            }
            else {
                $sleep_seconds = $wait;
            }
        }
        if ( $verbose > 3 ) {
            print "Next socket timeout is "
              . ($sleep_seconds)
              . " seconds...\n";
        }
    }

}

main();
