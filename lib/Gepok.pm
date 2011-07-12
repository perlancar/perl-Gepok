package Gepok;

use 5.010;
use strict;
use warnings;
use Log::Any '$log';

# VERSION

use HTTP::Daemon;
use HTTP::Daemon::SSL;
use HTTP::Daemon::UNIX;
#use IO::Handle::Record; # needed for something, forgot what
use IO::Scalar;
use IO::Select;
use Plack::Util;
use SHARYANTO::Proc::Daemon::Prefork;

use Moo;

has name                   => (is => 'rw',
                               default => sub {
                                   my $name = $0;
                                   $name =~ s!.*/!!;
                                   $name;
                               });
has daemonize              => (is => 'rw', default=>sub{1});
has sock_path              => (is => 'rw');
has pid_path               => (is => 'rw');
has scoreboard_path        => (is => 'rw');
has error_log_path         => (is => 'rw');
has access_log_path        => (is => 'rw');
has http_ports             => (is => 'rw', default => sub{[]});
has https_ports            => (is => 'rw', default => sub{[]});
has unix_sockets           => (is => 'rw', default => sub{[]});
has ssl_key_file           => (is => 'rw');
has ssl_cert_file          => (is => 'rw');
has start_servers          => (is => 'rw', default => sub{3});
has max_requests_per_child => (is => 'rw', default=>sub{1000});
has _daemon                => (is => 'rw'); # SHARYANTO::Proc::Daemon::Prefork
has _server_socks          => (is => 'rw'); # store server sockets
has _app                   => (is => 'rw'); # store PSGI app

sub BUILD {
    my ($self) = @_;

    unless ($self->error_log_path) {
        $self->error_log_path("/var/log/".$self->name."-error.log");
    }
    unless ($self->access_log_path) {
        $self->access_log_path("/var/log/".$self->name."-access.log");
    }
    unless ($self->pid_path) {
        $self->pid_path("/var/run/".$self->name.".pid");
    }
    unless ($self->scoreboard_path) {
        $self->scoreboard_path("/var/run/".$self->name.".scoreboard");
    }
    unless ($self->_daemon) {
        my $daemon = SHARYANTO::Proc::Daemon::Prefork->new(
            name                    => $self->name,
            error_log_path          => $self->error_log_path,
            access_log_path         => $self->access_log_path,
            pid_path                => $self->pid_path,
            scoreboard_path         => $self->scoreboard_path,
            daemonize               => $self->daemonize,
            prefork                 => $self->start_servers,
            after_init              => sub { $self->_after_init },
            main_loop               => sub { $self->_main_loop },
            # currently auto reloading is turned off
        );
        $self->_daemon($daemon);
    }
}

sub run {
    my ($self, $app) = @_;
    $self->_app($app);
    $self->_daemon->run;
}

# alias for run()
sub start {
    my $self = shift;
    $self->run(@_);
}

sub stop {
    my ($self) = @_;
    $self->_daemon->kill_running;
}

sub restart {
    my ($self) = @_;
    $self->_daemon->kill_running;
    $self->_daemon->run;
}

sub is_running {
    my ($self) = @_;
    my $pid = $self->_daemon->check_pidfile;
    $pid ? 1:0;
}

sub _after_init {
    my ($self) = @_;

    my @server_socks;

    for my $path (@{$self->unix_sockets}) {
        $log->infof("Binding to Unix socket %s (http) ...", $path);
        my $sock = HTTP::Daemon::UNIX->new(Local=>$path);
        die "Unable to bind to Unix socket $path" unless $sock;
        push @server_socks, $sock;
    }

    for my $port (@{$self->http_ports}) {
        my %args = (Reuse => 1);
        if ($port =~ /^(?:0\.0\.0\.0)?:?(\d+)$/) {
            $args{LocalPort} = $1;
        } elsif ($port =~ /^(\d+\.\d+\.\d+\.\d+):(\d+)$/) {
            $args{LocalHost} = $1;
            $args{LocalPort} = $2;
        } else {
            die "Invalid http_port syntax `$port`, please specify ".
                ":N or 1.2.3.4:N";
        }
        $log->infof("Binding to TCP socket %s (http) ...", $port);
        my $sock = HTTP::Daemon->new(%args);
        die "Unable to bind to TCP socket $port" unless $sock;
        push @server_socks, $sock;
    }

    for my $port (@{$self->https_ports}) {
        my %args = (Reuse => 1);
        # currently commented out, hangs with larger POST
        #$args{Timeout} = 180;

        $args{SSL_key_file}  = $self->ssl_key_file;
        $args{SSL_cert_file} = $self->ssl_cert_file;
        #$args{SSL_ca_file} = $self->ssl_ca_file;
        #$args{SSL_verify_mode} => 0x01;
        if ($port =~ /^(?:0\.0\.0\.0)?:?(\d+)$/) {
            $args{LocalPort} = $1;
        } elsif ($port =~ /^(\d+\.\d+\.\d+\.\d+):(\d+)$/) {
            $args{LocalHost} = $1;
            $args{LocalPort} = $2;
        } else {
            die "Invalid http_port syntax `$port`, please specify ".
                ":N or 1.2.3.4:N";
        }

        $log->infof("Binding to TCP socket %s (https) ...", $port);
        my $sock = HTTP::Daemon::SSL->new(%args);
        die "Unable to bind to TCP socket $port, common cause include ".
            "port taken or missing server key/cert file" unless $sock;
        push @server_socks, $sock;
    }

    die "Please specify at least one HTTP/HTTPS/Unix socket port"
        unless @server_socks;

    $self->_server_socks(\@server_socks);
    $self->before_prefork();
}

sub before_prefork {}

sub _main_loop {
    my ($self) = @_;
    $log->info("Child process started (PID $$)");
    $self->_daemon->update_scoreboard({child_start_time=>time()});

    my $sel = IO::Select->new(@{ $self->_server_socks });

    for (my $i=1; $i<$self->max_requests_per_child; $i++) {
        $self->_daemon->set_label("listening");
        my @ready = $sel->can_read();
        for my $s (@ready) {
            my $sock = $s->accept();
            $self->_set_label_serving($sock);
            $self->_daemon->update_scoreboard({
                req_start_time => time(),
                num_reqs => $i,
                state => "R",
            });
            while (my $req = $sock->get_request) {
                $self->_daemon->update_scoreboard({state => "W"});
                my $res = $self->_handle_psgi($req, $sock);
                $self->access_log($req, $res, $sock);
            }
            $self->_daemon->update_scoreboard({state => "_"});
        }
    }
}

sub handle_psgi {
    my ($self, $req, $sock) = @_;

    # to trap I/O errors or exception in psgi app
    eval {
        # construct $env for psgi app
        my $env = $self->_construct_psgi_env($req, $sock);
    };
}

sub _construct_psgi_env {
    my ($self, $req, $sock) = @_;

    my $is_unix = $sock->isa('HTTP::Daemon::UNIX');
    my $is_ssl  = $sock->isa('HTTP::Daemon::SSL');
    my $uri = $req->uri->as_string;
    my $qs  = $uri =~ /.\?(.*)/ ? $1 : '';
    my $env = {
        REQUEST_METHOD  => $req->method,
        SCRIPT_NAME     => '',
        PATH_INFO       => '/',
        REQUEST_URI     => $uri,
        QUERY_STRING    => $qs,
        SERVER_PORT     => $is_unix ? 0 : $sock->sockport,
        SERVER_NAME     => $is_unix ? $sock->hostpath : $sock->sockaddr,
        SERVER_PROTOCOL => 'HTTP/1.1',
        REMOTE_ADDR     => $is_unix ? 'localhost' : $sock->peeraddr,

        'psgi.version'         => [ 1, 1 ],
        'psgi.errors'          => *STDERR,
        'psgi.url_scheme'      => $is_ssl ? 'https' : 'http',
        'psgi.run_once'        => Plack::Util::FALSE,
        'psgi.multithread'     => Plack::Util::FALSE,
        'psgi.multiprocess'    => Plack::Util::TRUE,
        'psgi.streaming'       => Plack::Util::TRUE,
        'psgi.nonblocking'     => Plack::Util::FALSE,
        'psgix.input.buffered' => Plack::Util::TRUE,
        'psgix.io'             => $sock,
        'psgix.input.buffered' => Plack::Util::TRUE,
        'psgix.harakiri'       => Plack::Util::TRUE,
    };
    # HTTP_ vars
    my $rh = $req->headers;
    for my $hn ($rh->header_field_names) {
        my $hun = uc($hn); $hun =~ s/^[A-Z0-9]/_/g;
        $env->{"HTTP_$hun"} = join(", ", $rh->header($hn));
    }
    # XXX keep alive

    $env;
}

sub _set_label_serving {
    my ($self, $sock) = @_;

    my $is_unix = $sock->isa('HTTP::Daemon::UNIX');

    if ($is_unix) {
        my $sockpath = $sock->hostpath;
        my ($pid, $uid, $gid) = $sock->peercred;
        $log->trace("Unix socket info: path=$sock_path, ".
                        "pid=$pid, uid=$uid, gid=$gid");
        $self->_daemon->set_label("serving unix (pid=$pid, uid=$uid, ".
                                      "path=$sock_path)");
    } else {
        my $is_ssl = $sock->isa('HTTP::Daemon::SSL') ? 1:0;
        my $server_port = $sock->sockport;
        my $remote_ip   = $sock->peerhost;
        my $remote_port = $sock->peerport;
        $log->trace("TCP socket info: https=$is_ssl, server_port=$port, ".
                        "remote_ip=$remote_ip, remote_port=$remote_port");
        $self->_daemon->set_label("serving TCP :$server_port (https=$is_ssl, ".
                                      "remote=$remote_ip:$remote_port)");
    }
}

sub ___start_chunked_http_response {
    my ($self) = @_;
    my $req = $self->req;
    my $sock = $req->{sock};

    $sock->print("HTTP/1.1 200 OK\r\n");
    $sock->print("Content-Type: text/plain\r\n");
    $sock->print("Transfer-Encoding: chunked\r\n");
    $sock->print("\r\n");
    $req->{chunked}++;
}

sub __send_http_response {
    $log->trace("-> send_http_response()");
    my ($self) = @_;
    my $req = $self->req;
    my $http_req = $req->{http_req};
    my $sock = $req->{sock};
    my $resp = $self->resp;

    # determine output format

    my $accept;
    $accept = $http_req->header('Accept') if $http_req;
    $accept //= "application/json";
    my $format;
    my $ct;
    if ($accept =~ m!text/(?:html|x-spanel-(?:no)?pretty)!) {
        # if access from browser, give nice readable text dump
        $ct     = 'text/plain';
        $format = $accept =~ /nopretty/ ? 'nopretty' :
            $accept =~ /pretty/ ? 'pretty' : 'text';
        $resp->[2] //= "Success" if $resp->[0] == 200;
    } elsif ($accept eq 'text/yaml') {
        $ct       = $accept;
        $format   = 'yaml';
    } elsif ($accept eq 'application/vnd.php.serialized') {
        $ct       = $accept;
        $format   = 'php';
    } else {
        # fallback is json
        $ct       = 'application/json';
        $format   = 'json';
    }
    my $output = Sub::Spec::CmdLine::format_result(
        $resp, $format, {default_success_message => 'Success'});

    # construct an appropriate HTTP::Response

    my $http_resp = HTTP::Response->new;
    $http_resp->header ('Content-Type' => $ct);
    $http_resp->content($output);
    $http_resp->code(200);
    #$http_resp->message(...);
    # extra headers
    $http_resp->header('Content-Length' => length($output));
    $http_resp->header('Connection' => 'close');
    # Date?

    # send it!
    $log->trace("Sending HTTP response ...");

    # as_string & status_line doesn't produce "HTTP/x.y " in status line
    my $str = join(
        "",
        $req->{mark_chunk} ? "R" : "",
        "HTTP/1.0 ", $http_resp->as_string);
    if ($req->{chunked}) {
        $sock->print(sprintf("%02x\r\n", length($str)));
    }
    $sock->print($str);
    if ($req->{chunked}) {
        $sock->print("\r\n");
        $sock->print("0\r\n");
    }
    $sock->close;
}

sub access_log {
    my ($self, $req, ) = @_;
    my $req = $self->req;
    my $http_req = $req->{http_req};
    my $resp = $self->resp;

    my $fmt = join(
        "",
        "[%s] ", # time
        "[%s] ", # from
        "\"%s %s\" ", # HTTP method & URI
        "[user %s] ",
        "[mod %s] [sub %s] [args %s %s] ",
        "[resp %s %s] [subt %s] [reqt %s]",
        "%s", # extra info
        "\n"
    );
    my $from;
    if ($req->{proto} eq 'tcp') {
        $from = $req->{remote_ip} . ":" .
            ($req->{https} ? $self->https_port : $self->http_port);
    } else {
        $from = "unix";
    }

    my $args_s = $json->encode($self->{sub_args} // "");
    my $args_len = length($args_s);
    my $args_partial = $args_len > $self->access_log_max_args_len;
    $args_s = substr($args_s, 0, $self->access_log_max_args_len)
        if $args_partial;

    my ($resp_s, $resp_len, $resp_partial);
    if ($req->{access_log_mute_resp}) {
        $resp_s = "*";
        $resp_partial = 0;
        $resp_len = "*";
    } else {
        $resp_s = $json->encode($self->resp // "");
        $resp_len = length($resp_s);
        $resp_partial = $resp_len > $self->access_log_max_resp_len;
        $resp_s = substr($resp_s, 0, $self->access_log_max_resp_len)
            if $resp_partial;
    }

    my $logline = sprintf(
        $fmt,
        scalar(localtime $req->{time_connect}[0]),
        $from,
        $http_req->method, $http_req->uri,
        $req->{auth_user} // "-",
        $req->{sub_module} // "-", $req->{sub_name} // "-",
        $args_len.($args_partial ? "p" : ""), $args_s,
        $resp_len.($resp_partial ? "p" : ""), $resp_s,
        (!defined($req->{time_call_start}) ? "-" :
             !defined($req->{time_call_end}) ? "D" :
                 sprintf("%.3fms",
                         1000*tv_interval($req->{time_call_start},
                                          $req->{time_call_end}))),
        sprintf("%.3fms",
                1000*tv_interval($req->{time_connect},
                                 $req->{time_finish_response})),
        keys(%{$req->{log_extra}}) ? " ".$json->encode($req->{log_extra}) : "",
    );

    if ($self->_daemon->{daemonized}) {
        #warn "Printing to access log $daemon->{_access_log}: $logline";
        # XXX rotating?
        syswrite($self->_daemon->{_access_log}, $logline);
    } else {
        warn $logline;
    }
}

1;
__END__
# ABSTRACT: Preforking HTTP server, HTTPS/Unix socket/multiports/PSGI

=head1 SYNOPSIS

In your program:

 use Gepok;

 my $d = Gepok->new(
     http_ports     => [8081, ':8082', '127.0.0.1:8083'], # default none
     https_ports    => [8084, '0.0.0.0:8085'],            # default none
     unix_sockets   => ['/var/run/gepok.sock','/tmp/gepok.sock'], # default none
     #ssl_key_file  => '/path/to/key.pem', # required if https_ports specified
     #ssl_cert_file => '/path/to/crt.pem', # required if https_ports specified
     #max_requests_per_child => 100,       # default is 1000
     #start_servers          => 0,         # default is 3, 0 means don't prefork
     #daemonize => 0,       # default is 1, 0 = don't go into background
 );

 # run PSGI application
 $d->run($app);


=head1 DESCRIPTION

Gepok creates one or more L<HTTP::Daemon> (for TCP/HTTP), L<HTTP::Daemon::SSL>
(for TCP/HTTPS), L<HTTP::Daemon::UNIX> (for Unix socket/HTTP) objects to serve
web requests over one or several ports. Some unique features:

=over 4

=item * HTTPS support out-of-the-box

This is the primary reason why I wrote Gepok, and why it uses HTTP::Daemon::*
family (because there is HTTP::Daemon::SSL). I needed a pure-Perl standalone
webserver with SSL support builtin. Other Perl servers usually recommend running
behind Nginx or some other external HTTPS proxy.

=item * Preforking

Good performance and reliability.

=item * Multiple interface and Unix socket

=item * PSGI

Run any PSGI application/framework.

=item * Runs on Unix platform

=item * Autorefresh

With some extra effort, can also support autorefresh (restarting itself whenever
script/one of loaded Perl modules changes on disk). See
L<SHARYANTO::Proc::Daemon::Prefork> for more details.

=back

This module uses L<Log::Any> for logging.

This module uses L<Moo> for object system.


=head1 ATTRIBUTES

=head2 name => STR (default is basename of $0)

Name of server, for display in process table ('ps ax').

=head2 daemonize => BOOL (default 1)

Whether to daemonize (go into background).

=head2 http_ports => ARRAY OF STR (default [])

One or more HTTP ports to listen to. Default is none. Each port can be in the
form of N, ":N", "0.0.0.0:N" (all means the same thing, to bind to all
interfaces) or "1.2.3.4:N" (to bind to a specific network interface).

=head2 https_ports => ARRAY OF STR (default [])

Just like http_ports, but for specifying ports for HTTPS.

=head2 unix_sockets => ARRAY OF STR

Location of Unix sockets. Default is none, which means not listening to Unix
socket. Each element should be an absolute path.

You must at least specify one ports (either http, https, unix_socket) or Gepok
will refuse to run.

=head2 pid_path => STR (default /var/run/<name>.pid)

Location of PID file.

=head2 scoreboard_path => STR (default /var/run/<name>.scoreboard)

Location of scoreboard file (used for communication between parent and child
processes). If you disable this, autoadjusting number of children won't work
(number of children will be kept at 'start_servers').

=head2 error_log_path => STR (default /var/log/<name>-error.log)

Location of error log. Default is /var/log/<name>-error.log. It will be opened
in append mode.

=head2 access_log_path => STR (default /var/log/<name>-access.log)

Location of access log. It will be opened in append mode.

Default format of access log is the Apache combined format. Override
access_log() method if you wan't to customize this.

=head2 ssl_key_file => STR

Path to SSL key file, to be passed to HTTP::Daemon::SSL. If you specify one or
more HTTPS ports, you need to supply this.

=head2 ssl_cert_file => STR

Path to SSL cert file, to be passed to HTTP::Daemon::SSL. If you specify one or
more HTTPS ports, you need to supply this.

=head2 start_servers => INT (default 3)

Number of children to fork at the start of run. If you set this to 0, the server
becomes a nonforking one.

Tip: You can set start_servers to 0 and 'daemonize' to false for debugging.

=head2 max_clients => INT (default 150)

Maximum number of children processes to maintain. If server is busy, number of
children will be increased from the original 'start_servers' up until this
value.

=head2 max_requests_per_child => INT (default 1000)

Number of requests each child will serve until it exists.

=head2 psgi_app => CODE

Supply PSGI application. Optional. If not supplied, you'll need to subclass and
provide process_request().


=head1 METHODS

=for Pod::Coverage BUILD

=head2 new(%args)

Create a new instance of server. %args can be used to set attributes.

=head2 $gepok->run($app)

Start/run server and run the PSGI application $app.

=head2 $gepok->start($app)

Alias for run().

=head2 $gepok->stop()

Stop running server.

=head2 $gepok->restart()

Restart server.

=head2 $gepok->is_running() => BOOL

Check whether server is running.

=head2 $gepok->before_prefork()

This is a hook provided for subclasses to do something before the daemon is
preforking. For example, you can preload Perl modules here so that each child
doesn't have to load modules separately (= inefficient).

=head2 $gepok->access_log()

The default implementation uses the Apache combined format. Override if you want
custom format.


=head1 FAQ

=head2 Why the name Gepok?

Gepok is an Indonesian word, meaning bundle. This class bundles one or several
HTTP::Daemon::* objects to create a stand-alone web server.

=head2 Performance notes?

Gepok is not very performance-oriented. First, for convenience it is based on
HTTP::Daemon, which is also not performance-oriented. For each HTTP request,
HTTP::Daemon constructs an L<HTTP::Request> object, which copies request body
into a scalar (and, for PSGI, needs to be presented as a stream using
L<IO::Scalar>), and also involve creating other objects like L<URI> and
L<HTTP::Headers>.

Gepok also creates file-based scoreboard, which might or might not be a
bottleneck.

That being said, I find Gepok's performance adequate for small-scale uses.

For more high-performant alternative, take a look at L<Starman> or use Nginx.

=head2 How to do autorefresh?

Create your own L<SHARYANTO::Proc::Daemon::Prefork> object, setting its
'auto_reload_handler' and 'auto_reload_check_every' (along with the other
arguments), then pass the object to Gepok's constructor in '_daemon' attribute.


=head1 SEE ALSO

HTTP server classes used: L<HTTP::Daemon>, L<HTTP::Daemon::SSL>,
L<HTTP::Daemon::UNIX>.

L<Starman>, a high-performance preforking Perl HTTP server which also supports
Unix socket and multiple ports, but doesn't support HTTPS out-of-the-box.

L<Starlet>

L<HTTP::Server::PSGI>

=cut
