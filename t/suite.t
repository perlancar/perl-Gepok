# run Plack test suite for testing PSGI server implementation

use strict;
use warnings;

use Plack::Test::Suite;
use Test::More;

Plack::Test::Suite->run_server_tests('Gepok');
done_testing();