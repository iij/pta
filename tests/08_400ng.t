use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls5/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65deX');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: invalid format";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls5/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65d');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: invalid format";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls5/prog_index.m3u8?pta=0074ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid value";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls5/prog_index.m3u8?pta=7aa585bdbd015b4e0125163b6a5beb45');
$rc = $ua->request($rq);
is $rc->code, 410, "Query string: expiration date";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls5/prog_index.m3u8');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: without pta";

done_testing;
