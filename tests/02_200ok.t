use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65de");
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "foo=bar; pta=3174ffad10cc165d58d154bdbd8a65de; baz=qux");
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "foo=bar; pta=5bb5f856381f235842e0449a79f95d33476fe711108897a3044c24aec8001b5b05325f3769edcf5667dbfe4f2da362e5; baz=qux");
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200 with specific path");

done_testing;
