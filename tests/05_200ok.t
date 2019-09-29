use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65de');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65de00");
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200 with invalid cookie");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65de");
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200 with invalid cookie");

done_testing;
