use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookiex" => "pta=3174ffad10cc165d58d154bdbd8a65de");
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: invalid header");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: without cookie");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "ptapta=7aa585bdbd015b4e0125163b6a5beb45");
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: invalid pta");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "pta=7aa585bdbd015b4e0125163b6a5beb45");
$rc = $ua->request($rq);
is($rc->code, 410, "Cookie: expiration");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65dex");
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: invalid pta");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65d");
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: invalid pta");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls3/prog_index.m3u8pta=3174ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is($rc->code, 400, "Cookie: use qs instead of cookie");

done_testing;
