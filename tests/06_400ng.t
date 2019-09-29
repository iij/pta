use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=7aa585bdbd015b4e0125163b6a5beb45');
$rc = $ua->request($rq);
is($rc->code, 410, "Query string and Cookie: qs expiration");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8');
$rq->header("Cookie" => "pta=7aa585bdbd015b4e0125163b6a5beb45");
$rc = $ua->request($rq);
is($rc->code, 410, "Query string and Cookie: cookie expiration");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=');
$rq->header("Cookie" => "pta=7aa585bdbd015b4e0125163b6a5beb45");
$rc = $ua->request($rq);
is($rc->code, 400, "Query string and Cookie: qs pta invalid");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=X7aa585bdbd015b4e0125163b6a5beb45');
$rq->header("Cookie" => "pta=7aa585bdbd015b4e0125163b6a5beb45");
$rc = $ua->request($rq);
is($rc->code, 400, "Query string and Cookie: qs pta invalid");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8?pta=0aa585bdbd015b4e0125163b6a5beb45');
$rc = $ua->request($rq);
is($rc->code, 403, "Query string and Cookie: qs pta invalid");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls4/prog_index.m3u8');
$rq->header("Cookie" => "pta=7aa585bdbd015b4e0125163b6a5beb00");
$rc = $ua->request($rq);
is($rc->code, 403, "Query string and Cookie: qs pta invalid");

done_testing;
