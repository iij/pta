use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65deX');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: invalid format";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65d');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: invalid format";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=0074ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid value";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=00');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid value";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=01');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid value";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=7aa585bdbd015b4e0125163b6a5beb45');
$rc = $ua->request($rq);
is $rc->code, 410, "Query string: expiration date";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=2935008c7a6c5e01f89616eafc3c0d6ac44cf5f6f06862ca9c767b05adbe629cb1faad6f66f318b082b9b6d609c81945');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid path";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=a6e7a739f6dd7ab84b184b3c99f38406808a727602dfdd52163b51c38d3489730bc6f055bed7a04439b1cf9c5bb54539');
$rc = $ua->request($rq);
is $rc->code, 403, "Query string: invalid path";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8');
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: without pta";

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8');
$rq->header("Cookie" => "pta=3174ffad10cc165d58d154bdbd8a65de");
$rc = $ua->request($rq);
is $rc->code, 400, "Query string: without pta and with cookie";

done_testing;
