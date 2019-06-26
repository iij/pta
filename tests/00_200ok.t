use LWP::UserAgent;
use Test::More;

use Data::Dumper;

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?pta=3174ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?foo=bar&baz=qux&pta=3174ffad10cc165d58d154bdbd8a65de');
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?ptafoo=abcde&foo=bar&baz=qux&pta=3174ffad10cc165d58d154bdbd8a65de&xyzpta=123456');
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

$ua = LWP::UserAgent->new();
$rq = HTTP::Request->new(GET => 'http://localhost/hls2/prog_index.m3u8?ptafoo=abcde&foo=bar&baz=qux&pta=d1e992f801f213cba0b4e2fdbb7079081c1689aa5c28b594c3ebfe5b5a967b78f7ced8a05cf5fac84370c071ba3d01c5&xyzpta=123456');
$rc = $ua->request($rq);
is($rc->code, 200, "Query string 200");

done_testing;
