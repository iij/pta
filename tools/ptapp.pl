#!/usr/bin/env perl
package main;

use strict;
use warnings;
use integer;
use Carp;
use Getopt::Long;
use Time::Local;

use Data::Dumper;

sub usage {
    my $prog = (split('/', $0))[-1];
    print STDERR <<"__HDOC__";
Usage:
    $prog --key 32HEXCHARACTERS --iv 32HEXCHARACTERS --date UNIXTIME --url URL
__HDOC__
    exit 1;
}

my ($key, $iv, $unixtime, $url, $cipher, $crc);

GetOptions("key=s"    => \$key,
	   "iv=s"     => \$iv,
	   "date=s"   => \$unixtime,
	   "url=s"    => \$url,
#	   "cipher=s" => \$cipher,
#	   "crc=i"    => \$crc,
           "h|help"   => sub { usage(); exit 1; },
) or die "Error in command line arguments\n";

if (!defined($key)      or
    !defined($iv)       or
    !defined($unixtime) or
    !defined($url)) {
    usage();
    exit(1);
}

my $date = localtime($unixtime);

warn " Date: $date\n";
$date = pack("C*", (0, 0, 0, 0, (map {hex($_)}
				 unpack("(A2)*", sprintf("%x",$unixtime)))));
$url = pack("C*", (map {ord($_)} unpack("(A1)*", $url)));
warn " URL: $url\n";

my $plain = $date . $url;
$crc = Crypt::CRC32::crc32($plain);
warn sprintf(" CRC: 0x%08x (%d)\n", $crc, $crc);

$plain = pack("N", $crc) . $plain;

my $aes = Crypt::AES::PP->new({
#    debug => 1,
    key_size => 128,
    key      => $key,
    iv       =>  $iv,
    mode     => "CBC"});

my $out = $aes->Cipher(unpack("H*", $plain));
print "----\n";
print $out;
print "\n";
exit;

#
#~% ptapp.pl --key 11111111111111111111111111111111 --iv 22222222222222222222222222222222 --date 1830025200 --url '/hoge*geho'
#Date: Wed Dec 29 05:20:00 2027
# URL: /hoge*geho
# CRC: 0xb99cd31a (3114062618)
#====
#8598ef965eab565903647dca6af897d6a2ae1aa1f6d9a82751c333bbd46128c1
#
{
    package Crypt::CRC32;
    sub crc32 {
	my $input = shift;

	my $init_value = 0;
	my $polynomial = 0xedb88320;

	my @lookup_table;

	for (my $i=0; $i<256; $i++) {
	    my $x = $i;
	    for (my $j=0; $j<8; $j++) {
		if ($x & 1) {
		    $x = ($x >> 1) ^ $polynomial;
		} else {
		    $x = $x >> 1;
		}
	    }
	    push @lookup_table, $x;
	}
	my $crc = $init_value ^ 0xffffffff;
	foreach my $x (unpack ('C*', $input)) {
	    $crc = (($crc >> 8) & 0xffffff) ^ $lookup_table[ ($crc ^ $x) & 0xff ];
	}
	$crc = $crc ^ 0xffffffff;
	return $crc;
    }
}

{
    package Crypt::AES::PP;

    use Data::Dumper;

    my @S_box;

    sub new {
	my $self = shift;
	_init(bless shift, $self);
    }

    sub _init {
	my $self = shift;

	my @key = $self->{key} =~ /.{2}/g;
	$self->{key} = [ map { hex } @key ];

	#my @iv = $self->{iv} =~ /.{2}/g;
	#$self->{iv} = [ map { hex } @iv ];

	$self->{input_len} = 0;
	$self->{input} = "";
	$self->{output} = "";

	$self->{State} = undef;
	
	$self->{Nb} = 4; # 32 * 4 = 128 bit

	# AES128
	$self->{Nk} = 4; # key length
	$self->{Nr} = 10;# round size

	$self->{w} = [[]];

	@S_box = (
	    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

	_KeyExpansion($self);
	
	return $self;
    }

    sub _set_state_with_iv {
	my $self  = shift;
	#my $input = shift;

	my @state = $self->{input} =~ /.{2}/g;
	@state = map { hex } @state;

	my @iv = $self->{iv} =~ /.{2}/g;
	$self->{iv} = [ map { hex } @iv ];

	if (defined($self->{iv})) {
	    $self->{State} = [
		[$state[0]  ^ $self->{iv}[0], $state[4]  ^ $self->{iv}[4],
		 $state[8]  ^ $self->{iv}[8], $state[12] ^ $self->{iv}[12]],
		
		[$state[1]  ^ $self->{iv}[1], $state[5]  ^ $self->{iv}[5],
		 $state[9]  ^ $self->{iv}[9], $state[13] ^ $self->{iv}[13]],
		
		[$state[2]  ^ $self->{iv}[2], $state[6]  ^ $self->{iv}[6],
		 $state[10] ^ $self->{iv}[10],$state[14] ^ $self->{iv}[14]],
		
		[$state[3]  ^ $self->{iv}[3], $state[7]  ^ $self->{iv}[7],
		 $state[11] ^ $self->{iv}[11],$state[15] ^ $self->{iv}[15]]
		];
	} else {
	    $self->{State} = [
		[$state[0], $state[4], $state[8], $state[12]],
		[$state[1], $state[5], $state[9], $state[13]],
		[$state[2], $state[6], $state[10],$state[14]],
		[$state[3], $state[7], $state[11],$state[15]]
		];
	}
    }

    sub _ready_for_next {
	my $self = shift;

	$self->{iv} = "";
	for (my $c = 0; $c < 4; ++$c) {
	    for (my $r = 0; $r < 4; ++$r) {
		$self->{output} .= sprintf "%02x", $self->{State}->[$r][$c];
		$self->{iv} .= sprintf "%02x", $self->{State}->[$r][$c];
	    }
	}
	$self->{input} = substr($self->{input}, 32);
    }

    sub _pkcs7_padding {
	my $self = shift;
	my $input = shift;

	my $len = length($input);
	do {
	    $len = $len - 32;
	} while ($len > 0);
	my $padnum = ($len * -1) / 2;
	$padnum = $padnum == 0 ? 16 : $padnum;
	my $padstr = sprintf("%02x", $padnum) x $padnum;

	$self->{input} = $input . $padstr;
	$self->{input_len} = length($self->{input});
    }

    sub InvCipher {
	my $self = shift;
    }

    sub Cipher {
	my $self = shift;
	my $in   = shift;

	_pkcs7_padding($self, $in);
	for (my $i = 0; $i < $self->{input_len}; $i += 32) {
	    _set_state_with_iv($self);
	    _Cipher($self);
	    _ready_for_next($self);
	}

	return $self->{output};
    }

    sub _Cipher {
	my $self  = shift;
	#my $state = shift;

	_AddRoundKey($self, 0);

	for (my $round = 1; $round < $self->{Nr}; ++$round) {
	    _SubBytes($self);
	    _ShiftRows($self);
	    _MixColumns($self);
	    _AddRoundKey($self, $round);
	}

	_SubBytes($self);
	_ShiftRows($self);
	_AddRoundKey($self, $self->{Nr});
    }

    sub _AddRoundKey {
	my $self  = shift;
	my $round = shift;

	for (my $c = 0; $c < $self->{Nb}; ++$c) {
	    for (my $r = 0; $r < 4; ++$r) {
		$self->{State}->[$r][$c] =
		    $self->{State}->[$r][$c] ^ $self->{w}->[$round * $self->{Nb} + $c][$r];
	    }
	}
        if (defined($self->{debug})) {
	    print "vvvv AddRoundKey vvvv\n";
	    _debug_word_output($self->{State}->[0]);
	    _debug_word_output($self->{State}->[1]);
	    _debug_word_output($self->{State}->[2]);
	    _debug_word_output($self->{State}->[3]);
        }
    }

    sub _SubBytes {
	my $self = shift;

	for (my $r = 0; $r < 4; ++$r) {
	    for (my $c = 0; $c < 4; ++$c) {
		$self->{State}->[$r][$c] = $S_box[$self->{State}->[$r][$c]];
	    }
	}

        if (defined($self->{debug})) {
	    print "vvvv SubBytes vvvv\n";
	    _debug_word_output($self->{State}->[0]);
	    _debug_word_output($self->{State}->[1]);
	    _debug_word_output($self->{State}->[2]);
	    _debug_word_output($self->{State}->[3]);
        }
    }

    sub _ShiftRows {
	my $self = shift;

	for (my $r = 1; $r < 4; ++$r) {
	    for (1..$r) {
		push(@{$self->{State}->[$r]}, shift(@{$self->{State}->[$r]}));
	    }
	}

        if (defined($self->{debrug})) {
	    print "vvvv ShiftRows vvvv\n";
	    _debug_word_output($self->{State}->[0]);
	    _debug_word_output($self->{State}->[1]);
	    _debug_word_output($self->{State}->[2]);
	    _debug_word_output($self->{State}->[3]);
        }
    }

    sub _MixColumns {
	my $self = shift;

	my ($t0, $t1, $t2);
	for (my $c = 0; $c < 4; ++$c) {
	    $t0 = $self->{State}->[0][$c];
	    $t1 = ($self->{State}->[0][$c] ^ $self->{State}->[1][$c] ^ $self->{State}->[2][$c] ^ $self->{State}->[3][$c]);
	    $t2 = $self->{State}->[0][$c] ^ $self->{State}->[1][$c]; $t2 = _xtime($t2); $self->{State}->[0][$c] ^= (($t2 ^ $t1) & 0xff);
	    $t2 = $self->{State}->[1][$c] ^ $self->{State}->[2][$c]; $t2 = _xtime($t2); $self->{State}->[1][$c] ^= (($t2 ^ $t1) & 0xff);
	    $t2 = $self->{State}->[2][$c] ^ $self->{State}->[3][$c]; $t2 = _xtime($t2); $self->{State}->[2][$c] ^= (($t2 ^ $t1) & 0xff);
	    $t2 = $self->{State}->[3][$c] ^ $t0;                     $t2 = _xtime($t2); $self->{State}->[3][$c] ^= (($t2 ^ $t1) & 0xff);
	}

        if (defined($self->{debug})) {
	    print "vvvv MixColumns vvvv\n";
            _debug_word_output($self->{State}->[0]);
	    _debug_word_output($self->{State}->[1]);
	    _debug_word_output($self->{State}->[2]);
	    _debug_word_output($self->{State}->[3]);
        }
    }

    sub _xtime {
	my $x = shift;

	#printf "%x\n", (($x << 1) ^ ((($x >> 7) & 1) * 0x1b));
	return (($x << 1) ^ ((($x >> 7) & 1) * 0x1b));
    }
    
    sub _RotWord {
	return ($_[1], $_[2], $_[3], $_[0]);
    }

    sub _SubWord {
	return ($S_box[$_[0]], $S_box[$_[1]], $S_box[$_[2]], $S_box[$_[3]]);
    }

    sub _xor_Rcon {
	my $w0       = shift;
	my $w1       = shift;
	my $w2       = shift;
	my $w3       = shift;
	my $rcon_idx = shift;	
	my @Rcon     = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36);

	return ($w0 ^ $Rcon[$rcon_idx], $w1, $w2, $w3);
    }

    sub _xor_word {
	return ($_[0] ^ $_[4], $_[1] ^ $_[5], $_[2] ^ $_[6], $_[3] ^ $_[7]);
    }

    sub _KeyExpansion {
	my $self = shift;
	
	my @temp;
	for (my $i = 0; $i < $self->{Nk}; ++$i) {
	    @{$self->{w}->[$i]} = ($self->{key}->[($i * 4) + 0],
				   $self->{key}->[($i * 4) + 1],
				   $self->{key}->[($i * 4) + 2],
				   $self->{key}->[($i * 4) + 3]);
	}
	
	for (my $i = $self->{Nk}; $i < $self->{Nb} * ($self->{Nr} + 1); ++$i) {
	    @temp = @{$self->{w}->[$i - 1]};
	    if ($i % $self->{Nk} == 0) {
		@temp = _xor_Rcon(_SubWord(_RotWord(@temp)), $i / $self->{Nk});
	    }
	    @{$self->{w}->[$i]} = _xor_word(@{$self->{w}->[$i - $self->{Nk}]}, @temp);
            if (defined($self->{debug})) {
	        _debug_word_output($self->{w}->[$i]);
            }
	}
    }

    sub _debug_word_output {
	my $word = shift;
	
	printf "%02x %02x %02x %02x\n", $word->[0], $word->[1], $word->[2], $word->[3];
    }
}
