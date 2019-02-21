
ptapp.pl
========

This command generates the PTA token with arbitrary parameters.

Usage
=====

```
    ptapp.pl --key 32HEXCHARACTERS --iv 32HEXCHARACTERS --date UNIXTIME --url URL
```

Example
=======

```
% ./ptapp.pl --key 00112233445566778899aabbccddeeff --iv 00112233445566778899aabbccddeeff --date 1577804400 --url '/foo/bar.mp4'
 Date: Wed Jan  1 00:00:00 2020
 URL: /foo/bar.mp4
 CRC: 0xede3729d (3991106205)
----
9695ded82e25d717295f01af7905f5410ef9eb2f554217a1f5d2d4ca9ff00a1f
```
