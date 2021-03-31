It requires
  - LWP::UserAgent
  - Test::More

You can use misc/nginx.conf for handling these tests.
The html/ that contains sample files is supposed to be placed on /var/tmp.

memo
```
% perl ptapp.pl --key 0102030405060708090a0b0c0d0e0f00 --iv 00000000000000000000000000000000 --cipher 3174ffad10cc165d58d154bdbd8a65de
      CRC: 0xa321cc2c (2736901164)
     Date: Wed Jan  1 00:00:00 2025
      URL: /*
```
