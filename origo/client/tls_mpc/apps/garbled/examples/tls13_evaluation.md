## benchmarks of janus circuits

#### tls13_hvzk_256B_v2.mpcl (only for request)
Circuit: #gates=6952252 (XOR=5598976 XNOR=0 AND=1352714 OR=561 INV=1 xor=5598976 !xor=1353276 levels=863218 width=4790) #w=6956660

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 371.768125ms │ 50.35% │       │
│ Xfer    │  92.212625ms │ 12.49% │  71MB │
│ OT Init │     14.292µs │  0.00% │  58kB │
│ OT      │ 111.427958ms │ 15.09% │ 224kB │
│ Eval    │ 162.934667ms │ 22.07% │       │
│ Result  │     15.583µs │  0.00% │  133B │
│ Total   │  738.37325ms │        │  71MB │
│ ├╴Sent  │              │ 99.80% │  71MB │
│ ├╴Rcvd  │              │  0.20% │ 144kB │
│ ╰╴Flcd  │              │        │  1090 │
└─────────┴──────────────┴────────┴───────┘

#### tls13_hvzk_total_v2.mpcl (256 request, 16 kB response and 2 parity sums)
Circuit: #gates=82106180 (XOR=67550146 XNOR=0 AND=14555136 OR=897 INV=1 xor=67550146 !xor=14556034 levels=864267 width=186811) #w=82111668

┌─────────┬───────────────┬────────┬───────┐
│ Op      │          Time │      % │  Xfer │
├─────────┼───────────────┼────────┼───────┤
│ Garble  │  8.866602834s │ 61.50% │       │
│ Xfer    │  2.540007583s │ 17.62% │ 794MB │
│ OT Init │      70.125µs │  0.00% │  25kB │
│ OT      │  391.626208ms │  2.72% │ 274kB │
│ Eval    │    2.6191985s │ 18.17% │       │
│ Result  │      76.875µs │  0.00% │  133B │
│ Total   │ 14.417582125s │        │ 794MB │
│ ├╴Sent  │               │ 99.98% │ 794MB │
│ ├╴Rcvd  │               │  0.02% │ 176kB │
│ ╰╴Flcd  │               │        │ 12125 │
└─────────┴───────────────┴────────┴───────┘

exec offline: 8,86+2,54 = 11.4 s
exec online: 0,391+2,61 = 3 s
com offline: 794+0,025 = 794.05 MB
com online: 274+0.133 = 274.13 kB

#### tls13_xhts.mpcl (constant)
Circuit: #gates=3140701 (XOR=2440252 XNOR=0 AND=700447 OR=1 INV=1 xor=2440252 !xor=700449 levels=815354 width=1233) #w=3142933

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 178.243125ms │ 49.57% │       │
│ Xfer    │  37.317417ms │ 10.38% │  34MB │
│ OT Init │     12.958µs │  0.00% │   3kB │
│ OT      │  65.338209ms │ 18.17% │ 106kB │
│ Eval    │  78.631833ms │ 21.87% │       │
│ Result  │     40.292µs │  0.01% │   4kB │
│ Total   │ 359.583834ms │        │  35MB │
│ ├╴Sent  │              │ 99.79% │  35MB │
│ ├╴Rcvd  │              │  0.21% │  72kB │
│ ╰╴Flcd  │              │        │   538 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 178,24+37,31+0,012 = 215.56 ms
exec online: 65,33+78,63+0,04 = 144ms
com offline: 34+0,003 = 34 MB
com online: 106+4 = 110 kB

#### tls13_masked_k_xats.mpcl (constant)
Circuit: #gates=5178866 (XOR=4133917 XNOR=0 AND=1044947 OR=1 INV=1 xor=4133917 !xor=1044949 levels=862733 width=1689) #w=5181842

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 281.386791ms │ 46.55% │       │
│ Xfer    │  80.598875ms │ 13.33% │  54MB │
│ OT Init │     15.584µs │  0.00% │  46kB │
│ OT      │  95.151625ms │ 15.74% │ 175kB │
│ Eval    │ 147.239875ms │ 24.36% │       │
│ Result  │     32.958µs │  0.01% │   3kB │
│ Total   │ 604.425708ms │        │  54MB │
│ ├╴Sent  │              │ 99.79% │  54MB │
│ ├╴Rcvd  │              │  0.21% │ 116kB │
│ ╰╴Flcd  │              │        │   830 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 281,38+80,59+0,015 = 361.98 ms
exec online: 95,15+147,23+0,03 = 242.41 ms
com offline: 54+0,046 = 54.04 MB
com online: 175+3 = 178 kB

#### tls13_ecb_2plus.mpcl (256B ECBs)
Circuit: #gates=588309 (XOR=485906 XNOR=0 AND=102401 OR=1 INV=1 xor=485906 !xor=102403 levels=311 width=2940) #w=588661

┌─────────┬─────────────┬────────┬──────┐
│ Op      │        Time │      % │ Xfer │
├─────────┼─────────────┼────────┼──────┤
│ Garble  │ 28.506875ms │ 42.09% │      │
│ Xfer    │  5.388834ms │  7.96% │  5MB │
│ OT Init │    18.708µs │  0.03% │ 62kB │
│ OT      │ 17.278417ms │ 25.51% │ 25kB │
│ Eval    │ 16.328166ms │ 24.11% │      │
│ Result  │   210.292µs │  0.31% │ 33kB │
│ Total   │ 67.731292ms │        │  5MB │
│ ├╴Sent  │             │ 99.14% │  5MB │
│ ├╴Rcvd  │             │  0.86% │ 48kB │
│ ╰╴Flcd  │             │        │   89 │
└─────────┴─────────────┴────────┴──────┘

exec offline: 28,50+5,38+0,018 = 33.89 ms
exec online: 17,27+16,32+0,21 = 33.8 ms
com offline: 5+0,063 = 5.06 MB
com online: 33+25 = 58 kB

#### tls13_ecb_2plus.mpcl (2 kB ECBs)
Circuit: #gates=4595446 (XOR=3795443 XNOR=0 AND=800001 OR=1 INV=1 xor=3795443 !xor=800003 levels=311 width=23019) #w=4595798

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │  239.83725ms │ 64.50% │       │
│ Xfer    │     49.548ms │ 13.32% │  43MB │
│ OT Init │     13.375µs │  0.00% │  11kB │
│ OT      │  18.686583ms │  5.03% │  25kB │
│ Eval    │  61.693917ms │ 16.59% │       │
│ Result  │   2.088667ms │  0.56% │ 258kB │
│ Total   │ 371.867792ms │        │  44MB │
│ ├╴Sent  │              │ 99.39% │  43MB │
│ ├╴Rcvd  │              │  0.61% │ 272kB │
│ ╰╴Flcd  │              │        │   675 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 239,83+49,54+0,013 = 289.38 ms
exec online: 18,68+61,69+2,08 = 82.45 ms
com offline: 43+0,011 = 43.01 MB
com online: 258+25 = 283 kB

#### tls13_ecb_2plus.mpcl (16 kB ECBs)
Circuit: #gates=36764075 (XOR=30364072 XNOR=0 AND=6400001 OR=1 INV=1 xor=30364072 !xor=6400003 levels=311 width=183818) #w=36764427

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │  3.08466125s │ 53.36% │       │
│ Xfer    │    1.172634s │ 20.28% │ 351MB │
│ OT Init │     19.167µs │  0.00% │  13kB │
│ OT      │  30.559125ms │  0.53% │  25kB │
│ Eval    │ 1.060292791s │ 18.34% │       │
│ Result  │    432.788ms │  7.49% │   2MB │
│ Total   │ 5.780954333s │        │ 353MB │
│ ├╴Sent  │              │ 99.42% │ 351MB │
│ ├╴Rcvd  │              │  0.58% │   2MB │
│ ╰╴Flcd  │              │        │  5373 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 3,08+1,17 = 4.25 s
exec online: 0,030+1,06+0,432 = 1.52 s
com offline: 351+0,013 = 351.01 MB
com online: 2+0,025 = 2.02 MB

#### tls13_ecb_auth_mkey.mpcl (constant)
Circuit: #gates=73554 (XOR=60751 XNOR=0 AND=12801 OR=1 INV=1 xor=60751 !xor=12803 levels=310 width=377) #w=73906

┌─────────┬─────────────┬────────┬───────┐
│ Op      │        Time │      % │  Xfer │
├─────────┼─────────────┼────────┼───────┤
│ Garble  │  4.136875ms │ 13.29% │       │
│ Xfer    │   532.042µs │  1.71% │ 655kB │
│ OT Init │     12.25µs │  0.04% │  50kB │
│ OT      │ 15.550875ms │ 49.94% │  25kB │
│ Eval    │ 10.875375ms │ 34.93% │       │
│ Result  │    30.042µs │  0.10% │   4kB │
│ Total   │ 31.137459ms │        │ 735kB │
│ ├╴Sent  │             │ 97.25% │ 715kB │
│ ├╴Rcvd  │             │  2.75% │  20kB │
│ ╰╴Flcd  │             │        │    14 │
└─────────┴─────────────┴────────┴───────┘

exec offline: 4,13+0,53+0,012 = 4.67 ms
exec online: 15,55+10,87+0,03 = 26.45 ms
com offline: 655+50 = 705 kB
com online: 25+4 = 29 kB

#### tls13_ecb_mkey.mpcl (256B ECBs)
Circuit: #gates=661732 (XOR=546529 XNOR=0 AND=115201 OR=1 INV=1 xor=546529 !xor=115203 levels=311 width=3284) #w=662084

┌─────────┬─────────────┬────────┬──────┐
│ Op      │        Time │      % │ Xfer │
├─────────┼─────────────┼────────┼──────┤
│ Garble  │ 32.447459ms │ 43.66% │      │
│ Xfer    │    5.1405ms │  6.92% │  6MB │
│ OT Init │    13.125µs │  0.02% │ 44kB │
│ OT      │ 17.942833ms │ 24.14% │ 25kB │
│ Eval    │ 18.500208ms │ 24.89% │      │
│ Result  │   271.584µs │  0.37% │ 37kB │
│ Total   │ 74.315709ms │        │  6MB │
│ ├╴Sent  │             │ 99.17% │  6MB │
│ ├╴Rcvd  │             │  0.83% │ 52kB │
│ ╰╴Flcd  │             │        │  100 │
└─────────┴─────────────┴────────┴──────┘

exec offline: 32.44+5.14+0,013 = 37.59 ms
exec online: 17,94+18,50+0,27 = 36.71 ms
com offline: 6+0,044 = 6.04 MB
com online: 25+37 = 62 kB

#### tls13_ecb_mkey.mpcl (2 kB ECBs)
Circuit: #gates=4668869 (XOR=3856066 XNOR=0 AND=812801 OR=1 INV=1 xor=3856066 !xor=812803 levels=311 width=23363) #w=4669221

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │  245.59675ms │ 65.93% │       │
│ Xfer    │  47.145417ms │ 12.66% │  44MB │
│ OT Init │     18.833µs │  0.01% │  59kB │
│ OT      │    18.1155ms │  4.86% │  25kB │
│ Eval    │  59.196083ms │ 15.89% │       │
│ Result  │   2.431875ms │  0.65% │ 262kB │
│ Total   │ 372.504458ms │        │  44MB │
│ ├╴Sent  │              │ 99.39% │  44MB │
│ ├╴Rcvd  │              │  0.61% │ 276kB │
│ ╰╴Flcd  │              │        │   685 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 245,59+47,14+0,018 = 292.74 ms
exec online: 18,11+59,19+2,43 = 79.73 ms
com offline: 44+0,059 = 44.05 MB
com online: 262+25 = 287 kB

#### tls13_ecb_mkey.mpcl (16 kB ECBs)
Circuit: #gates=36837498 (XOR=30424695 XNOR=0 AND=6412801 OR=1 INV=1 xor=30424695 !xor=6412803 levels=311 width=184162) #w=36837850

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 3.410117167s │ 64.59% │       │
│ Xfer    │ 686.260333ms │ 13.00% │ 352MB │
│ OT Init │     39.625µs │  0.00% │  61kB │
│ OT      │  49.528708ms │  0.94% │  25kB │
│ Eval    │ 812.803334ms │ 15.39% │       │
│ Result  │   321.2955ms │  6.09% │   2MB │
│ Total   │ 5.280044667s │        │ 354MB │
│ ├╴Sent  │              │ 99.42% │ 352MB │
│ ├╴Rcvd  │              │  0.58% │   2MB │
│ ╰╴Flcd  │              │        │  5383 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 3,41+0,68 = 4.09 s
exec online: 49,52+812,80+321,29 = 1.18 s
com offline: 352+0,061 = 352.06 MB
com online: 2+0,025 = 2.02 MB

#### tls13_parity.mpcl (256 B ECBs)
Circuit: #gates=2048 (XOR=2048 XNOR=0 AND=0 OR=0 INV=0 xor=2048 !xor=0 levels=16 width=128) #w=4224

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │   1.681041ms │  0.83% │       │
│ Xfer    │     34.959µs │  0.02% │    0B │
│ OT Init │      5.625µs │  0.00% │  10kB │
│ OT      │ 114.432833ms │ 56.57% │ 229kB │
│ Eval    │     86.128ms │ 42.57% │       │
│ Result  │     18.542µs │  0.01% │   2kB │
│ Total   │    202.301ms │        │ 241kB │
│ ├╴Sent  │              │ 38.17% │  92kB │
│ ├╴Rcvd  │              │ 61.83% │ 149kB │
│ ╰╴Flcd  │              │        │     5 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 1,68+0,03 = 1.71 ms
exec online: 114,43+86,12+0,018 = 200.56 ms
com offline: 10 = 10 kB
com online: 229+2 = 231 kB

#### tls13_parity.mpcl (2 kB ECBs)
Circuit: #gates=16000 (XOR=16000 XNOR=0 AND=0 OR=0 INV=0 xor=16000 !xor=0 levels=125 width=128) #w=32128

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │   8.545917ms │  0.59% │       │
│ Xfer    │     70.458µs │  0.00% │  65kB │
│ OT Init │      3.625µs │  0.00% │  569B │
│ OT      │ 761.379917ms │ 52.94% │   1MB │
│ Eval    │ 668.155083ms │ 46.46% │       │
│ Result  │     27.833µs │  0.00% │   2kB │
│ Total   │ 1.438182833s │        │   1MB │
│ ├╴Sent  │              │ 37.96% │ 706kB │
│ ├╴Rcvd  │              │ 62.04% │   1MB │
│ ╰╴Flcd  │              │        │    14 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 8,54+0,07 = 8.61 ms
exec online: 761,37+668,15+0,027 = 1.42 s
com offline: 65+0,569 = 65.56 kB
com online: 1+0,002 = 1 MB

#### tls13_hvzk.mpcl (2 kB ECBs -- response)
Circuit: #gates=10371339 (XOR=8424911 XNOR=0 AND=1945866 OR=561 INV=1 xor=8424911 !xor=1946428 levels=863327 width=22205) #w=10375651

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │    545.879ms │ 54.88% │       │
│ Xfer    │ 125.154625ms │ 12.58% │ 103MB │
│ OT Init │     13.458µs │  0.00% │  13kB │
│ OT      │ 113.611833ms │ 11.42% │ 224kB │
│ Eval    │ 210.064959ms │ 21.12% │       │
│ Result  │     14.791µs │  0.00% │  133B │
│ Total   │ 994.738666ms │        │ 104MB │
│ ├╴Sent  │              │ 99.86% │ 103MB │
│ ├╴Rcvd  │              │  0.14% │ 144kB │
│ ╰╴Flcd  │              │        │  1589 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 545,87+125,15+0,013 = 671.03 ms
exec online: 113,61+210,06+0,014 = 323.68 ms
com offline: 103+0,013 = 103.01 MB
com online: 224+0,133 = 224.13 kB

#### tls13_hvzk.mpcl (16 kB ECBs -- response)
Circuit: #gates=42539968 (XOR=34993540 XNOR=0 AND=7545866 OR=561 INV=1 xor=34993540 !xor=7546428 levels=864202 width=175330) #w=42544280

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 3.498155542s │ 64.94% │       │
│ Xfer    │ 794.596417ms │ 14.75% │ 411MB │
│ OT Init │    418.958µs │  0.01% │  15kB │
│ OT      │  121.80125ms │  2.26% │ 224kB │
│ Eval    │ 971.536208ms │ 18.04% │       │
│ Result  │     30.834µs │  0.00% │  133B │
│ Total   │ 5.386539209s │        │ 411MB │
│ ├╴Sent  │              │ 99.96% │ 411MB │
│ ├╴Rcvd  │              │  0.04% │ 144kB │
│ ╰╴Flcd  │              │        │  6287 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 3.49+0,79 = 4.28 s
exec online: 121,80+971,53+0,03 = 1.09 s
com offline: 411+0,015 = 411.01 MB
com online: 224+0,133 = 224.13 kB

#### tls13_hvzk.mpcl (256B ECBs -- request)
Circuit: #gates=6364202 (XOR=5115374 XNOR=0 AND=1248266 OR=561 INV=1 xor=5115374 !xor=1248828 levels=863218 width=3130) #w=6368514

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 318.511625ms │ 47.06% │       │
│ Xfer    │  77.453542ms │ 11.44% │  65MB │
│ OT Init │     14.375µs │  0.00% │  63kB │
│ OT      │ 112.185125ms │ 16.57% │ 224kB │
│ Eval    │ 168.679917ms │ 24.92% │       │
│ Result  │     30.625µs │  0.00% │  133B │
│ Total   │ 676.875209ms │        │  65MB │
│ ├╴Sent  │              │ 99.78% │  65MB │
│ ├╴Rcvd  │              │  0.22% │ 144kB │
│ ╰╴Flcd  │              │        │  1003 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 318,51+77,45+0,01 = 395.97 ms
exec online: 112,18+168,67+0,03 = 280.88 ms
com offline: 65+0,06 = 65.06 MB
com online: 224+0,133 = 224.13 kB

#### tls13_hvzk.mpcl (kdc, shts, 16kB response ecb parity with ecb01, 256 B request ecb parity)
Circuit: #gates=44754226 (XOR=36830640 XNOR=0 AND=7922688 OR=897 INV=1 xor=36830640 !xor=7923586 levels=864267 width=178460) #w=44759618

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │  2.55048725s │ 51.60% │       │
│ Xfer    │ 931.628166ms │ 18.85% │ 432MB │
│ OT Init │     29.709µs │  0.00% │  52kB │
│ OT      │ 142.923083ms │  2.89% │ 274kB │
│ Eval    │ 1.317931958s │ 26.66% │       │
│ Result  │       24.5µs │  0.00% │  133B │
│ Total   │ 4.943024666s │        │ 432MB │
│ ├╴Sent  │              │ 99.96% │ 432MB │
│ ├╴Rcvd  │              │  0.04% │ 176kB │
│ ╰╴Flcd  │              │        │  6606 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 2,55+0,93 = 3.48 s
exec online: 0,14+1,31 = 1.45 ms
com offline: 432+0,052 = 432.05 MB
com online: 274+0,133 = 274.13 kB

#### tls13_hvzk_transparent.mpcl (kdc, shts, 16kB response ecb parity with ecb01, 256 B request ecb parity)
Circuit: #gates=79126072 (XOR=65434170 XNOR=0 AND=13690780 OR=1121 INV=1 xor=65434170 !xor=13691902 levels=2197091 width=178460) #w=79131592

┌─────────┬───────────────┬────────┬───────┐
│ Op      │          Time │      % │  Xfer │
├─────────┼───────────────┼────────┼───────┤
│ Garble  │  8.336996417s │ 46.59% │       │
│ Xfer    │  4.351013333s │ 24.31% │ 754MB │
│ OT Init │      23.709µs │  0.00% │  40kB │
│ OT      │  277.925166ms │  1.55% │ 274kB │
│ Eval    │  4.929336292s │ 27.54% │       │
│ Result  │     305.042µs │  0.00% │  133B │
│ Total   │ 17.895599959s │        │ 754MB │
│ ├╴Sent  │               │ 99.98% │ 754MB │
│ ├╴Rcvd  │               │  0.02% │ 176kB │
│ ╰╴Flcd  │               │        │ 11521 │
└─────────┴───────────────┴────────┴───────┘

exec offline: 8,33+4,35 = 12.68 s
exec online: 0,277+4,92 = 5.19 s
com offline: 754+0,04 = 754.04 MB
com online: 274+0,133 = 274.13 kB

#### tls13_tag.mpcl (256B ciphertext as input)
Circuit: #gates=2020785 (XOR=1455261 XNOR=0 AND=565522 OR=1 INV=1 xor=1455261 !xor=565524 levels=9011 width=1584) #w=2023185
gates time 2: 4.04 million

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 119.330459ms │ 30.67% │       │
│ Xfer    │     23.651ms │  6.08% │  26MB │
│ OT Init │     13.708µs │  0.00% │  34kB │
│ OT      │ 121.677708ms │ 31.27% │ 254kB │
│ Eval    │ 124.421125ms │ 31.97% │       │
│ Result  │         34µs │  0.01% │   2kB │
│ Total   │    389.128ms │        │  26MB │
│ ├╴Sent  │              │ 99.37% │  26MB │
│ ├╴Rcvd  │              │  0.63% │ 165kB │
│ ╰╴Flcd  │              │        │   404 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 119,33+23,65+0,013 = 142.99 ms, times 2 = 285.98 ms
exec online: 121,67+124,42+0,034 = 246.12 ms, times 2 = 492.24 ms
com offline: 26+0,034 = 26.03 MB, times 2 = 52.06 MB
com online: 254+2 = 256 kB, times 2 = 512 kB

#### tls13_tag.mpcl (1.6 kB ciphertext as input)
Circuit: #gates=11643659 (XOR=8347043 XNOR=0 AND=3296614 OR=1 INV=1 xor=8347043 !xor=3296616 levels=52019 width=7632) #w=11656811

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 712.649625ms │ 31.12% │       │
│ Xfer    │ 191.680667ms │  8.37% │ 152MB │
│ OT Init │     16.375µs │  0.00% │  34kB │
│ OT      │ 629.947166ms │ 27.51% │   1MB │
│ Eval    │ 755.627917ms │ 33.00% │       │
│ Result  │     27.167µs │  0.00% │   2kB │
│ Total   │ 2.289948917s │        │ 153MB │
│ ├╴Sent  │              │ 99.39% │ 152MB │
│ ├╴Rcvd  │              │  0.61% │ 939kB │
│ ╰╴Flcd  │              │        │  2331 │
└─────────┴──────────────┴────────┴───────┘

#### tls13_tag.mpcl (2 kB ciphertext as input)
Circuit: #gates=14507612 (XOR=10398171 XNOR=0 AND=4109439 OR=1 INV=1 xor=10398171 !xor=4109441 levels=64819 width=9432) #w=14523964
gates times 2: 29.01 million

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 887.611583ms │ 28.49% │       │
│ Xfer    │ 329.924125ms │ 10.59% │ 189MB │
│ OT Init │     17.167µs │  0.00% │  16kB │
│ OT      │ 803.299375ms │ 25.79% │   1MB │
│ Eval    │ 1.094273167s │ 35.13% │       │
│ Result  │     71.208µs │  0.00% │   2kB │
│ Total   │ 3.115196625s │        │ 191MB │
│ ├╴Sent  │              │ 99.39% │ 190MB │
│ ├╴Rcvd  │              │  0.61% │   1MB │
│ ╰╴Flcd  │              │        │  2905 │
└─────────┴──────────────┴────────┴───────┘

exec offline: 887,61+329,92+0,017 = 1.21 s, times 2 = 2.42 s
exec online: 0,80+1,09 = 1.89 s, times 2 = 3.78 s
com offline: 54+0,046 = 189.01 MB, times 2 = 378.02 MB
com online: 175+3 = 1 MB, times 2 = 2 MB

#### tls13_tag.mpcl (4 kB ciphertext as input)
Circuit: #gates=28827362 (XOR=20653796 XNOR=0 AND=8173564 OR=1 INV=1 xor=20653796 !xor=8173566 levels=128822 width=18432) #w=28859714

┌─────────┬──────────────┬────────┬───────┐
│ Op      │         Time │      % │  Xfer │
├─────────┼──────────────┼────────┼───────┤
│ Garble  │ 2.711303041s │ 37.78% │       │
│ Xfer    │ 675.922084ms │  9.42% │ 376MB │
│ OT Init │     16.125µs │  0.00% │  57kB │
│ OT      │ 1.571386875s │ 21.90% │   3MB │
│ Eval    │ 2.217592583s │ 30.90% │       │
│ Result  │     77.667µs │  0.00% │   2kB │
│ Total   │ 7.176298375s │        │ 380MB │
│ ├╴Sent  │              │ 99.39% │ 378MB │
│ ├╴Rcvd  │              │  0.61% │   2MB │
│ ╰╴Flcd  │              │        │  5773 │
└─────────┴──────────────┴────────┴───────┘

#### tls13_tag.mpcl (6.4 kB ciphertext as input)
Circuit: #gates=46011059 (XOR=32960543 XNOR=0 AND=13050514 OR=1 INV=1 xor=32960543 !xor=13050516 levels=205625 width=29232) #w=46062611

┌─────────┬───────────────┬────────┬───────┐
│ Op      │          Time │      % │  Xfer │
├─────────┼───────────────┼────────┼───────┤
│ Garble  │  6.167864042s │ 42.65% │       │
│ Xfer    │  1.473100458s │ 10.19% │ 601MB │
│ OT Init │        38.5µs │  0.00% │  14kB │
│ OT      │  2.567710375s │ 17.76% │   5MB │
│ Eval    │  4.251528792s │ 29.40% │       │
│ Result  │        72.5µs │  0.00% │   2kB │
│ Total   │ 14.460314667s │        │ 607MB │
│ ├╴Sent  │               │ 99.39% │ 603MB │
│ ├╴Rcvd  │               │  0.61% │   3MB │
│ ╰╴Flcd  │               │        │  9216 │
└─────────┴───────────────┴────────┴───────┘


### zkp evaluation

#### 2kb zkopen (without plaintext)
: 22:58:50 INF compiling circuit
22:58:50 INF parsed circuit inputs nbPublic=17 nbSecret=2000
22:58:56 INF building constraint builder nbConstraints=58285
{"level":"debug","elapsed":"11.824307s","time":1692824342,"message":"compile constraint system time."}
{"level":"debug","written":"2260543331","time":1692824354,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"6.538226s","time":1692824360,"message":"groth16.Setup time."}
{"level":"debug","written":"9100144","time":1692824360,"message":"prover key bytes"}
{"level":"debug","written":"868","time":1692824360,"message":"verifier key bytes"}
22:59:23 DBG constraint system solver done backend=groth16 nbConstraints=58285 took=3189.888583
22:59:23 DBG main.go:181 > modulus of zk snark compiler 21888242871839275222246405745257275088548364400416034343698204186575808495617
22:59:24 DBG prover done backend=groth16 curve=bn254 nbConstraints=58285 took=129.613333
{"level":"debug","elapsed":"3.321334917s","time":1692824364,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692824364,"message":"proof bytes"}
{"level":"debug","written":"69","time":1692824364,"message":"witness bytes"}
22:59:24 DBG verifier done backend=groth16 curve=bn254 took=1.032584
{"level":"debug","elapsed":"1.045166ms","time":1692824364,"message":"groth16.Verify time."}

## 1kB zkopen:
go run main.go -debug -tls13-zkopen -byte-size 1000 -iterations 1            (main)gnark_lib
{"level":"error","time":1692902633,"message":"byte_size must be divisible by 16, e.g. byte_size=64 works."}
{"level":"debug","time":1692902633,"message":"Debugging activated."}
modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
size mimc: 31
kdf: &{0x140000b4480 32 [] 1 [] []}
{"level":"debug","time":1692902633,"message":"EvaluateZkOpen"}
{"level":"debug","length":"31","time":1692902633,"message":"zkOpen input size"}
20:43:53 INF compiling circuit
20:43:53 INF parsed circuit inputs nbPublic=1009 nbSecret=2000
20:43:55 INF building constraint builder nbConstraints=49047
{"level":"debug","elapsed":"3.081750666s","time":1692902637,"message":"compile constraint system time."}
{"level":"debug","written":"561060909","time":1692902639,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"3.082404333s","time":1692902642,"message":"groth16.Setup time."}
{"level":"debug","written":"8280132","time":1692902642,"message":"prover key bytes"}
{"level":"debug","written":"32612","time":1692902642,"message":"verifier key bytes"}
20:44:03 DBG constraint system solver done backend=groth16 nbConstraints=49047 took=798.232708
20:44:03 DBG prover done backend=groth16 curve=bn254 nbConstraints=49047 took=104.815125
{"level":"debug","elapsed":"903.505375ms","time":1692902643,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692902643,"message":"proof bytes"}
{"level":"debug","written":"4037","time":1692902643,"message":"witness bytes"}
20:44:03 DBG verifier done backend=groth16 curve=bn254 took=1.149584
{"level":"debug","elapsed":"1.173083ms","time":1692902643,"message":"groth16.Verify time."}

### 2kB zkOpen including xor for ciphertext
go run main.go -debug -tls13-zkopen -byte-size 2000 -iterations 1            (main)gnark_lib
{"level":"debug","time":1692900696,"message":"Debugging activated."}
modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
size mimc: 62
kdf: &{0x140000b44e0 32 [] 1 [] []}
{"level":"debug","time":1692900696,"message":"EvaluateZkOpen"}
{"level":"debug","length":"62","time":1692900696,"message":"zkOpen input size"}
20:11:36 INF compiling circuit
20:11:36 INF parsed circuit inputs nbPublic=2001 nbSecret=3984
20:11:42 INF building constraint builder nbConstraints=93997
{"level":"debug","elapsed":"12.032136875s","time":1692900708,"message":"compile constraint system time."}
{"level":"debug","written":"2269774883","time":1692900721,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"8.968863875s","time":1692900730,"message":"groth16.Setup time."}
{"level":"debug","written":"15903344","time":1692900730,"message":"prover key bytes"}
{"level":"debug","written":"64356","time":1692900730,"message":"verifier key bytes"}
20:12:13 DBG constraint system solver done backend=groth16 nbConstraints=93997 took=3592.206542
20:12:14 DBG prover done backend=groth16 curve=bn254 nbConstraints=93997 took=220.064875
{"level":"debug","elapsed":"3.815470833s","time":1692900734,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692900734,"message":"proof bytes"}
{"level":"debug","written":"8005","time":1692900734,"message":"witness bytes"}
20:12:14 DBG verifier done backend=groth16 curve=bn254 took=1.45075
{"level":"debug","elapsed":"1.513875ms","time":1692900734,"message":"groth16.Verify time."}


## 4kB ZkOpen:
go run main.go -debug -tls13-zkopen -byte-size 4000 -iterations 1           (main)gnark_lib
{"level":"debug","time":1692902439,"message":"Debugging activated."}
modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
size mimc: 125
kdf: &{0x140000b4480 32 [] 1 [] []}
{"level":"debug","time":1692902439,"message":"EvaluateZkOpen"}
{"level":"debug","length":"125","time":1692902439,"message":"zkOpen input size"}
20:40:39 INF compiling circuit
20:40:39 INF parsed circuit inputs nbPublic=4017 nbSecret=8016
20:41:06 INF building constraint builder nbConstraints=185347
{"level":"debug","elapsed":"49.778955667s","time":1692902488,"message":"compile constraint system time."}
{"level":"debug","written":"9750109051","time":1692902561,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"41.461696625s","time":1692902602,"message":"groth16.Setup time."}
{"level":"debug","written":"31328028","time":1692902602,"message":"prover key bytes"}
{"level":"debug","written":"128868","time":1692902602,"message":"verifier key bytes"}
20:43:38 DBG constraint system solver done backend=groth16 nbConstraints=185347 took=15704.876541
20:43:39 DBG prover done backend=groth16 curve=bn254 nbConstraints=185347 took=507.600166
{"level":"debug","elapsed":"16.338770334s","time":1692902619,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692902619,"message":"proof bytes"}
{"level":"debug","written":"16069","time":1692902619,"message":"witness bytes"}
{"level":"debug","elapsed":"3.360209ms","time":1692902619,"message":"groth16.Verify time."}

## 256B zkOpen:
go run main.go -debug -tls13-zkopen -byte-size 256 -iterations 1             (main)gnark_lib
{"level":"debug","time":1692904847,"message":"Debugging activated."}
modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
size mimc: 8
kdf: &{0x14000134480 32 [] 1 [] []}
{"level":"debug","time":1692904847,"message":"EvaluateZkOpen"}
{"level":"debug","length":"8","time":1692904847,"message":"zkOpen input size"}
21:20:47 INF compiling circuit
21:20:47 INF parsed circuit inputs nbPublic=273 nbSecret=528
21:20:47 INF building constraint builder nbConstraints=15697
{"level":"debug","elapsed":"217.498292ms","time":1692904847,"message":"compile constraint system time."}
{"level":"debug","written":"38217641","time":1692904848,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"774.025334ms","time":1692904848,"message":"groth16.Setup time."}
{"level":"debug","written":"2607288","time":1692904848,"message":"prover key bytes"}
{"level":"debug","written":"9060","time":1692904848,"message":"verifier key bytes"}
21:20:48 DBG constraint system solver done backend=groth16 nbConstraints=15697 took=49.094417
21:20:48 DBG prover done backend=groth16 curve=bn254 nbConstraints=15697 took=32.069083
{"level":"debug","elapsed":"81.371458ms","time":1692904848,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692904848,"message":"proof bytes"}
{"level":"debug","written":"1093","time":1692904848,"message":"witness bytes"}
21:20:48 DBG verifier done backend=groth16 curve=bn254 took=1.029041
{"level":"debug","elapsed":"1.041833ms","time":1692904848,"message":"groth16.Verify time."}