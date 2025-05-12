//! PEM decoding and encoding tests.
#![cfg(all(feature = "derive", feature = "oid", feature = "alloc"))]

use const_oid::ObjectIdentifier;
use der::{Any, Decode, Sequence, asn1::BitString};
use hex_literal::hex;

/// X.509 `AlgorithmIdentifier`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpkiOwned {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

#[test]
fn from_ber() {
    let _any1 = Any::from_ber(&BER_CERT).expect("from_ber 1");

    //let any2 = Any::from_ber(any1.value()).expect("from_ber 2");
}

const BER_CERT: [u8; 1630] = hex!(
    "30 80 06 09 2a 86 48 86 f7 0d 01 07 02 a0 80 30 
80 02 01 01 31 0b 30 09 06 05 2b 0e 03 02 1a 05 
00 30 80 06 09 2a 86 48 86 f7 0d 01 07 01 00 00 
a0 82 04 49 30 82 04 45 30 82 02 2d a0 03 02 01 
02 02 01 10 30 0d 06 09 2a 86 48 86 f7 0d 01 01 
0b 05 00 30 4c 31 0b 30 09 06 03 55 04 06 13 02 
55 53 31 10 30 0e 06 03 55 04 0a 13 07 73 63 65 
70 2d 63 61 31 10 30 0e 06 03 55 04 0b 13 07 53 
43 45 50 20 43 41 31 19 30 17 06 03 55 04 03 13 
10 4d 49 43 52 4f 4d 44 4d 20 53 43 45 50 20 43 
41 30 1e 17 0d 32 32 31 31 32 39 31 35 34 34 32 
38 5a 17 0d 32 33 31 31 32 39 31 35 34 34 32 38 
5a 30 17 31 15 30 13 06 03 55 04 03 13 0c 61 73 
64 66 31 32 33 34 61 73 64 66 30 82 01 22 30 0d 
06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 
0f 00 30 82 01 0a 02 82 01 01 00 bc c2 53 f6 be 
75 54 96 ea 15 98 08 9b 45 cc ab 63 3b dc 33 8d 
9b 5e 77 0a 86 b7 22 9f f3 68 5d 42 34 9e e3 a3 
50 27 99 b5 29 29 5c 3f 45 ea 53 fb 74 dd 4c ce 
50 0f 23 63 99 05 0e 3a 86 91 aa c6 f1 67 2c e0 
6a 13 be ce 6e af 77 0f a2 54 b2 c9 84 e5 5a d5 
5a 41 ff a0 f0 4a a2 f5 77 56 3d 90 4a a4 d4 a1 
98 d2 28 8d 25 f7 6a 84 de 93 23 25 67 e2 5e cc 
fc 26 fc 9d e6 cd 22 64 91 22 4d 67 3c f7 0e 50 
30 4f ed 1e a7 63 88 2c 16 5a 79 53 aa 36 c4 f9 
a5 e8 8e 00 f5 0a d9 9d 09 81 9c 44 75 14 c1 3b 
3e fb 59 df 71 b5 a0 13 d2 e1 73 7b b4 30 79 6f 
0f 31 a9 89 48 f6 7d b3 56 63 d4 f9 ae c4 39 2b 
85 ca e6 ba d4 93 dd f7 df 3c 16 d1 05 96 c8 17 
06 74 59 c2 b3 69 c2 99 1d 4c 19 03 81 5d a2 06 
70 21 e0 a5 39 5f 87 24 4a 2b 30 a5 f1 bb 46 14 
d0 d5 27 ab c0 eb 8d c2 00 ac bd 02 03 01 00 01 
a3 67 30 65 30 0e 06 03 55 1d 0f 01 01 ff 04 04 
03 02 07 80 30 13 06 03 55 1d 25 04 0c 30 0a 06 
08 2b 06 01 05 05 07 03 02 30 1d 06 03 55 1d 0e 
04 16 04 14 a2 07 75 c6 b8 1b 9a 8e bc c0 be 99 
7a 4f 91 84 d5 01 76 73 30 1f 06 03 55 1d 23 04 
18 30 16 80 14 06 0a d7 48 64 c9 78 f8 99 6f 95 
41 c7 85 6c 95 69 d2 16 2d 30 0d 06 09 2a 86 48 
86 f7 0d 01 01 0b 05 00 03 82 02 01 00 50 65 be 
56 57 78 f9 bf 07 1d fd d9 18 29 d6 2c 28 b8 6f 
1f ad e3 53 cd 6b 15 f9 8c 6b 41 0c 4a f0 d5 c0 
cf 3f 4f f1 72 f9 77 ee eb 94 0c 6f b9 38 f2 36 
2b f4 a1 b3 8f a5 93 fd ac ef ca 7a db 5c 14 ad 
e2 cb ab 7d 31 a4 05 14 4f 36 d7 9f 65 92 e7 3f 
3d 0d c4 ab 83 db fc da 87 b9 60 92 39 71 74 5e 
46 dd 23 18 87 04 1c ee c7 14 1c bd d1 13 33 c0 
16 09 07 0d 87 b7 04 38 3b ca e4 7a 84 12 fe 64 
db 3b 4c ba b1 99 27 19 55 91 c8 9e eb 44 a6 64 
4f a3 49 24 31 ef 49 fe 12 d7 44 8f 5e f9 d6 57 
53 fe d9 d9 4a f7 15 e6 7c 36 6e 36 17 9c 9e 37 
21 fb 64 24 9c 63 f1 6c e9 8c b0 3d 6b 40 a5 5c 
44 6b c9 68 4f 52 f9 b7 b1 d0 63 03 7b ef 72 5d 
6b d1 c1 90 a2 30 8d c1 af d2 48 b8 fa ed 78 3f 
fd 71 6f 4a 9c 84 12 26 3b c1 98 c0 a8 79 79 a8 
e9 8a 5d ac f4 18 9e 63 95 a0 43 ac da 75 4d c3 
f8 2b 3c d8 cf b9 12 bd d5 53 cf 47 a4 9f 6d 23 
d5 4d ae 3b 8a 3d f2 87 2b 1f 22 12 a9 88 63 e5 
b0 4b f6 2c ef 4a ee 5f 7f fb 55 90 69 d0 ec d1 
b7 00 4f 30 0b aa 2b 73 a2 32 5d d2 e3 f1 5d bf 
d5 ea d3 f6 bd ab f9 f7 84 15 1c 05 f4 15 e5 b8 
03 7c 21 ca 35 be 22 bf b5 da f2 03 d6 63 ec fc 
78 f4 32 a6 c1 e0 99 26 11 51 c1 ec 5f 36 35 90 
9a e2 a6 bc 0e cb f3 af be b6 d4 ee ac ff 92 61 
4f 53 e9 bd 47 a7 b7 3a c2 32 6f 33 d7 76 6e 40 
27 f7 bc 49 4c f1 ce bb 6d 5f dd 97 24 7a fa 47 
77 60 be 94 9d 3a 5a 12 88 fc b0 27 18 36 25 14 
d7 e7 04 6e af 8e 86 97 a7 51 b6 f9 e4 ea 80 d1 
bd 05 96 6d 02 52 13 fb a8 21 e5 43 00 e8 8c a7 
7f c6 ba f8 a8 2a 66 7f 38 a0 52 98 95 8c 71 25 
9b e8 25 9b a4 e1 4d f8 d7 09 fb b7 f3 4f 04 74 
da aa e2 e7 24 8e d6 07 a5 54 25 dd d4 31 82 01 
d7 30 82 01 d3 02 01 01 30 51 30 4c 31 0b 30 09 
06 03 55 04 06 13 02 55 53 31 10 30 0e 06 03 55 
04 0a 13 07 73 63 65 70 2d 63 61 31 10 30 0e 06 
03 55 04 0b 13 07 53 43 45 50 20 43 41 31 19 30 
17 06 03 55 04 03 13 10 4d 49 43 52 4f 4d 44 4d 
20 53 43 45 50 20 43 41 02 01 10 30 09 06 05 2b 
0e 03 02 1a 05 00 a0 5d 30 18 06 09 2a 86 48 86 
f7 0d 01 09 03 31 0b 06 09 2a 86 48 86 f7 0d 01 
07 01 30 1c 06 09 2a 86 48 86 f7 0d 01 09 05 31 
0f 17 0d 32 32 31 31 32 39 31 35 34 34 33 31 5a 
30 23 06 09 2a 86 48 86 f7 0d 01 09 04 31 16 04 
14 92 04 58 96 9e b3 01 02 d8 01 65 5a 93 5d 3c 
ed 78 a1 4b c7 30 0d 06 09 2a 86 48 86 f7 0d 01 
01 05 05 00 04 82 01 00 3f 18 aa 88 30 ed c9 79 
64 f7 2e 0c d0 67 c8 ba 7f 3f 40 fd 6a 4c 18 11 
9e dd 28 be de 1a b6 3c 03 00 50 dc ed a9 c0 32 
ec 4e d7 c6 77 21 1e a6 f8 4a 3c 71 02 62 82 e6 
e0 a3 63 98 47 a8 11 d7 5a 5f 6d 96 a3 64 da 9f 
bf 96 94 03 08 bc b6 3c 48 22 8d 5d 8e f5 2d 25 
81 ab 73 92 4b f3 c3 62 44 46 ac 7c 97 ec b3 0e 
b3 35 9f 11 59 8c 58 d3 0e 92 2f df 4e 18 7b ee 
76 98 e6 45 23 6b 6e 49 d3 cf 10 db bb 86 d5 9a 
33 e5 ef 40 a3 d5 df ce 12 31 d0 a0 d4 77 90 67 
71 d3 19 7c 35 3b 03 9b 46 25 bc 06 f3 a0 f5 79 
ee 55 04 b2 1a b8 71 15 af 5a 63 54 b5 02 ac c4 
58 26 70 f9 cf 93 21 14 e1 0a c9 a6 74 94 29 14 
03 fb d3 32 3d f8 e9 ae ee f6 90 56 6f 5d 82 ed 
1c 72 82 ff 8d 43 8b d7 27 8f 55 3d 0d 67 b0 47 
d4 c8 ae a1 f1 c1 aa 44 9c c1 3f 31 57 ec 97 52 
1a 43 00 53 7b 05 f3 d1 00 00 00 00 00 00"
);
