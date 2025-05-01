//! Base64 test vectors.

/// Padded Base64-encoded example
pub(crate) const PADDED_BASE64: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";
pub(crate) const PADDED_BIN: &[u8] = &[
    0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53,
    54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115, 12,
    229, 52, 87, 190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99, 172, 101,
    111, 221, 69, 33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45, 6, 173,
    21, 166, 106, 66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71,
];

/// Unpadded Base64-encoded example
pub(crate) const UNPADDED_BASE64: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
pub(crate) const UNPADDED_BIN: &[u8] = &[
    0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174, 243,
    126, 162, 223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62,
    209, 67, 39, 245, 197, 74, 171, 98,
];

/// Padded multi-line Base64 example (from the `ssh-key` crate's `id_ed25519`)
pub(crate) const MULTILINE_PADDED_BASE64: &str =
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
         QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
         XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
         AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
         ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==";
pub(crate) const MULTILINE_PADDED_BIN: &[u8] = &[
    111, 112, 101, 110, 115, 115, 104, 45, 107, 101, 121, 45, 118, 49, 0, 0, 0, 0, 4, 110, 111,
    110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 51, 0, 0, 0, 11,
    115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174, 243, 126, 162, 223,
    124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62, 209, 67, 39, 245,
    197, 74, 171, 98, 0, 0, 0, 152, 0, 32, 12, 93, 0, 32, 12, 93, 0, 0, 0, 11, 115, 115, 104, 45,
    101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174, 243, 126, 162, 223, 124, 170, 1, 13,
    239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62, 209, 67, 39, 245, 197, 74, 171, 98,
    0, 0, 0, 64, 182, 6, 194, 34, 209, 12, 22, 218, 225, 108, 112, 164, 212, 81, 115, 71, 46, 198,
    23, 224, 92, 101, 105, 32, 210, 110, 86, 192, 143, 181, 145, 237, 179, 62, 174, 243, 126, 162,
    223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62, 209, 67, 39,
    245, 197, 74, 171, 98, 0, 0, 0, 16, 117, 115, 101, 114, 64, 101, 120, 97, 109, 112, 108, 101,
    46, 99, 111, 109, 1, 2, 3, 4, 5,
];

/// Unpadded multi-line Base64 example (from the `ssh-key` crate's `id_ecdsa_p256`).
pub(crate) const MULTILINE_UNPADDED_BASE64: &str =
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n\
         1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR8H9hzDOU0V76NkkCY7DZIgw+Sqooj\n\
         Y6xlb91FIfpjE+UR8YkbTp5ar44ULQatFaZqQlfz8FHYTooOL5G6gHBHAAAAsB8RBhUfEQ\n\
         YVAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2S\n\
         QJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcE\n\
         cAAAAhAMp4pkd0v643EjIkk38DmJYBiXB6ygqGRc60NZxCO6B5AAAAEHVzZXJAZXhhbXBs\n\
         ZS5jb20BAgMEBQYH";

pub(crate) const MULTILINE_UNPADDED_BIN: &[u8] = &[
    111, 112, 101, 110, 115, 115, 104, 45, 107, 101, 121, 45, 118, 49, 0, 0, 0, 0, 4, 110, 111,
    110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 104, 0, 0, 0, 19,
    101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0,
    8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115, 12, 229, 52, 87,
    190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99, 172, 101, 111, 221, 69,
    33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45, 6, 173, 21, 166, 106,
    66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71, 0, 0, 0, 176, 31, 17, 6,
    21, 31, 17, 6, 21, 0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115,
    116, 112, 50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31,
    216, 115, 12, 229, 52, 87, 190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99,
    172, 101, 111, 221, 69, 33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45,
    6, 173, 21, 166, 106, 66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71, 0, 0,
    0, 33, 0, 202, 120, 166, 71, 116, 191, 174, 55, 18, 50, 36, 147, 127, 3, 152, 150, 1, 137, 112,
    122, 202, 10, 134, 69, 206, 180, 53, 156, 66, 59, 160, 121, 0, 0, 0, 16, 117, 115, 101, 114,
    64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 1, 2, 3, 4, 5, 6, 7,
];

pub(crate) const MULTILINE_UNPADDED_BASE64_ISSUE1609: &str =
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDctrRCQ6LEyzTbsXkAQ8mhdIOQZzP/XKcuplituD2PaQAAAKC+1uNjvtbj\n\
YwAAAAtzc2gtZWQyNTUxOQAAACDctrRCQ6LEyzTbsXkAQ8mhdIOQZzP/XKcuplituD2PaQ\n\
AAAEAyjynmk0ex/GrImDlAEN81gXGK4tWaq36kO+HRp8szLNy2tEJDosTLNNuxeQBDyaF0\n\
g5BnM/9cpy6mWK24PY9pAAAAFEdlbmVyYXRlZCBCeSBUZXJtaXVzAQIDBAUGBwgJ";

pub(crate) const MULTILINE_UNPADDED_BIN_ISSUE1609: &[u8] = &[
    0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x31, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x6e, 0x6f, 0x6e, 0x65, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x6f, 0x6e, 0x65, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x0b, 0x73,
    0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xdc, 0xb6,
    0xb4, 0x42, 0x43, 0xa2, 0xc4, 0xcb, 0x34, 0xdb, 0xb1, 0x79, 0x00, 0x43, 0xc9, 0xa1, 0x74, 0x83,
    0x90, 0x67, 0x33, 0xff, 0x5c, 0xa7, 0x2e, 0xa6, 0x58, 0xad, 0xb8, 0x3d, 0x8f, 0x69, 0x00, 0x00,
    0x00, 0xa0, 0xbe, 0xd6, 0xe3, 0x63, 0xbe, 0xd6, 0xe3, 0x63, 0x00, 0x00, 0x00, 0x0b, 0x73, 0x73,
    0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xdc, 0xb6, 0xb4,
    0x42, 0x43, 0xa2, 0xc4, 0xcb, 0x34, 0xdb, 0xb1, 0x79, 0x00, 0x43, 0xc9, 0xa1, 0x74, 0x83, 0x90,
    0x67, 0x33, 0xff, 0x5c, 0xa7, 0x2e, 0xa6, 0x58, 0xad, 0xb8, 0x3d, 0x8f, 0x69, 0x00, 0x00, 0x00,
    0x40, 0x32, 0x8f, 0x29, 0xe6, 0x93, 0x47, 0xb1, 0xfc, 0x6a, 0xc8, 0x98, 0x39, 0x40, 0x10, 0xdf,
    0x35, 0x81, 0x71, 0x8a, 0xe2, 0xd5, 0x9a, 0xab, 0x7e, 0xa4, 0x3b, 0xe1, 0xd1, 0xa7, 0xcb, 0x33,
    0x2c, 0xdc, 0xb6, 0xb4, 0x42, 0x43, 0xa2, 0xc4, 0xcb, 0x34, 0xdb, 0xb1, 0x79, 0x00, 0x43, 0xc9,
    0xa1, 0x74, 0x83, 0x90, 0x67, 0x33, 0xff, 0x5c, 0xa7, 0x2e, 0xa6, 0x58, 0xad, 0xb8, 0x3d, 0x8f,
    0x69, 0x00, 0x00, 0x00, 0x14, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x42,
    0x79, 0x20, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x75, 0x73, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09,
];
