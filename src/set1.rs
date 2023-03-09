use std::cmp::min;
use std::fmt::Write;
use std::num::ParseIntError;

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len()*2);

    for &b in bytes{
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16))
        .collect()
}

pub fn base64_encode(data: &[u8]) -> Vec<u8> {
    (0..data.len())
        .step_by(3)
        .flat_map(|i| {
            let mut buffer = [0u8; 4];
            let bytes = &data[i..min(i+3, data.len())];
            buffer[1..=bytes.len()].copy_from_slice(bytes);
            let mut uint = u32::from_be_bytes(buffer);

            (0..=bytes.len())
                .map(move |_| {
                    let byte = ((uint >> 18) & 0x3f) as u8;
                    uint = uint << 6;
        
                    match byte {
                        0..=25 => b'A' + byte,
                        26..=51 => b'a' + byte - 26,
                        52..=61 => b'0' + byte - 52,
                        62 => b'+',
                        63 => b'/',
                        _ => panic!("invalid byte value {}", byte)
                    }
                })
                .chain((0..3-bytes.len()).map(|_| b'='))
        })
        .collect()
}

pub fn base64_decode(data: &[u8]) ->Vec<u8> {
    let mut skip_bytes = 0;

    let mut result: Vec<u8> = (0..data.len())
        .step_by(4)
        .flat_map(|i| {
            let uint = (0..4).fold(0u32, |acc, j| {
                let byte = match data[i+j] {
                    byte @ b'A'..=b'Z' => byte - b'A',
                    byte @ b'a'..=b'z' => byte - b'a' + 26,
                    byte @ b'0'..=b'9' => byte - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => {
                        skip_bytes += 1;
                        0
                    },
                    byte => panic!("invalid base64 byte value {}", byte),
                };

                acc | ((byte as u32) << 6 * (3 - j))
            });

            let bytes = u32::to_be_bytes(uint);
            let mut buffer = [0u8; 3];
            buffer.copy_from_slice(&bytes[1..]);
            buffer
        })
        .collect();

    result.truncate(result.len() - skip_bytes);
    result
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hex_encode() {
        let bytes = [73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];
        let expected_hex_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        
        assert_eq!(expected_hex_string, hex_encode(&bytes[..]));
    }

    #[test]
    fn test_hex_decode() {
        let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_bytes = vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];

        assert_eq!(expected_bytes, hex_decode(hex_string).unwrap());
    }

    #[test]
    fn test_base64_encode() {
        let bytes = hex_decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        let expected_base64_string = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    
        let base64_string = base64_encode(&bytes[..]);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(base64_string, expected_base64_string);
    }

    #[test]    
    fn test_base64_encode_with_padding() {
        let bytes = "Ma".as_bytes();
        let expected_base64_string = String::from("TWE=");
    
        let base64_string = base64_encode(&bytes[..]);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(expected_base64_string, base64_string);
    }

    #[test]    
    fn test_base64_encode_with_two_paddings() {
        let bytes = "M".as_bytes();
        let expected_base64_string = String::from("TQ==");
    
        let base64_string = base64_encode(&bytes[..]);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(expected_base64_string, base64_string);
    }



    #[test]
    fn test_base64_decode() {
        let base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let expected_hex_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    
        let hex_string = base64_decode(base64_string.as_bytes());
        let hex_string = hex_encode(&hex_string[..]);

        assert_eq!(expected_hex_string, hex_string);
    }

    #[test]
    fn test_base64_decode_with_padding() {
        let base64_string = "TWE=";
        let expected_string = "Ma".as_bytes();
    
        let string = base64_decode(base64_string.as_bytes());

        assert_eq!(expected_string, string);
    }

    #[test]
    fn test_base64_decode_with_two_paddings() {
        let base64_string = "TQ==";
        let expected_string = "M".as_bytes();
    
        let string = base64_decode(base64_string.as_bytes());

        assert_eq!(expected_string, string);
    }
}

