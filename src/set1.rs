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
            buffer[1..bytes.len()+1].copy_from_slice(bytes);
            if bytes.len() < 3 {
                buffer[bytes.len()+1..].fill('=' as u8);
            }
            let mut uint = u32::from_be_bytes(buffer);

            (0..4).map(move |_| {
                    let byte = ((uint >> 18) & 0x3f) as u8;
                    uint = uint << 6;
        
                    match byte {
                        0..=25 => 'A' as u8 + byte,
                        26..=51 => 'a' as u8 + byte - 26,
                        52..=61 => '0' as u8 + byte - 52,
                        62 => '+' as u8,
                        63 => '/' as u8,
                        _ => panic!("invalid byte value {}", byte)
                    }
                })
        }).collect()
}

pub fn base64_decode(data: &[u8]) ->Vec<u8> {
    todo!()
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
    fn test_base64_decode() {
        let base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let expected_hex_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    
        let hex_string = base64_decode(base64_string.as_bytes());
        let hex_string = hex_encode(&hex_string[..]);

        assert_eq!(expected_hex_string, hex_string);
    }
}

