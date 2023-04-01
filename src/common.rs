use std::fmt::Write;
use std::num::ParseIntError;
use std::cmp;
use std::path::Path;
use std::io;
use std::fs;

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

fn plain_byte_to_base64(plain_byte: u8) -> u8 {
    match plain_byte {
        0..=25 => b'A' + plain_byte,
        26..=51 => b'a' + plain_byte - 26,
        52..=61 => b'0' + plain_byte - 52,
        62 => b'+',
        63 => b'/',
        _ => panic!("invalid byte value {}", plain_byte)
    }
}

pub fn base64_encode(data: &[u8]) -> Vec<u8> {
    (0..data.len())
        .step_by(3)
        .flat_map(|i| {
            let mut buffer = [0u8; 4];
            let bytes = &data[i..cmp::min(i+3, data.len())];
            buffer[1..=bytes.len()].copy_from_slice(bytes);
            let mut uint = u32::from_be_bytes(buffer);

            (0..=bytes.len())
                .map(move |_| {
                    let byte = ((uint >> 18) & 0x3f) as u8;
                    uint = uint << 6;
        
                    plain_byte_to_base64(byte)
                })
                .chain((0..3-bytes.len()).map(|_| b'='))
        })
        .collect()
}

fn base64_to_plain_byte(base64_byte: u8) -> (u8, bool) {
    let mut skip_byte = false;

    let plain_byte = match base64_byte {
        byte @ b'A'..=b'Z' => byte - b'A',
        byte @ b'a'..=b'z' => byte - b'a' + 26,
        byte @ b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        b'=' => {
            skip_byte = true;
            0
        },
        byte => panic!("invalid base64 byte value {}", byte),
    };

    (plain_byte, skip_byte)
}

pub fn base64_decode(data: &[u8]) ->Vec<u8> {
    let mut skip_bytes = 0;
    let mut result = Vec::with_capacity(data.len() / 4 * 3);

    for i in (0..data.len()).step_by(4) {
        let uint = (0..4).fold(0u32, |acc, j| {
            let (byte, skip) = base64_to_plain_byte(data[i+j]);
            if skip {
                skip_bytes += 1;
            }

            acc | ((byte as u32) << 6 * (3 - j))
        });

        let bytes = u32::to_be_bytes(uint);
        result.extend_from_slice(&bytes[1..]);
    }

    result.truncate(result.len() - skip_bytes);
    result
}

pub fn apply_to_files<P, F>(src: P, cb: &mut F) -> io::Result<()> 
where
    P: AsRef<Path>,
    F: FnMut(&Path) -> io::Result<()>,
{
    let src = src.as_ref();
    if src.is_dir() {
        for entry in fs::read_dir(src)? {
            let path = entry?.path();
            apply_to_files(&path, cb)?;
        }
        return Ok(())
    } 

    cb(src)
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_hex_encode() {
        let bytes = [73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];
        let expected_hex_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        
        assert_eq!(expected_hex_string, hex_encode(&bytes));
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
    
        let base64_string = base64_encode(&bytes);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(expected_base64_string, base64_string);
    }

    #[test]    
    fn test_base64_encode_with_padding() {
        let bytes = "Ma".as_bytes();
        let expected_base64_string = String::from("TWE=");
    
        let base64_string = base64_encode(&bytes);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(expected_base64_string, base64_string);
    }

    #[test]    
    fn test_base64_encode_with_two_paddings() {
        let bytes = "M".as_bytes();
        let expected_base64_string = String::from("TQ==");
    
        let base64_string = base64_encode(&bytes);
        let base64_string = String::from_utf8(base64_string).unwrap();

        assert_eq!(expected_base64_string, base64_string);
    }

    #[test]
    fn test_base64_decode() {
        let base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let expected_hex_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    
        let hex_string = base64_decode(base64_string.as_bytes());
        let hex_string = hex_encode(&hex_string);

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

    #[test]
    fn test_apply_to_files() {
        let first_dir = PathBuf::from("./test1");
        let second_dir = first_dir.join("test2");
        fs::create_dir_all(&second_dir).unwrap();

        let file1_path =  first_dir.join("test1.txt");
        File::create(&file1_path).unwrap();

        let file2_path = second_dir.join("test2.txt");
        File::create(&file2_path).unwrap();

        let mut files = Vec::new();
        apply_to_files(&first_dir, &mut |file| {
            let file = file.to_path_buf();
            Ok(files.push(file))
        }).unwrap();
        files.sort();

        fs::remove_dir_all(first_dir).unwrap();

        assert_eq!(vec![file1_path, file2_path], files);
    }
}