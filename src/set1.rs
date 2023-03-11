use std::cmp::min;
use std::fmt::{Write, Display};
use std::num::ParseIntError;
use std::path::Path;
use std::fs;
use std::io;
use std::convert::From;
use std::str;

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
    let mut result = Vec::with_capacity(data.len() / 4 * 3);

    for i in (0..data.len()).step_by(4) {
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
        result.extend_from_slice(&bytes[1..]);
    }

    result.truncate(result.len() - skip_bytes);
    result
}

pub fn fixed_xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), y.len());

    (0..x.len())
        .map(|i| x[i] ^ y[i])
        .collect()
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

pub struct FrequencyTable {
    letter_counts: [u32; 26],
    total_letters: u64,
}

impl FrequencyTable {
    pub fn new() -> FrequencyTable {
        FrequencyTable {
            letter_counts: [0; 26],
            total_letters: 0
        }
    }

    pub fn get_freq(&self, c: char) -> Option<f32> {
        let idx = Self::char_to_idx(c)?;
        Some((self.letter_counts[idx] as f32 / self.total_letters as f32) * 100f32)
    }

    pub fn update(&mut self, c: char) {
        if let Some(idx) = Self::char_to_idx(c) {
            self.letter_counts[idx] += 1;
            self.total_letters += 1;
        }
    }

    pub fn mean_absolute_error(&self, other: &FrequencyTable) -> f32 {
        let sum_absolute_error = ('a'..='z')
            .fold(0f32, |acc, c| {
                acc + (self.get_freq(c).unwrap() - other.get_freq(c).unwrap()).abs()
            });

        sum_absolute_error / 26f32
    }

    pub fn decrypt_single_byte_xor(&self, data: &[u8]) -> Vec<u8> {
        let mut best_score = f32::INFINITY;
        let mut best_plaintext = String::new();

        for byte in 0u8..=255 {
            let bytes_vec= vec![byte; data.len()];
            let plaintext = fixed_xor(data, &bytes_vec[..]);
    
            if let Ok(plaintext) = String::from_utf8(plaintext) {
                let plaintext_table = FrequencyTable::from(&plaintext[..]);
                let mae = self.mean_absolute_error(&plaintext_table);

                if mae < best_score {
                    best_score = mae;
                    best_plaintext = plaintext;

                }
            }
        }
        best_plaintext.into_bytes()
    }

    fn char_to_idx(c: char) -> Option<usize> {
        let c = c as u8;
        let idx = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c.to_ascii_lowercase() - b'a',
            _ => return None,
        };

        Some(idx as usize)
    }
}

impl From<&str> for FrequencyTable {
    fn from(s: &str) -> Self {
        let mut table = FrequencyTable::new();

        for c in s.chars() {
            table.update(c)
        }    
        table
    }
}

// can't be replaced with a generic: https://github.com/rust-lang/rust/issues/50133#issuecomment-64690839
impl TryFrom<&Path> for FrequencyTable {
    type Error = io::Error;

    fn try_from(src: &Path) -> Result<Self, Self::Error> {
        let mut table = FrequencyTable::new();

        apply_to_files(src, &mut |file| {
            for c in fs::read_to_string(file)?.chars() {
                table.update(c)
            }

            Ok(())
        })?;

        Ok(table)     
    }
}

impl Display for FrequencyTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "FrequencyTable (total number of processed letters: {}): {{", self.total_letters)?;
        for c in 'a'..='z' {
            writeln!(f, "  {}: {}", c, self.get_freq(c).unwrap())?;
        }
        writeln!(f, "}}")
    }
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

        assert_eq!(expected_base64_string, base64_string);
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

    #[test]
    fn test_fixed_xor() {
        let s1 = hex_decode("1c0111001f010100061a024b53535009181c").unwrap();
        let s2 = hex_decode("686974207468652062756c6c277320657965").unwrap();

        let expected_bytes = hex_decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(expected_bytes, fixed_xor(&s1[..], &s2[..]));
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

    fn assert_frequency_table(table: &FrequencyTable) {
        assert_eq!(5f32 / 12f32 * 100f32, table.get_freq('a').unwrap());
        assert_eq!(5f32 / 12f32 * 100f32, table.get_freq('A').unwrap());
        assert_eq!(3f32 / 12f32 * 100f32, table.get_freq('b').unwrap());
        assert_eq!(3f32 / 12f32 * 100f32, table.get_freq('B').unwrap());
        assert_eq!(4f32 / 12f32 * 100f32, table.get_freq('c').unwrap());
        assert_eq!(4f32 / 12f32 * 100f32, table.get_freq('c').unwrap());
    
        assert!(table.get_freq('0').is_none());
        assert!(table.get_freq('+').is_none()); 
        assert!(table.get_freq(' ').is_none());
        assert!(table.get_freq('\n').is_none());
    }

    #[test]
   fn test_frequency_table_from_str() {
        let table = FrequencyTable::from("aAa* aAbb+ BcC Cc/=");
        assert_frequency_table(&table);
    }

    #[test]
    fn test_frequency_table_from_dir() {
        let dir = PathBuf::from("./test");
        fs::create_dir(&dir).unwrap();

        let file_path = dir.join("test.txt");
        fs::write(file_path, "aAa* aAbb+ BcC Cc/=").unwrap();

        let table = FrequencyTable::try_from(dir.as_path()).unwrap();
    
        assert_frequency_table(&table);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_frequency_table_mae() {
        let table1 = FrequencyTable::from("aaaabbb");
        let table2 = FrequencyTable::from("bbccc");

        let mut expected_mae = (4f32 / 7f32).abs() +
                                (3f32 / 7f32 - 2f32 / 5f32).abs() +
                                (3f32 / 5f32).abs();
        expected_mae = expected_mae * 100f32 / 26f32; 

        assert_eq!(expected_mae, table1.mean_absolute_error(&table2));
    }

    #[ignore]
    #[test]
    fn test_decrypt_single_byte_xor() {
        let path = Path::new(".ascii_text_archive");
        let table = FrequencyTable::try_from(path).unwrap();

        let ciphertext = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let plaintext = table.decrypt_single_byte_xor(&ciphertext[..]);
        let plaintext = str::from_utf8(&plaintext[..]).unwrap();

        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
    }
}

