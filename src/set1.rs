use std::cmp::{min, Reverse};
use std::fmt::{Write, Display};
use std::iter::Cycle;
use std::num::ParseIntError;
use std::path::Path;
use std::fs;
use std::io;
use std::convert::From;
use std::str;
use std::collections::BinaryHeap;

use serde::{Serialize, Deserialize};

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
            let bytes = &data[i..min(i+3, data.len())];
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

pub struct DecryptSingleByteXorResult {
    pub plaintext: Vec<u8>,
    pub byte: u8,
    pub err: f32,
}

impl DecryptSingleByteXorResult {
    pub fn new() -> DecryptSingleByteXorResult {
        DecryptSingleByteXorResult {
            plaintext: Vec::new(),
            byte: 0u8,
            err: f32::INFINITY,
        }
    }

    pub fn update(&mut self, plaintext: Vec<u8>, byte: u8, err: f32) {
        self.plaintext = plaintext;
        self.byte = byte;
        self.err = err;
    }
}

#[derive(Serialize, Deserialize)]
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

    pub fn decrypt_single_byte_xor(&self, ciphertext: &[u8]) -> DecryptSingleByteXorResult {
        let mut result = DecryptSingleByteXorResult::new();

        for byte in 0u8..=255 {
            let bytes_vec= vec![byte; ciphertext.len()];
            let plaintext = fixed_xor(ciphertext, &bytes_vec);
    
            if let Ok(plaintext) = String::from_utf8(plaintext) {
                let plaintext_table = FrequencyTable::from(plaintext.as_str());
                let mae = self.mean_absolute_error(&plaintext_table);

                if mae < result.err {
                    result.update(plaintext.into_bytes(), byte, mae);
                }
            }
        }

        result
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

pub struct XORerRepeatingKey(Cycle<std::vec::IntoIter<u8>>);

impl XORerRepeatingKey {
    pub fn new(key: Vec<u8>) -> XORerRepeatingKey {
        Self(key.into_iter().cycle())
    }

    pub fn xor(&mut self, src: &[u8]) -> Vec<u8> {
        src.iter()
            .map(|&byte| byte ^ self.0.next().unwrap())
            .collect()
    }
}

pub fn edit_distance(x: &[u8], y: &[u8]) -> u32 {
    fixed_xor(x, y)
        .into_iter()
        .fold(0u32, |acc, byte| acc + byte.count_ones())
}

pub struct DecryptorXorRepeatingKey(FrequencyTable);

impl DecryptorXorRepeatingKey {
    const MAX_KEYSIZE: usize = 40;
    const BLOCKS_TO_EVALUATE: usize = 4;
    const NUMBER_OF_KEYSIZES: usize = 3;
    const PRECISION_MULTIPLIER: f32 = 1000f32;
    
    pub fn new(frequency_table: FrequencyTable) -> DecryptorXorRepeatingKey {
        Self(frequency_table)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut best_err = f32::INFINITY;
        let mut best_plaintext = Vec::new();

        let keysizes = Self::find_keysizes(ciphertext);

        for keysize in keysizes.into_iter().filter(|&keysize| keysize > 0) {
            let ciphertext_blocks = Self::build_ciphertext_blocks(ciphertext, keysize);

            let key: Vec<_> = ciphertext_blocks 
                .into_iter()
                .map(|ciphertext| self.0.decrypt_single_byte_xor(&ciphertext).byte)
                .collect();

            let plaintext_bytes = XORerRepeatingKey::new(key).xor(ciphertext);
            if let Ok(plaintext) = str::from_utf8(&plaintext_bytes) {
                let plaintext_table = FrequencyTable::from(plaintext);
                let err = self.0.mean_absolute_error(&plaintext_table);

                if err < best_err {
                    best_err = err;
                    best_plaintext = plaintext_bytes;
                }
            }
        }

        best_plaintext
    }

    fn find_keysizes(ciphertext: &[u8]) -> [usize; Self::NUMBER_OF_KEYSIZES] {
        let max_keysize = min(Self::MAX_KEYSIZE, ciphertext.len() / Self::BLOCKS_TO_EVALUATE);
        let mut heap = BinaryHeap::with_capacity(max_keysize - 1);

        for keysize in 2..=max_keysize {
            let edit_distance_sum = ciphertext
                .chunks(keysize)
                .take(Self::BLOCKS_TO_EVALUATE)
                .collect::<Vec<&[u8]>>()
                .windows(2)
                .fold(0u32, |acc, chunks| {
                    acc + edit_distance(chunks[0], chunks[1])
                });
                
            let mut edit_distance_sum = edit_distance_sum as f32 / keysize as f32;
            edit_distance_sum /= (Self::BLOCKS_TO_EVALUATE - 1) as f32;
            let edit_distance_sum = (edit_distance_sum * Self::PRECISION_MULTIPLIER) as u32;

            heap.push((Reverse(edit_distance_sum), Reverse(keysize)));
        }

        let mut keysizes = [0; Self::NUMBER_OF_KEYSIZES];
        for i in 0..keysizes.len() {
            if let Some((_, Reverse(keysize))) = heap.pop() {
                keysizes[i] = keysize;
            } else {
                break
            }
        }

        keysizes
    }

    fn build_ciphertext_blocks(ciphertext: &[u8], keysize: usize) -> Vec<Vec<u8>> {
        let mut blocks = vec![vec![0u8; ciphertext.len() / keysize]; keysize];
            
        for (i, chunk) in ciphertext.chunks_exact(keysize).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                blocks[j][i] = byte;
            }
        }

        blocks
    }

}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::{BufReader, BufRead};

    use super::*;

    const FREQUENCY_TABLE_PATH: &str = "./data/frequency_table.bin";

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
    fn test_fixed_xor() {
        let s1 = hex_decode("1c0111001f010100061a024b53535009181c").unwrap();
        let s2 = hex_decode("686974207468652062756c6c277320657965").unwrap();

        let expected_bytes = hex_decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(expected_bytes, fixed_xor(&s1, &s2));
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

    #[test]
    fn test_decrypt_single_byte_xor() {
        let table_bytes= fs::read(FREQUENCY_TABLE_PATH).unwrap();
        let table: FrequencyTable = bincode::deserialize(&table_bytes).unwrap();

        let ciphertext = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let result = table.decrypt_single_byte_xor(&ciphertext);
        let plaintext = str::from_utf8(&result.plaintext).unwrap();

        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
    }

    #[test]
    fn test_decrypt_single_byte_xor_from_file() {
        let table_bytes = fs::read(FREQUENCY_TABLE_PATH).unwrap();
        let table: FrequencyTable = bincode::deserialize(&table_bytes).unwrap();

        let mut best_err = f32::INFINITY;
        let mut best_plaintext = Vec::new();

        let file = File::open("./data/set1_challenge4.txt").unwrap();
    
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            let line = hex_decode(&line).unwrap();
            let result = table.decrypt_single_byte_xor(&line);

            if result.err < best_err {
                best_plaintext = result.plaintext;
                best_err = result.err;
            }
        }

        assert_eq!("nOW\0THAT\0THE\0PARTY\0IS\0JUMPING*", str::from_utf8(&best_plaintext).unwrap());
    }

    #[test]
    fn test_encrypt_xor_repeating_key() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\n\
                               I go crazy when I hear a cymbal";

        let key = "ICE".as_bytes().to_owned();
        let mut encryptor = XORerRepeatingKey::new(key);

        let ciphertext = encryptor.xor(plaintext.as_bytes());
        let expected_ciphertext = hex_decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                                                       a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

        assert_eq!(expected_ciphertext, ciphertext);
    }

    #[test]
    fn test_edit_distance() {
        let x = "this is a test".as_bytes();
        let y = "wokka wokka!!!".as_bytes();

        assert_eq!(37, edit_distance(x, y));
    }

    #[test]
    fn test_decrypt_xor_repeating_key() {
        let table_bytes = fs::read(FREQUENCY_TABLE_PATH).unwrap();
        let table: FrequencyTable = bincode::deserialize(&table_bytes).unwrap();
        let decryptor = DecryptorXorRepeatingKey::new(table);

        let ciphertext = fs::read_to_string("./data/set1_challenge6.txt").unwrap().replace("\n", "");
        let ciphertext = base64_decode(ciphertext.as_bytes());

        let plaintext = decryptor.decrypt(&ciphertext);
        assert!(String::from_utf8(plaintext).unwrap().is_ascii());
    }
}

