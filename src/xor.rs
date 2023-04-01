use std::cmp::{self, Reverse};
use std::fmt::Display;
use std::iter::Cycle;
use std::path::Path;
use std::fs;
use std::io;
use std::convert::From;
use std::str;
use std::collections::BinaryHeap;

use serde::{Serialize, Deserialize};

use crate::common;


pub fn fixed_xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), y.len());

    (0..x.len())
        .map(|i| x[i] ^ y[i])
        .collect()
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

        common::apply_to_files(src, &mut |file| {
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
        let max_keysize = cmp::min(Self::MAX_KEYSIZE, ciphertext.len() / Self::BLOCKS_TO_EVALUATE);
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
    fn test_fixed_xor() {
        let s1 = common::hex_decode("1c0111001f010100061a024b53535009181c").unwrap();
        let s2 = common::hex_decode("686974207468652062756c6c277320657965").unwrap();

        let expected_bytes = common::hex_decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(expected_bytes, fixed_xor(&s1, &s2));
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

        let ciphertext = common::hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
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
            let line = common::hex_decode(&line).unwrap();
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
        let expected_ciphertext = common::hex_decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
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
        let ciphertext = common::base64_decode(ciphertext.as_bytes());

        let plaintext = decryptor.decrypt(&ciphertext);
        assert!(String::from_utf8(plaintext).unwrap().is_ascii());
    }
}

