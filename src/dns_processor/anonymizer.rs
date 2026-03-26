/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

// The community edition uses a fixed PBKDF2 salt on purpose so that the same passphrase yields the
// same deterministic pseudonymization output across runs and hosts. The passphrase remains the
// operator-controlled secret; rotating it rotates all derived pseudonyms.
static SALT: [u8; 32] = [
    199, 76, 160, 70, 220, 85, 167, 75, 67, 93, 117, 51, 223, 17, 109, 52, 125, 192, 43, 44, 172,
    36, 193, 95, 137, 81, 216, 92, 201, 141, 252, 241,
];

pub(super) struct Anonymizer {
    cipher: Option<Aes256>,
}

impl Anonymizer {
    pub(super) fn new(anonymize_key_path: Option<&Path>) -> io::Result<Self> {
        let cipher = match anonymize_key_path {
            Some(path) => {
                let passphrase = Self::read_key_from_file(path)?;
                Some(Self::derive_cipher(&passphrase)?)
            }
            None => None,
        };

        Ok(Self { cipher })
    }

    pub(super) fn anonymize_ip(&self, ip: &IpAddr) -> IpAddr {
        let Some(cipher) = &self.cipher else {
            return *ip;
        };

        match ip {
            IpAddr::V4(ipv4) => IpAddr::V4(Self::encrypt_ipv4(cipher, ipv4)),
            IpAddr::V6(ipv6) => IpAddr::V6(Self::encrypt_ipv6(cipher, ipv6)),
        }
    }

    fn read_key_from_file(path: &Path) -> Result<Box<str>, io::Error> {
        let mut file = fs::File::open(path)?;
        let mut passphrase = String::new();
        file.read_to_string(&mut passphrase)?;
        Ok(passphrase.trim().into())
    }

    fn derive_cipher(passphrase: &str) -> Result<Aes256, io::Error> {
        let key = Self::derive_key_from_passphrase(passphrase, &SALT)?;
        Ok(Aes256::new((&key).into()))
    }

    fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], io::Error> {
        let mut key = [0u8; 32];
        let iterations = 100_000;

        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
        Ok(key)
    }

    fn encrypt_ipv4(cipher: &Aes256, ipv4: &Ipv4Addr) -> Ipv4Addr {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&ipv4.octets());

        let mut encrypted_block = Block::<Aes256>::default();
        encrypted_block.copy_from_slice(&block);
        cipher.encrypt_block(&mut encrypted_block);

        Ipv4Addr::new(
            encrypted_block[0],
            encrypted_block[1],
            encrypted_block[2],
            encrypted_block[3],
        )
    }

    fn encrypt_ipv6(cipher: &Aes256, ipv6: &Ipv6Addr) -> Ipv6Addr {
        let mut block = Block::<Aes256>::default();
        block.copy_from_slice(&ipv6.octets());
        cipher.encrypt_block(&mut block);

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&block);
        Ipv6Addr::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Anonymizer;
    use std::fs;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_key_file(contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time is valid")
            .as_nanos();
        path.push(format!("dpp-anonymizer-{unique}.key"));
        fs::write(&path, contents).expect("writes temp key file");
        path
    }

    #[test]
    fn empty_key_path_leaves_ip_unchanged() {
        let anonymizer = Anonymizer::new(None).expect("anonymizer initializes without key");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(anonymizer.anonymize_ip(&ip), ip);
    }

    #[test]
    fn key_file_produces_deterministic_pseudonymization() {
        let key_path = temp_key_file("secret-passphrase\n");
        let anonymizer =
            Anonymizer::new(Some(key_path.as_path())).expect("anonymizer initializes with key");
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let first = anonymizer.anonymize_ip(&ip);
        let second = anonymizer.anonymize_ip(&ip);

        assert_eq!(first, second);
        assert_ne!(first, ip);

        fs::remove_file(key_path).expect("removes temp key file");
    }

    #[test]
    fn missing_key_file_is_an_error() {
        let mut path = std::env::temp_dir();
        path.push("dpp-anonymizer-missing.key");

        let error = Anonymizer::new(Some(path.as_path()))
            .err()
            .expect("missing key file must fail");

        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
}
