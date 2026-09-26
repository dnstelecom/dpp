/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use aes::Aes256;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

// Legacy text key files retain this salt so existing pseudonyms remain stable across runs and hosts.
static SALT: [u8; 32] = [
    199, 76, 160, 70, 220, 85, 167, 75, 67, 93, 117, 51, 223, 17, 109, 52, 125, 192, 43, 44, 172,
    36, 193, 95, 137, 81, 216, 92, 201, 141, 252, 241,
];
const SALTED_KEY_MAGIC: &[u8] = b"\x89DPP-ANON-KEY-v2\n";
const IPV4_FEISTEL_ROUNDS: u8 = 8;
const IPV4_KEY_LABEL: &[u8] = b"dpp-ipv4-feistel-v1";

struct AnonymizationCiphers {
    ipv4: Aes256,
    ipv6: Aes256,
}

pub(super) struct Anonymizer {
    ciphers: Option<AnonymizationCiphers>,
}

impl Anonymizer {
    pub(super) fn new(anonymize_key_path: Option<&Path>) -> io::Result<Self> {
        let ciphers = match anonymize_key_path {
            Some(path) => {
                let (passphrase, salt) = Self::read_key_from_file(path)?;
                Some(Self::derive_ciphers(&passphrase, &salt)?)
            }
            None => None,
        };

        Ok(Self { ciphers })
    }

    pub(super) fn anonymize_ip(&self, ip: &IpAddr) -> IpAddr {
        let Some(ciphers) = &self.ciphers else {
            return *ip;
        };

        match ip {
            IpAddr::V4(ipv4) => IpAddr::V4(Self::encrypt_ipv4(&ciphers.ipv4, ipv4)),
            IpAddr::V6(ipv6) => IpAddr::V6(Self::encrypt_ipv6(&ciphers.ipv6, ipv6)),
        }
    }

    fn read_key_from_file(path: &Path) -> io::Result<(Box<str>, [u8; 32])> {
        let contents = fs::read(path)?;
        let (passphrase, salt) = if let Some(body) = contents.strip_prefix(SALTED_KEY_MAGIC) {
            let salt_line_end = body.iter().position(|byte| *byte == b'\n').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "salted key file has no salt line",
                )
            })?;
            let salt_hex = &body[..salt_line_end];
            if salt_hex.len() != 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "salted key file must contain exactly 64 hexadecimal salt digits",
                ));
            }
            if !salt_hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid hexadecimal salt",
                ));
            }
            let mut salt = [0u8; 32];
            for (output, pair) in salt.iter_mut().zip(salt_hex.chunks_exact(2)) {
                let digits = std::str::from_utf8(pair).expect("ASCII hex digits checked");
                *output = u8::from_str_radix(digits, 16).expect("ASCII hex digits checked");
            }
            (
                std::str::from_utf8(&body[salt_line_end + 1..]).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "passphrase must be valid UTF-8")
                })?,
                salt,
            )
        } else {
            (
                std::str::from_utf8(&contents).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "passphrase must be valid UTF-8")
                })?,
                SALT,
            )
        };
        let passphrase = passphrase.trim();
        if passphrase.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "anonymization key file must contain a non-empty passphrase",
            ));
        }

        Ok((passphrase.into(), salt))
    }

    fn derive_ciphers(
        passphrase: &str,
        salt: &[u8; 32],
    ) -> Result<AnonymizationCiphers, io::Error> {
        // Keep the original key for IPv6 so existing IPv6 pseudonyms remain stable.
        let ipv6_key = Self::derive_key_from_passphrase(passphrase, salt)?;
        let mut ipv4_salt = salt.to_vec();
        ipv4_salt.extend_from_slice(IPV4_KEY_LABEL);
        let ipv4_key = Self::derive_key_from_passphrase(passphrase, &ipv4_salt)?;

        Ok(AnonymizationCiphers {
            ipv4: Aes256::new((&ipv4_key).into()),
            ipv6: Aes256::new((&ipv6_key).into()),
        })
    }

    fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], io::Error> {
        let mut key = [0u8; 32];
        let iterations = 100_000;

        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
        Ok(key)
    }

    fn encrypt_ipv4(cipher: &Aes256, ipv4: &Ipv4Addr) -> Ipv4Addr {
        let octets = ipv4.octets();
        let mut left = u16::from_be_bytes([octets[0], octets[1]]);
        let mut right = u16::from_be_bytes([octets[2], octets[3]]);

        // Each Feistel round is invertible regardless of collisions in its round function.
        for round in 0..IPV4_FEISTEL_ROUNDS {
            (left, right) = (right, left ^ Self::ipv4_round(cipher, round, right));
        }

        let mut output = [0u8; 4];
        output[..2].copy_from_slice(&left.to_be_bytes());
        output[2..].copy_from_slice(&right.to_be_bytes());
        Ipv4Addr::from(output)
    }

    fn ipv4_round(cipher: &Aes256, round: u8, right: u16) -> u16 {
        let mut block = Block::<Aes256>::default();
        block[..12].copy_from_slice(b"dpp-ipv4-v1:");
        block[12] = round;
        block[14..].copy_from_slice(&right.to_be_bytes());
        cipher.encrypt_block(&mut block);
        u16::from_be_bytes([block[0], block[1]])
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
    use super::{Anonymizer, SALT, SALTED_KEY_MAGIC};
    use std::collections::HashSet;
    use std::fs;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_key_file(contents: impl AsRef<[u8]>) -> PathBuf {
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
        assert_eq!(
            first,
            IpAddr::V6(Ipv6Addr::new(
                0x4733, 0xfbc0, 0xdf1c, 0xdc0e, 0x97e5, 0x4929, 0x9f74, 0x5421
            )),
            "existing IPv6 pseudonyms must remain stable"
        );
        assert_eq!(
            anonymizer.anonymize_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            IpAddr::V4(Ipv4Addr::new(54, 5, 4, 44)),
            "IPv4 pseudonyms must remain stable across runs and hosts"
        );

        fs::remove_file(key_path).expect("removes temp key file");
    }

    #[test]
    fn salted_key_changes_both_families_and_is_stable_across_reloads() {
        let legacy_path = temp_key_file("secret-passphrase\n");
        let mut salted_contents = SALTED_KEY_MAGIC.to_vec();
        salted_contents.extend_from_slice(
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\nsecret-passphrase\n",
        );
        let salted_path = temp_key_file(salted_contents);

        let legacy = Anonymizer::new(Some(&legacy_path)).expect("legacy key loads");
        let salted = Anonymizer::new(Some(&salted_path)).expect("salted key loads");
        let reloaded = Anonymizer::new(Some(&salted_path)).expect("salted key reloads");
        for ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert_ne!(salted.anonymize_ip(&ip), legacy.anonymize_ip(&ip));
            assert_eq!(salted.anonymize_ip(&ip), reloaded.anonymize_ip(&ip));
        }

        fs::remove_file(legacy_path).expect("removes legacy key file");
        fs::remove_file(salted_path).expect("removes salted key file");
    }

    #[test]
    fn malformed_salted_keys_are_rejected_without_legacy_fallback() {
        for body in [
            b"short\nsecret".as_slice(),
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeefg\nsecret",
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n  ",
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\xff",
        ] {
            let mut contents = SALTED_KEY_MAGIC.to_vec();
            contents.extend_from_slice(body);
            let key_path = temp_key_file(contents);
            let error = Anonymizer::new(Some(&key_path))
                .err()
                .expect("malformed salted key must fail");
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::InvalidInput
                ),
                "unexpected error: {error}"
            );
            fs::remove_file(key_path).expect("removes malformed key file");
        }

        let mut contents = SALTED_KEY_MAGIC.to_vec();
        let mut body =
            b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\nsecret".to_vec();
        body[0] = b'+';
        contents.extend_from_slice(&body);
        let key_path = temp_key_file(contents);
        assert_eq!(
            Anonymizer::new(Some(&key_path))
                .err()
                .expect("plus sign is not a hex digit")
                .kind(),
            ErrorKind::InvalidData
        );
        fs::remove_file(key_path).expect("removes malformed key file");
    }

    #[test]
    fn text_that_looks_like_a_key_header_remains_a_legacy_passphrase() {
        let passphrase = "DPP-ANON-KEY-v2\n00112233445566778899aabbccddeeff";
        let key_path = temp_key_file(passphrase);
        let (loaded, salt) = Anonymizer::read_key_from_file(&key_path).expect("legacy key loads");
        assert_eq!(&*loaded, passphrase);
        assert_eq!(salt, SALT);
        fs::remove_file(key_path).expect("removes legacy key file");
    }

    #[test]
    fn ipv4_pseudonyms_are_unique_for_distinct_addresses() {
        let ciphers = Anonymizer::derive_ciphers("secret", &SALT).expect("derives ciphers");
        let mut seen = HashSet::with_capacity(100_000);

        for address in 0..100_000u32 {
            let input = Ipv4Addr::from(address.to_be_bytes());
            let output = Anonymizer::encrypt_ipv4(&ciphers.ipv4, &input);
            assert!(seen.insert(output), "IPv4 collision for {input}");
        }
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

    #[test]
    fn empty_or_whitespace_only_key_is_an_error() {
        for contents in ["", " \t\r\n"] {
            let key_path = temp_key_file(contents);
            let error = Anonymizer::new(Some(key_path.as_path()))
                .err()
                .expect("empty anonymization key must fail");

            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "anonymization key file must contain a non-empty passphrase"
            );

            fs::remove_file(key_path).expect("removes temp key file");
        }
    }
}
