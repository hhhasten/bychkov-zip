//! шифрування: ключ з пароля Argon2id і AES-256-GCM
//!
//! пароль ніколи не використовується як ключ напряму, Argon2id навмисно повільно
//! і ресурсоємно перетворює його разом із випадковою сіллю на 256-бітний ключ,
//! щоб підбір паролів коштував дорого.
//!
//! AES-GCM шифрує дані і одночасно рахує тег аутентифікації (16 байт у кінці).
//! при розшифруванні тег перевіряється, тож будь-яка зміна шифротексту,
//! неправильний пароль чи підмінений заголовок (AAD) дають помилку,
//! а не сміття замість даних
//!

use crate::error::{ByzError, Result};
use crate::format::{NONCE_LEN, SALT_LEN};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

// параметри Argon2 для версії формату 1. змінювати їх не можна
// старі архіви перестануть відкриватися. для нових параметрів піднімаємо VERSION
const V1_MEMORY_KIB: u32 = 64 * 1024;
const V1_ITERATIONS: u32 = 3;
const V1_PARALLELISM: u32 = 1;

fn argon2_for_version(version: u8) -> Result<Argon2<'static>> {
    match version {
        1 => {
            let params =
                Params::new(V1_MEMORY_KIB, V1_ITERATIONS, V1_PARALLELISM, Some(KEY_LEN))
                    .map_err(|e| ByzError::Internal(format!("invalid argon2 parameters: {e}")))?;

            Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        }
        other => Err(ByzError::BadFormat(format!(
            "unsupported format version {other}"
        ))),
    }
}

/// виводить 256-бітний ключ з пароля і солі.
/// `Zeroizing` затре ключ у пам'яті, коли він вийде зі сфери видимості
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    version: u8,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon2 = argon2_for_version(version)?;

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| ByzError::Internal(format!("key derivation failed: {e}")))?;

    Ok(key)
}

/// шифрує `plaintext`. `aad` це дані які не шифруються, але входять у тег:
/// ми передаємо туди відкритий заголовок архіву.
/// результат = шифротекст + 16 байт тегу
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(*nonce);

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ByzError::Internal("encryption failed".into()))
}

/// розшифровує і перевіряє тег. будь-яка невдача це `AuthFailed`
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(*nonce);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ByzError::AuthFailed)
}

/// випадкова сіль із системного генератора
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// випадковий nonce. для одного ключа він не повинен повторюватися:
/// ключ у нас новий для кожного архіву, тож випадкового 96-бітного
/// значення цілком достатньо
pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    SysRng
        .try_fill_bytes(buf)
        .map_err(|e| ByzError::Internal(format!("system random generator failed: {e}")))
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{HEADER_LEN, Header};

    /// шістнадцятковий рядок у байти
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn test_key() -> [u8; KEY_LEN] {
        core::array::from_fn(|i| i as u8)
    }

    fn test_nonce() -> [u8; NONCE_LEN] {
        core::array::from_fn(|i| 100 + i as u8)
    }

    #[test]
    fn aes_gcm_known_answer() {
        // тестовий вектор з офіційного опису GCM (McGrew, Viega), Test Case 16:
        // AES-256, 60 байт відкритого тексту і 20 байт AAD.
        // перевіряє що ми підключили бібліотеку правильно, зокрема AAD
        let key: [u8; 32] = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected_ciphertext = hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        let expected_tag = hex("76fc6ece0f4e1768cddf8853bb2d551b");

        let result = encrypt(&plaintext, &key, &nonce, &aad).unwrap();

        let (ciphertext, tag) = result.split_at(plaintext.len());
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
        assert_eq!(decrypt(&result, &key, &nonce, &aad).unwrap(), plaintext);
    }

    #[test]
    fn roundtrip_and_overhead_is_the_16_byte_tag() {
        let data = b"secret archive contents";
        let encrypted = encrypt(data, &test_key(), &test_nonce(), b"header").unwrap();

        assert_eq!(encrypted.len(), data.len() + 16);
        assert_ne!(&encrypted[..data.len()], data);

        let decrypted = decrypt(&encrypted, &test_key(), &test_nonce(), b"header").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let encrypted = encrypt(&[], &test_key(), &test_nonce(), b"").unwrap();
        assert_eq!(encrypted.len(), 16);
        assert!(
            decrypt(&encrypted, &test_key(), &test_nonce(), b"")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let encrypted = encrypt(b"data", &test_key(), &test_nonce(), b"").unwrap();
        let mut other_key = test_key();
        other_key[0] ^= 1;

        let err = decrypt(&encrypted, &other_key, &test_nonce(), b"").unwrap_err();
        assert!(matches!(err, ByzError::AuthFailed));
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let encrypted = encrypt(b"data", &test_key(), &test_nonce(), b"").unwrap();
        let mut other_nonce = test_nonce();
        other_nonce[0] ^= 1;

        let err = decrypt(&encrypted, &test_key(), &other_nonce, b"").unwrap_err();
        assert!(matches!(err, ByzError::AuthFailed));
    }

    #[test]
    fn any_flipped_bit_of_ciphertext_or_tag_is_rejected() {
        // міняємо по одному біту в кожній позиції, включно з тегом
        let encrypted = encrypt(
            b"forty bytes of data for the flip test..",
            &test_key(),
            &test_nonce(),
            b"aad",
        )
        .unwrap();

        for position in 0..encrypted.len() {
            let mut tampered = encrypted.clone();
            tampered[position] ^= 0b0000_0100;
            let err = decrypt(&tampered, &test_key(), &test_nonce(), b"aad").unwrap_err();
            assert!(matches!(err, ByzError::AuthFailed), "position = {position}");
        }
    }

    #[test]
    fn truncated_ciphertext_is_rejected_without_panic() {
        let encrypted = encrypt(b"some data", &test_key(), &test_nonce(), b"").unwrap();
        for len in 0..encrypted.len() {
            let err = decrypt(&encrypted[..len], &test_key(), &test_nonce(), b"").unwrap_err();
            assert!(matches!(err, ByzError::AuthFailed), "len = {len}");
        }
    }

    #[test]
    fn tampered_header_is_rejected() {
        // головна перевірка AAD: заголовок не зашифрований, але змінити в ньому
        // жодного байта не можна. змінюємо кожен байт по черзі
        let header = Header::new([1u8; SALT_LEN], test_nonce());
        let aad = header.to_bytes();
        let encrypted = encrypt(b"payload", &test_key(), &test_nonce(), &aad).unwrap();

        // без змін усе гаразд
        assert!(decrypt(&encrypted, &test_key(), &test_nonce(), &aad).is_ok());

        for position in 0..HEADER_LEN {
            let mut tampered = aad;
            tampered[position] ^= 1;
            let err = decrypt(&encrypted, &test_key(), &test_nonce(), &tampered).unwrap_err();
            assert!(matches!(err, ByzError::AuthFailed), "position = {position}");
        }
    }

    #[test]
    fn same_input_with_different_nonce_gives_different_ciphertext() {
        let a = encrypt(b"same data", &test_key(), &test_nonce(), b"").unwrap();
        let mut other_nonce = test_nonce();
        other_nonce[11] ^= 1;
        let b = encrypt(b"same data", &test_key(), &other_nonce, b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_is_deterministic_and_depends_on_every_input() {
        let salt = [7u8; SALT_LEN];
        let key = derive_key(b"password", &salt, 1).unwrap();

        // той самий пароль і сіль дають той самий ключ
        assert_eq!(*key, *derive_key(b"password", &salt, 1).unwrap());
        // інший пароль
        assert_ne!(*key, *derive_key(b"passwore", &salt, 1).unwrap());
        // інша сіль
        let mut other_salt = salt;
        other_salt[0] ^= 1;
        assert_ne!(*key, *derive_key(b"password", &other_salt, 1).unwrap());
    }

    #[test]
    fn derive_key_rejects_unknown_version() {
        let err = derive_key(b"password", &[0u8; SALT_LEN], 99).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn password_to_decryption_end_to_end() {
        // увесь шлях: пароль + сіль -> ключ -> шифрування -> розшифрування з тим самим
        // паролем працює, з іншим дає AuthFailed
        let salt = random_salt().unwrap();
        let nonce = random_nonce().unwrap();
        let header = Header::new(salt, nonce).to_bytes();

        let key = derive_key(b"correct horse", &salt, 1).unwrap();
        let encrypted = encrypt(b"top secret", &key, &nonce, &header).unwrap();

        let same_key = derive_key(b"correct horse", &salt, 1).unwrap();
        assert_eq!(
            decrypt(&encrypted, &same_key, &nonce, &header).unwrap(),
            b"top secret"
        );

        let wrong_key = derive_key(b"battery staple", &salt, 1).unwrap();
        let err = decrypt(&encrypted, &wrong_key, &nonce, &header).unwrap_err();
        assert!(matches!(err, ByzError::AuthFailed));
    }

    #[test]
    fn random_values_differ_between_calls() {
        assert_ne!(random_salt().unwrap(), random_salt().unwrap());
        assert_ne!(random_nonce().unwrap(), random_nonce().unwrap());
    }
}
