//! The 12-word kit (VI-20): the words that open the reserve key.
//!
//! `diseno-vinculacion.md` §2.3 and §26.2, `Recuperacion/diseno.md` §3.1:
//!
//! ```text
//! E   = 120 bits from the system's generator (15 bytes)
//! C   = first 12 bits of SHA-256("trino/kit/v1/check" ‖ E)
//! kit = E ‖ C = 132 bits = 12 indices of 11 bits, most significant first
//! ```
//!
//! The 12 bits of check (BIP-39 has 4) catch a swapped pair of words but
//! once in 4096, and the domain ties the words to this version of the kit.
//! **The bits are not BIP-39's,** so the sheet is not a wallet seed; only the
//! word lists are BIP-39's Spanish, Portuguese and English lists (David's
//! choice of 29 Oct 2026, in place of REC-04's own lists).
//!
//! **The language comes from the words.** Unlike REC-04's lists, BIP-39's
//! share words and four-letter prefixes across languages (12 Spanish words
//! are also English ones). So a reading is tried in every language where all
//! 12 words are recognized, and the check picks it. In the rare case where
//! the words pass in two languages (one kit in millions of the ones made of
//! shared words), [`KitError::Ambiguous`] asks for the language and
//! [`Kit::parse_in`] reads it in that one.
//!
//! **The sheet is 3 rows of 4.** If the check fails as typed but passes read
//! by columns, [`KitError::ByColumns`] lets the screen ask "Did you write
//! them down by columns?", and [`Kit::parse_by_columns`] reads them so.

mod record;
mod words;

pub use record::{KitRecord, RecordError, RECORD_LEN};

use crate::kdf::{KdfError, KdfParams};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Bytes of entropy in a kit (120 bits).
pub const ENTROPY_LEN: usize = 15;
/// Words in a kit.
pub const WORD_COUNT: usize = 12;

const CHECK_DOMAIN: &[u8] = b"trino/kit/v1/check";
const KDF_SALT: &[u8] = b"trino/kit/v1";
const INFO_RESERVE: &[u8] = b"trino/kit/v1/reserve";
const INFO_CHECK_LOCAL: &[u8] = b"trino/kit/v1/check-local";

/// Argon2id for the kit: 64 MiB, 3 passes, 1 lane (`Recuperacion/diseno.md`
/// §3.2). Fixed for version 1 of the kit, because the sheet cannot carry
/// them: changing them means `trino/kit/v2`. One lane, not the vault's four,
/// because the kit is opened on a phone (S-VI5 measures it there).
pub const KIT_KDF: KdfParams = KdfParams {
    m_kib: 64 * 1024,
    t: 3,
    p: 1,
};

/// What the kit opens. `k_reserva` wraps the reserve key and is never
/// stored; `h_check` is stored to test the sheet later without the words.
pub struct KitKeys {
    pub k_reserva: Zeroizing<[u8; 32]>,
    pub h_check: [u8; 32],
}

/// The language of a word list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    Es,
    Pt,
    En,
}

impl Language {
    /// Every language, in the order a tie is settled.
    pub const ALL: [Language; 3] = [Language::Es, Language::Pt, Language::En];

    /// The language's code: "es", "pt" or "en".
    pub fn code(self) -> &'static str {
        match self {
            Language::Es => "es",
            Language::Pt => "pt",
            Language::En => "en",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KitError {
    /// Not 12 words.
    #[error("a kit has 12 words, got {0}")]
    WordCount(usize),
    /// The word at `index` (from 0) is in no list. `suggestion` is the one
    /// word one letter away from it, if there is exactly one; it is never
    /// taken without asking.
    #[error("word {index} is not in the list")]
    UnknownWord {
        index: usize,
        suggestion: Option<&'static str>,
    },
    /// Every word is right but the check fails: the order is wrong.
    #[error("the words are right but their order is not")]
    Checksum,
    /// The check fails as typed but passes read by columns.
    #[error("the words pass when read by columns")]
    ByColumns,
    /// The words pass in more than one language.
    #[error("the words pass in more than one language")]
    Ambiguous,
}

/// A kit: the 120 bits behind the 12 words. Never stored: the device keeps
/// only what is derived from it.
pub struct Kit {
    entropy: Zeroizing<[u8; ENTROPY_LEN]>,
}

impl fmt::Debug for Kit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kit(..)")
    }
}

impl Kit {
    /// A new kit from the system's generator.
    pub fn generate() -> Kit {
        Kit::generate_with_rng(&mut OsRng)
    }

    /// A new kit from `rng`.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Kit {
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        rng.fill_bytes(&mut entropy[..]);
        Kit { entropy }
    }

    /// The kit with these 120 bits.
    pub fn from_entropy(entropy: [u8; ENTROPY_LEN]) -> Kit {
        Kit {
            entropy: Zeroizing::new(entropy),
        }
    }

    #[cfg(test)]
    pub(crate) fn entropy(&self) -> &[u8; ENTROPY_LEN] {
        &self.entropy
    }

    /// The 12 words in `lang`, as its list writes them (the Spanish list
    /// keeps its accents, decomposed: a screen shows them composed).
    pub fn words(&self, lang: Language) -> [&'static str; WORD_COUNT] {
        indices(&self.entropy).map(|i| words::word(lang, i))
    }

    /// Reads typed words in whichever language they pass.
    pub fn parse(text: &str) -> Result<(Kit, Language), KitError> {
        read(text, &Language::ALL, false)
    }

    /// Reads typed words in `lang` only (after [`KitError::Ambiguous`]).
    pub fn parse_in(text: &str, lang: Language) -> Result<Kit, KitError> {
        read(text, &[lang], false).map(|(kit, _)| kit)
    }

    /// Reads typed words written down by columns of the 3 × 4 sheet (after
    /// [`KitError::ByColumns`] and a yes).
    pub fn parse_by_columns(text: &str) -> Result<(Kit, Language), KitError> {
        read(text, &Language::ALL, true)
    }

    /// `K = Argon2id(E)`, and from it `k_reserva` and `h_check` with HKDF.
    /// `K` is wiped before returning: only these two leave.
    pub fn derive(&self) -> Result<KitKeys, KdfError> {
        // A build with `test-kdf` (app tests only, never a release) derives
        // with the cheap parameters, like the vault does.
        #[cfg(feature = "test-kdf")]
        let k = crate::kdf::argon2id_test(&self.entropy[..], KDF_SALT)?;
        #[cfg(not(feature = "test-kdf"))]
        let k = crate::kdf::argon2id(&self.entropy[..], KDF_SALT, &KIT_KDF)?;
        let hk = Hkdf::<Sha256>::new(None, &k[..]);
        let mut keys = KitKeys {
            k_reserva: Zeroizing::new([0u8; 32]),
            h_check: [0u8; 32],
        };
        hk.expand(INFO_RESERVE, &mut keys.k_reserva[..])
            .expect("32 bytes is a valid HKDF-SHA256 length");
        hk.expand(INFO_CHECK_LOCAL, &mut keys.h_check)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        Ok(keys)
    }

    /// Whether these are the words of the kit whose `h_check` is stored: the
    /// "check your sheet" drill. Costs one Argon2id.
    pub fn matches(&self, h_check: &[u8; 32]) -> Result<bool, KdfError> {
        let keys = self.derive()?;
        Ok(ct_eq(&keys.h_check, h_check))
    }
}

/// The 12 word indices of `entropy`: its 120 bits, then the 12 check bits.
fn indices(entropy: &[u8; ENTROPY_LEN]) -> [u16; WORD_COUNT] {
    let mut bits = Zeroizing::new([0u8; 17]);
    bits[..ENTROPY_LEN].copy_from_slice(entropy);
    let c = check(entropy);
    bits[15] = (c >> 4) as u8;
    bits[16] = ((c & 0x0F) as u8) << 4;
    let mut out = [0u16; WORD_COUNT];
    for (n, index) in out.iter_mut().enumerate() {
        for bit in n * 11..n * 11 + 11 {
            let b = (bits[bit / 8] >> (7 - bit % 8)) & 1;
            *index = (*index << 1) | u16::from(b);
        }
    }
    out
}

/// The entropy of 12 word indices, if their check bits are right.
fn entropy_of(indices: &[u16; WORD_COUNT]) -> Option<Zeroizing<[u8; ENTROPY_LEN]>> {
    let mut bits = Zeroizing::new([0u8; 17]);
    for (n, index) in indices.iter().enumerate() {
        for k in 0..11 {
            let bit = n * 11 + k;
            let b = ((index >> (10 - k)) & 1) as u8;
            bits[bit / 8] |= b << (7 - bit % 8);
        }
    }
    let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
    entropy.copy_from_slice(&bits[..ENTROPY_LEN]);
    let c = (u16::from(bits[15]) << 4) | (u16::from(bits[16]) >> 4);
    (check(&entropy) == c).then_some(entropy)
}

/// The sheet's order from words written down by its columns (3 rows of 4).
fn from_columns(typed: &[u16; WORD_COUNT]) -> [u16; WORD_COUNT] {
    let mut out = [0u16; WORD_COUNT];
    for r in 0..3 {
        for c in 0..4 {
            out[r * 4 + c] = typed[c * 3 + r];
        }
    }
    out
}

/// One reading of typed words in one language.
struct Reading {
    lang: Language,
    matches: Vec<Option<words::Match>>,
}

impl Reading {
    fn complete(&self) -> Option<[u16; WORD_COUNT]> {
        let mut out = [0u16; WORD_COUNT];
        for (slot, m) in out.iter_mut().zip(&self.matches) {
            *slot = m.as_ref()?.index();
        }
        Some(out)
    }

    fn exact(&self) -> bool {
        self.matches
            .iter()
            .all(|m| matches!(m, Some(words::Match::Exact(_))))
    }
}

/// Reads typed words in each of `langs` and keeps the reading that passes
/// the check (see the module's notes on languages and columns).
fn read(text: &str, langs: &[Language], by_columns: bool) -> Result<(Kit, Language), KitError> {
    let tokens = words::tokens(text);
    if tokens.len() != WORD_COUNT {
        return Err(KitError::WordCount(tokens.len()));
    }
    let readings: Vec<Reading> = langs
        .iter()
        .map(|&lang| Reading {
            lang,
            matches: tokens.iter().map(|t| words::recognize(lang, t)).collect(),
        })
        .collect();
    let complete: Vec<(&Reading, [u16; WORD_COUNT])> = readings
        .iter()
        .filter_map(|r| r.complete().map(|i| (r, i)))
        .collect();
    if complete.is_empty() {
        // Point at the first unknown word of the closest language.
        let best = readings
            .iter()
            .rev()
            .max_by_key(|r| r.matches.iter().filter(|m| m.is_some()).count())
            .expect("at least one language");
        let index = best
            .matches
            .iter()
            .position(Option::is_none)
            .expect("an incomplete reading");
        return Err(KitError::UnknownWord {
            index,
            suggestion: words::suggest(best.lang, &tokens[index]),
        });
    }
    let order = |i: &[u16; WORD_COUNT]| if by_columns { from_columns(i) } else { *i };
    let mut passing: Vec<(&Reading, Zeroizing<[u8; ENTROPY_LEN]>)> = complete
        .iter()
        .filter_map(|(r, i)| entropy_of(&order(i)).map(|e| (*r, e)))
        .collect();
    if passing.len() > 1 && passing.iter().any(|(r, _)| r.exact()) {
        // Words typed whole beat a reading that needed prefixes.
        passing.retain(|(r, _)| r.exact());
    }
    match passing.len() {
        1 => {
            let (r, entropy) = passing.pop().expect("one reading");
            Ok((Kit { entropy }, r.lang))
        }
        0 if !by_columns
            && complete
                .iter()
                .any(|(_, i)| entropy_of(&from_columns(i)).is_some()) =>
        {
            Err(KitError::ByColumns)
        }
        0 => Err(KitError::Checksum),
        _ => Err(KitError::Ambiguous),
    }
}

/// Compares two values without stopping at the first difference.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// The 12 check bits of `entropy`.
fn check(entropy: &[u8; ENTROPY_LEN]) -> u16 {
    let d = Sha256::new()
        .chain_update(CHECK_DOMAIN)
        .chain_update(entropy)
        .finalize();
    (u16::from(d[0]) << 4) | (u16::from(d[1]) >> 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/kit.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn e15(v: &Value) -> [u8; ENTROPY_LEN] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_words_match_the_independent_vectors() {
        for case in vectors()["words"].as_array().unwrap() {
            let kit = Kit::from_entropy(e15(&case["entropy"]));
            assert_eq!(
                u64::from(check(kit.entropy())),
                case["check"].as_u64().unwrap()
            );
            for lang in Language::ALL {
                assert_eq!(kit.words(lang).to_vec(), strings(&case[lang.code()]));
            }
        }
    }

    #[test]
    fn the_vectors_read_back_in_their_language() {
        for case in vectors()["words"].as_array().unwrap() {
            let entropy = e15(&case["entropy"]);
            for lang in Language::ALL {
                let typed = strings(&case[lang.code()]).join(" ");
                let (kit, got) = Kit::parse(&typed).unwrap();
                assert_eq!((kit.entropy(), got), (&entropy, lang));
                // As a keyboard types accents (composed), in capitals, numbered.
                let nfc = case[format!("{}_nfc", lang.code())].as_str().unwrap();
                let numbered: String = nfc
                    .split(' ')
                    .enumerate()
                    .map(|(i, w)| format!("{}. {},\n", i + 1, w.to_uppercase()))
                    .collect();
                assert_eq!(Kit::parse(&numbered).unwrap().0.entropy(), &entropy);
            }
        }
    }

    #[test]
    fn four_letters_of_each_word_are_enough() {
        let case = &vectors()["words"][3];
        for lang in Language::ALL {
            let short: Vec<String> = strings(&case[lang.code()])
                .iter()
                .map(|w| words::fold(w).chars().take(4).collect())
                .collect();
            let kit = Kit::parse_in(&short.join(" "), lang).unwrap();
            assert_eq!(kit.entropy(), &e15(&case["entropy"]));
        }
    }

    #[test]
    fn a_kit_reads_back_its_own_words() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        for _ in 0..50 {
            let kit = Kit::generate_with_rng(&mut rng);
            for lang in Language::ALL {
                let (back, got) = Kit::parse(&kit.words(lang).join(" ")).unwrap();
                assert_eq!((back.entropy(), got), (kit.entropy(), lang));
            }
        }
    }

    #[test]
    fn kits_from_the_system_differ() {
        assert_ne!(Kit::generate().entropy(), Kit::generate().entropy());
    }

    #[test]
    fn not_twelve_words_is_refused() {
        let w = strings(&vectors()["words"][2]["en"]);
        assert_eq!(
            Kit::parse(&w[..11].join(" ")).unwrap_err(),
            KitError::WordCount(11)
        );
        let thirteen = format!("{} {}", w.join(" "), w[0]);
        assert_eq!(Kit::parse(&thirteen).unwrap_err(), KitError::WordCount(13));
    }

    #[test]
    fn an_unknown_word_says_where_and_suggests_only_a_sure_one() {
        let mut w = strings(&vectors()["words"][2]["es"]);
        assert_eq!(w[0], "chivo");
        w[0] = "cjivo".into();
        assert_eq!(
            Kit::parse(&w.join(" ")).unwrap_err(),
            KitError::UnknownWord {
                index: 0,
                suggestion: Some("chivo")
            }
        );
        w[0] = "hivo".into();
        assert_eq!(
            Kit::parse(&w.join(" ")).unwrap_err(),
            KitError::UnknownWord {
                index: 0,
                suggestion: None
            }
        );
    }

    #[test]
    fn a_swapped_pair_fails_the_check() {
        let mut w = strings(&vectors()["words"][2]["pt"]);
        w.swap(4, 9);
        assert_eq!(Kit::parse(&w.join(" ")).unwrap_err(), KitError::Checksum);
    }

    #[test]
    fn words_written_by_columns_are_noticed_and_read() {
        let case = &vectors()["words"][4];
        let w = strings(&case["es"]);
        // The sheet shows rows of 4; written by columns: 1 5 9 2 6 10 ...
        let by_columns: Vec<&str> = (0..4)
            .flat_map(|c| (0..3).map(move |r| r * 4 + c))
            .map(|i| w[i].as_str())
            .collect();
        let typed = by_columns.join(" ");
        assert_eq!(Kit::parse(&typed).unwrap_err(), KitError::ByColumns);
        let (kit, lang) = Kit::parse_by_columns(&typed).unwrap();
        assert_eq!(
            (kit.entropy(), lang),
            (&e15(&case["entropy"]), Language::Es)
        );
    }

    #[test]
    fn words_that_pass_in_two_languages_ask_for_the_language() {
        let amb = &vectors()["ambiguous"];
        let typed = strings(&amb["words"]).join(" ");
        assert_eq!(Kit::parse(&typed).unwrap_err(), KitError::Ambiguous);
        assert_eq!(
            Kit::parse_in(&typed, Language::Es).unwrap().entropy(),
            &e15(&amb["es_entropy"])
        );
        assert_eq!(
            Kit::parse_in(&typed, Language::En).unwrap().entropy(),
            &e15(&amb["en_entropy"])
        );
        assert!(matches!(
            Kit::parse_in(&typed, Language::Pt),
            Err(KitError::UnknownWord { .. })
        ));
    }

    #[test]
    fn prefixes_that_pass_in_two_languages_ask_for_the_language_too() {
        // No reading is whole here, so neither can win on that.
        let amb = &vectors()["ambiguous_prefixes"];
        let typed = strings(&amb["words"]).join(" ");
        assert_eq!(Kit::parse(&typed).unwrap_err(), KitError::Ambiguous);
        assert_eq!(
            Kit::parse_in(&typed, Language::En).unwrap().entropy(),
            &e15(&amb["en_entropy"])
        );
    }

    #[test]
    #[cfg(not(feature = "test-kdf"))]
    fn the_keys_match_the_independent_vectors() {
        for case in vectors()["keys"].as_array().unwrap() {
            let keys = Kit::from_entropy(e15(&case["entropy"])).derive().unwrap();
            assert_eq!(
                hex::encode(*keys.k_reserva),
                case["k_reserva"].as_str().unwrap()
            );
            assert_eq!(hex::encode(keys.h_check), case["h_check"].as_str().unwrap());
        }
    }

    #[test]
    fn the_kit_kdf_is_within_the_bounds() {
        assert_eq!(KIT_KDF.check(), Ok(()));
    }

    #[test]
    #[cfg(not(feature = "test-kdf"))]
    fn the_sheet_drill_tells_the_right_words_from_others() {
        let case = &vectors()["keys"][1];
        let h_check: [u8; 32] = hex::decode(case["h_check"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let typed = strings(&vectors()["words"][1]["pt"]).join(" ");
        let (kit, _) = Kit::parse(&typed).unwrap();
        assert!(kit.matches(&h_check).unwrap());
        assert!(!Kit::from_entropy([0; ENTROPY_LEN])
            .matches(&h_check)
            .unwrap());
    }

    #[test]
    fn the_debug_form_hides_the_kit() {
        assert_eq!(
            format!("{:?}", Kit::from_entropy([7; ENTROPY_LEN])),
            "Kit(..)"
        );
    }
}
