//! The three word lists and how typed words are read.
//!
//! The lists are BIP-39's Spanish, Portuguese and English lists, unchanged
//! (`tests/vectors/README.md` has their source and SHA-256). Only the lists
//! are BIP-39's: the kit's bits and check are Trino's own (`super`).
//!
//! Reading is forgiving with the form and strict with the choice
//! (`Recuperacion/diseno.md` §3.1.1):
//! - accents, case, numbering and punctuation do not matter: "1. Aéreo," and
//!   "aereo" are the same word;
//! - a word is recognized whole, or by its first four letters, which are
//!   unique within each list;
//! - a word one letter away from exactly one word of the list is never taken:
//!   it is only offered as a suggestion.

use super::Language;
use std::sync::OnceLock;
use zeroize::Zeroizing;

const SPANISH: &str = include_str!("wordlists/spanish.txt");
const PORTUGUESE: &str = include_str!("wordlists/portuguese.txt");
const ENGLISH: &str = include_str!("wordlists/english.txt");

/// Number of words in each list.
pub const LIST_LEN: usize = 2048;

struct List {
    /// The words as the list writes them (Spanish keeps its accents, in NFKD).
    words: Vec<&'static str>,
    /// The same words folded: no accents, lower case, only `a` to `z`.
    folded: Vec<String>,
}

fn load(text: &'static str) -> List {
    let words: Vec<&'static str> = text.lines().collect();
    assert_eq!(words.len(), LIST_LEN, "a word list must have 2048 words");
    let folded = words.iter().map(|w| fold(w)).collect();
    List { words, folded }
}

fn list(lang: Language) -> &'static List {
    static LISTS: [OnceLock<List>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    match lang {
        Language::Es => LISTS[0].get_or_init(|| load(SPANISH)),
        Language::Pt => LISTS[1].get_or_init(|| load(PORTUGUESE)),
        Language::En => LISTS[2].get_or_init(|| load(ENGLISH)),
    }
}

/// The word at `index` (below 2048) of `lang`'s list.
pub(crate) fn word(lang: Language, index: u16) -> &'static str {
    list(lang).words[usize::from(index)]
}

/// One character folded: the base letter of an accented Latin letter, lower
/// case; `None` for a combining mark, which belongs to the letter before it.
fn fold_char(c: char) -> Option<char> {
    if ('\u{0300}'..='\u{036F}').contains(&c) {
        return None;
    }
    let lower = c.to_lowercase().next().unwrap_or(c);
    Some(match lower {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'ç' => 'c',
        'è' | 'é' | 'ê' | 'ë' => 'e',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'ñ' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'ý' | 'ÿ' => 'y',
        other => other,
    })
}

/// A word without accents, in lower case.
pub(crate) fn fold(word: &str) -> String {
    word.chars().filter_map(fold_char).collect()
}

/// The words in what someone typed: anything that is not a letter (spaces,
/// line breaks, digits, commas, periods) separates them. The words are the
/// secret, so each is wiped when dropped. `current` gets room up front (a
/// lower-case letter can take more bytes than its capital), so growing it
/// leaves no copies behind.
pub(crate) fn tokens(text: &str) -> Vec<Zeroizing<String>> {
    let mut out = Vec::new();
    let mut current = Zeroizing::new(String::with_capacity(2 * text.len()));
    for c in text.chars() {
        match fold_char(c) {
            None => {}
            Some(f) if f.is_alphabetic() => current.push(f),
            Some(_) => flush(&mut current, &mut out),
        }
    }
    flush(&mut current, &mut out);
    out
}

fn flush(current: &mut Zeroizing<String>, out: &mut Vec<Zeroizing<String>>) {
    if !current.is_empty() {
        out.push(Zeroizing::new(current.as_str().to_owned()));
        current.clear();
    }
}

/// How a typed word matched a word of a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Match {
    /// The whole word.
    Exact(u16),
    /// Four letters or more that start exactly one word.
    Prefix(u16),
}

impl Match {
    pub(crate) fn index(self) -> u16 {
        match self {
            Match::Exact(i) | Match::Prefix(i) => i,
        }
    }
}

/// The word of `lang`'s list that the folded `token` names, if any.
pub(crate) fn recognize(lang: Language, token: &str) -> Option<Match> {
    let list = list(lang);
    if let Some(i) = list.folded.iter().position(|w| w == token) {
        return Some(Match::Exact(i as u16));
    }
    if token.chars().count() < 4 {
        return None;
    }
    let prefix: Zeroizing<String> = Zeroizing::new(token.chars().take(4).collect());
    let mut found = list
        .folded
        .iter()
        .enumerate()
        .filter(|(_, w)| w.starts_with(prefix.as_str()));
    match (found.next(), found.next()) {
        (Some((i, _)), None) => Some(Match::Prefix(i as u16)),
        _ => None,
    }
}

/// Whether `a` becomes `b` with one substitution, insertion or deletion.
fn one_edit_apart(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (short, long) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    match long.len() - short.len() {
        0 => {
            short
                .iter()
                .zip(long.iter())
                .filter(|(x, y)| x != y)
                .count()
                == 1
        }
        1 => {
            let skip = short
                .iter()
                .zip(long.iter())
                .position(|(x, y)| x != y)
                .unwrap_or(short.len());
            short[skip..] == long[skip + 1..]
        }
        _ => false,
    }
}

/// The one word of `lang`'s list one letter away from `token`, if there is
/// exactly one.
pub(crate) fn suggest(lang: Language, token: &str) -> Option<&'static str> {
    let list = list(lang);
    let mut near = list
        .folded
        .iter()
        .enumerate()
        .filter(|(_, w)| one_edit_apart(token, w));
    match (near.next(), near.next()) {
        (Some((i, _)), None) => Some(list.words[i]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_lists_are_the_downloaded_ones() {
        let sha = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
        assert_eq!(
            sha(SPANISH),
            "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b"
        );
        assert_eq!(
            sha(PORTUGUESE),
            "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f"
        );
        assert_eq!(
            sha(ENGLISH),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn every_folded_word_is_plain_and_unique_with_a_unique_prefix() {
        for lang in Language::ALL {
            let folded = &list(lang).folded;
            assert_eq!(folded.len(), LIST_LEN);
            let mut seen = std::collections::HashSet::new();
            let mut prefixes = std::collections::HashSet::new();
            for w in folded {
                assert!(w.chars().all(|c| c.is_ascii_lowercase()), "{w}");
                assert!(seen.insert(w.clone()), "{w} twice");
                let p: String = w.chars().take(4).collect();
                assert!(prefixes.insert(p), "prefix of {w} twice");
            }
        }
    }

    #[test]
    fn every_word_is_recognized_whole_and_by_its_prefix() {
        for lang in Language::ALL {
            for (i, w) in list(lang).folded.iter().enumerate() {
                assert_eq!(recognize(lang, w), Some(Match::Exact(i as u16)));
                if w.len() > 4 {
                    assert_eq!(recognize(lang, &w[..4]), Some(Match::Prefix(i as u16)));
                }
            }
        }
    }

    #[test]
    fn composed_and_decomposed_accents_fold_the_same() {
        assert_eq!(fold("A\u{e9}reo"), "aereo");
        assert_eq!(fold("ae\u{301}reo"), "aereo");
        assert_eq!(fold("CIPRÉS"), "cipres");
        assert_eq!(fold("Ñandú"), "nandu");
    }

    #[test]
    fn numbering_and_punctuation_separate_words() {
        let got: Vec<String> = tokens("1. Chivo, 2.fuerza\n3) PIEZA;  a\u{e9}reo")
            .iter()
            .map(|t| t.to_string())
            .collect();
        assert_eq!(got, ["chivo", "fuerza", "pieza", "aereo"]);
    }

    #[test]
    fn one_letter_away_is_only_a_suggestion() {
        // "chivo" with a letter changed and one added within its first four.
        assert_eq!(recognize(Language::Es, "cjivo"), None);
        assert_eq!(suggest(Language::Es, "cjivo"), Some("chivo"));
        assert_eq!(recognize(Language::Es, "chhivo"), None);
        assert_eq!(suggest(Language::Es, "chhivo"), Some("chivo"));
        // A letter dropped: "hivo" is one away from chivo, hijo and vivo.
        assert_eq!(suggest(Language::Es, "hivo"), None);
        // Past the fourth letter a slip does not matter: the prefix decides.
        assert_eq!(
            recognize(Language::Es, "fuersa").map(Match::index),
            recognize(Language::Es, "fuerza").map(Match::index)
        );
        assert!(one_edit_apart("mango", "manga"));
        assert!(!one_edit_apart("mango", "mango"));
        assert!(!one_edit_apart("mango", "mangoes"));
    }
}
