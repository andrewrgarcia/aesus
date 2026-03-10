use std::sync::OnceLock;

static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn load_words() -> Vec<&'static str> {

    include_str!("diceware.txt")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect()
}

pub fn get_words() -> &'static Vec<&'static str> {

    WORDS.get_or_init(load_words)
}