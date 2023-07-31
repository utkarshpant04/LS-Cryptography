import itertools
import string
import sys
import textwrap

def vigenere(plaintext, key, a_is_zero=True):
    key = key.lower()
    if not all(k in string.ascii_lowercase for k in key):
        raise ValueError("Invalid key {!r}; the key can only consist of English letters".format(key))
    key_iter = itertools.cycle(map(ord, key))
    return "".join(
        chr(ord('a') + (
            (next(key_iter) - ord('a') + ord(letter) - ord('a'))    # Calculate shifted value
            + (0 if a_is_zero else 2)                               # Account for non-zero indexing
            ) % 26) if letter in string.ascii_lowercase             # Ignore non-alphabetic chars
        else letter
        for letter in plaintext.lower()
    )

def vigenere_decrypt(ciphertext, key, a_is_zero=True):
    # Decryption is encryption with the inverse key
    key_ind = [ord(k) - ord('a') for k in key.lower()]
    inverse = "".join(chr(ord('a') +
            ((26 if a_is_zero else 22) -
                (ord(k) - ord('a'))
            ) % 26) for k in key)
    return vigenere(ciphertext, inverse, a_is_zero)

def test_vigenere(text, key, a_is_zero=True):
    ciphertext = vigenere(text, key, a_is_zero)
    plaintext  = vigenere_decrypt(ciphertext, key, a_is_zero)
    assert plaintext == text, "{!r} -> {!r} -> {!r} (a {}= 0)".format(
        text, ciphertext, plaintext, "" if a_is_zero else "!")

for text in ["rewind", "text with spaces", "pun.ctuation", "numb3rs"]:
    for key in ["iepw", "aceaq", "safe", "pwa"]:
        test_vigenere(text, key, True)
        test_vigenere(text, key, False)

ENGLISH_FREQ = (0.0749, 0.0129, 0.0354, 0.0362, 0.1400, 0.0218, 0.0174, 0.0422, 0.0665, 0.0027, 0.0047,
                0.0357, 0.0339, 0.0674, 0.0737, 0.0243, 0.0026, 0.0614, 0.0695, 0.0985, 0.0300, 0.0116,
                0.0169, 0.0028, 0.0164, 0.0004)

def compare_freq(text):
    if not text:
        return None
    text = [t for t in text.lower() if t in string.ascii_lowercase]
    freq = [0] * 26
    total = float(len(text))
    for l in text:
        freq[ord(l) - ord('a')] += 1
    return sum(abs(f / total - E) for f, E in zip(freq, ENGLISH_FREQ))


def solve_vigenere(text, key_min_size=1, key_max_size=12, a_is_zero=True):
    best_keys = []

    text_letters = [c for c in text.lower() if c in string.ascii_lowercase]

    for key_length in range(key_min_size, key_max_size + 1):
        # Try all possible key lengths
        key = [None] * key_length
        for key_index in range(key_length):
            letters = "".join(itertools.islice(text_letters, key_index, None, key_length))
            shifts = []
            for key_char in string.ascii_lowercase:
                shifts.append(
                    (compare_freq(vigenere_decrypt(letters, key_char, a_is_zero)), key_char)
                )
            key[key_index] = min(shifts, key=lambda x: x[0])[1]
        best_keys.append("".join(key))
    best_keys.sort(key=lambda key: compare_freq(vigenere_decrypt(text, key, a_is_zero)))
    return best_keys[:2]
ENGLISH_WORDS = {
    "any", "of", "it", "real", "mean", "look", "at", "this", "a", "world", "built", "on", "fantasy",
    "synthetic", "emotions", "in", "the", "form", "pills", "psychological", "warfare", "advertising",
    "mind", "altering", "chemicals", "food", "brainwashing", "seminars", "media", "controlled",
    "isolated", "bubbles", "social", "networks", "you", "want", "to", "talk", "about", "reality",
    "we", "haven't", "lived", "anything", "remotely", "close", "since", "turn", "century", "turned",
    "off", "took", "out", "batteries", "snacked", "bag", "gmos", "while", "tossed", "remnants", "into",
    "ever", "expanding", "dumpster", "human", "condition", "live", "branded", "houses", "trademarked",
    "by", "corporations", "bipolar", "numbers", "jumping", "up", "and", "down", "digital", "displays",
    "hypnotizing", "us", "biggest", "slumber", "mankind", "has", "ever", "seen", "have", "dig", "pretty",
    "deep", "kiddo", "before", "can", "find", "anything", "kingdom", "bullshit", "even", "for", "far",
    "too", "long", "so", "don't", "tell", "me", "not", "being", "i'm", "no", "less", "than", "fucking",
    "beef", "patty", "your", "mac", "as", "far", "concerned", "elliot", "i", "am", "very", "all", "together",
    "now", "whether", "like", "it", "or", "notit", "came", "from", "first", "computer", "mark", "1",
    "room-size", "maze", "electromechanical", "circuits", "1944", "lab", "harvard", "university", "developed",
    "glitch", "one", "day", "no", "one", "able", "locate", "cause", "after", "hours", "searching", "assistant",
    "finally", "spotted", "problem", "seemed", "had", "landed", "circuit", "boards", "shorted", "from", "that",
    "moment", "glitches", "were", "referred", "bugs", "solution", "had", "taken", "terrific", "toll", "restless",
    "turning", "mind", "tormented", "by", "puzzle", "preoccupation", "meals", "insomnia", "sudden", "wakening",
    "midnight", "pressure", "succeed", "because", "failure", "could", "national", "consequences", "despair",
    "long", "weeks", "when", "insoluble", "repeated", "dashings", "uplifted", "hopes", "mental", "shocks",
    "tension", "frustration", "urgency", "secrecy", "converged", "hammered", "furiously", "upon", "his", "skull",
    "collapsed", "in", "december", "make", "list", "above", "words"
}
def contains_meaningful_words(text):
    words = text.lower().split()
    meaningful_word_count = sum(1 for word in words if word in ENGLISH_WORDS)
    return meaningful_word_count >= len(words) * 0.4  # Check if at least 40% of words are meaningful English words

def main():
    ciphertext = input("Enter the ciphertext to decrypt: ").strip()

    for key in reversed(solve_vigenere(ciphertext)):
        decrypted_text = vigenere_decrypt(ciphertext, key)
        if ciphertext == vigenere(decrypted_text, key) and contains_meaningful_words(decrypted_text):
            print("")
            print("Found key: {!r}".format(key))
            print("Solution:")
            
            print(textwrap.fill(decrypted_text))
            break
    else:
        print("No unique solution found or no meaningful English words.")

if __name__ == "__main__":
    main()