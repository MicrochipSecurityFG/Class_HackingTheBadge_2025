#ifndef BIP39_H
#define BIP39_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define BIP39_ENTROPY_MIN 128  // Minimum entropy bits (12 words)
#define BIP39_ENTROPY_MAX 256  // Maximum entropy bits (24 words)
#define BIP39_SEED_LEN 64      // Seed length in bytes (512 bits)
#define BIP39_WORDS_MIN 12     // Minimum number of words
#define BIP39_WORDS_MAX 24     // Maximum number of words

// Generate a mnemonic phrase from entropy (12, 15, 18, 21, or 24 words)
int bip39_generate_mnemonic(char *mnemonic);

// Validate a mnemonic phrase
bool bip39_validate_mnemonic(const char *mnemonic);

// Convert mnemonic to seed using PBKDF2 with optional passphrase
int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed, size_t seed_len);

#endif // BIP39_H
