#define SINGLE_THREADED
#include "bip39.h"
#include "bip39_english.h" // Assumes bip39_wordlist[2048]
#include "pbkdf2.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include "secure_element.h"

#define SHA256_DIGEST_SIZE 32

static void print_hex(const uint8_t* data, size_t len, const char* label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper: Convert 128-bit entropy + 4-bit checksum to 12 word indices
void entropy_to_indices(const uint8_t *entropy, uint16_t *indices) {

	uint8_t hash[SHA256_DIGEST_SIZE];

	sha256((uint8_t *)entropy, 16, hash);

	// Concatenate 128-bit entropy and 4-bit checksum
	uint8_t buffer[17];  // Fixed size for 132 bits
	memset(buffer, 0, 17);
	memcpy(buffer, entropy, 16);  // Copy 16 bytes of entropy

	buffer[16] = (hash[0] & 0xF0);

	// Extract 12 11-bit indices
	    for (size_t i = 0; i < 12; i++) {
	        size_t bit_start = i * 11;         // Start bit position (0, 11, 22, ...)
	        size_t byte_start = bit_start / 8; // Start byte
	        size_t bit_offset = bit_start % 8; // Bits into the start byte

	        // Grab 32 bits to cover any 11-bit chunk
	        uint32_t bits = 0;
	        bits |= (uint32_t)buffer[byte_start] << 24;
	        if (byte_start + 1 < 17) bits |= (uint32_t)buffer[byte_start + 1] << 16;
	        if (byte_start + 2 < 17) bits |= (uint32_t)buffer[byte_start + 2] << 8;
	        if (byte_start + 3 < 17) bits |= (uint32_t)buffer[byte_start + 3];

	        // Shift to align the 11 bits to the right
	        bits >>= (32 - 11 - bit_offset);  // 21 - bit_offset
	        indices[i] = bits & 0x7FF;        // Mask to 11 bits

	}

}

int bip39_generate_mnemonic(char *mnemonic) {

    uint8_t entropy[16];
    uint8_t random[32] = {0};

    SECURE_ELEMENT_GetRandom(random);

    memcpy(entropy, random, 16);
    
    print_hex(entropy, 16, "Entropy");

    uint16_t indices[12];
    entropy_to_indices(entropy, indices);

    size_t pos = 0;
    for (int i = 0; i < 12; i++) {
        const char *word = bip39_wordlist[indices[i]];
        size_t word_len = strlen(word);
        strcpy(mnemonic + pos, word);
        pos += word_len;
        if (i < 12 - 1) {
            mnemonic[pos] = ' ';
            pos++;
        }
    }
    mnemonic[pos] = '\0';
    return 0;
}

void uint32_to_uint8_byteswap(const uint32_t *h, uint8_t *output, size_t num_elements) {
    for (size_t i = 0; i < num_elements; i++) {
        uint8_t *bytes = (uint8_t *)&h[i]; // Treat each uint32_t as 4 bytes
        // Copy 4 bytes with reversed order
        output[i * 4 + 0] = bytes[3]; // MSB becomes first
        output[i * 4 + 1] = bytes[2];
        output[i * 4 + 2] = bytes[1];
        output[i * 4 + 3] = bytes[0]; // LSB becomes last
    }
}

bool bip39_validate_mnemonic(const char *mnemonic) {
    if (!mnemonic) return false;

    int word_count = 0;
    const char *p = mnemonic;
    while (*p) if (*p++ == ' ') word_count++;
    word_count++;
    if (word_count < BIP39_WORDS_MIN || word_count > BIP39_WORDS_MAX || word_count % 3 != 0) return false;

    uint16_t indices[word_count];
    p = mnemonic;
    for (int i = 0; i < word_count; i++) {
        int len = 0;
        char word[16];
        while (*p && *p != ' ') {
            if (len < sizeof(word) - 1) word[len++] = *p++;
        }
        word[len] = '\0';
        if (*p == ' ') p++;

        int ndx = -1;
        for (int j = 0; j < 2048; j++) {
            if (strcmp(word, bip39_wordlist[j]) == 0) {
                ndx = j;
                break;
            }
        }
        if (ndx < 0) return false;
        indices[i] = ndx;
    }

    unsigned int total_bits = word_count * 11;
    unsigned int entropy_bits;
    switch (word_count) {
        case 12: entropy_bits = 128; break;
        case 15: entropy_bits = 160; break;
        case 18: entropy_bits = 192; break;
        case 21: entropy_bits = 224; break;
        case 24: entropy_bits = 256; break;
        default: return false;
    }
    unsigned int checksum_bits = entropy_bits / 32;
    size_t entropy_len = entropy_bits / 8;
    size_t total_bytes = (total_bits + 7) / 8;

    uint8_t concat[total_bytes];
    memset(concat, 0, total_bytes);
    for (int i = 0; i < word_count; i++) {
        uint32_t value = indices[i];
        for (int j = 0; j < 11; j++) {
            int bit_pos = i * 11 + j;
            int byte_pos = bit_pos / 8;
            int bit_offset = bit_pos % 8;
            if (value & (1 << (10 - j))) {
                concat[byte_pos] |= 1 << (7 - bit_offset);
            }
        }
    }

    uint8_t entropy[entropy_len];
    memcpy(entropy, concat, entropy_len);

    //print_hex(entropy, entropy_len, "entropy");
    
    uint8_t hash[SHA256_DIGEST_SIZE];
    HashState sha; //TODO: I'm getting memory errors making this a static hides them for now...
    sha256Begin(&sha);
    for (int i = 0; i < entropy_len; i++)
	{
		sha256WriteByte(&sha, entropy[i]);
	}
    sha256Finish(&sha);
    
    uint32_to_uint8_byteswap(sha.h, hash, 8);

    //print_hex(hash, 32, "hash");
    
    uint8_t checksum_mask = (1 << checksum_bits) - 1;
    uint8_t actual_checksum = (concat[total_bytes - 1] >> (8 - checksum_bits)) & checksum_mask;
    uint8_t expected_checksum = hash[0] >> 4;

    //printf("expected %02x vs %02x\n", expected_checksum, actual_checksum);
    
    return actual_checksum == expected_checksum;
}

int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed, size_t seed_len) {
    if (!mnemonic || !seed || seed_len < BIP39_SEED_LEN) return -1;
    if (!passphrase) passphrase = ""; // Default empty passphrase

    const char *salt_prefix = "mnemonic";
    size_t salt_len = strlen(salt_prefix) + strlen(passphrase);
    uint8_t salt[salt_len];
    memcpy(salt, salt_prefix, strlen(salt_prefix));
    memcpy(salt + strlen(salt_prefix), passphrase, strlen(passphrase));

    pbkdf2(seed, (const uint8_t *)mnemonic, strlen(mnemonic), salt, salt_len);
    
    return 0;

}
