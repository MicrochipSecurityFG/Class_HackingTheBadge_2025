#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "bitcoin_util.h"

uint32_t path[4] = {0x80000054, 0x80000001, 0x80000000, 0};
#define PUBKEY_LEN 33
extern WALLET_t wallet;

#define TX_PARSE_OK 0
#define TX_PARSE_INVALID_INPUT 1
#define TX_PARSE_TOO_MANY_INPUTS 2
#define TX_PARSE_TOO_MANY_OUTPUTS 3

// DER-encode r and s (manual implementation)
size_t der_encode_signature(const BigNum256 r, const BigNum256 s, uint8_t *out) {
    size_t pos = 0;
    uint8_t r_len = 32, s_len = 32;
    int r_pad = (r[0] & 0x80) ? 1 : 0; // Pad if high bit is set
    int s_pad = (s[0] & 0x80) ? 1 : 0;

    out[pos++] = 0x30; // Sequence tag
    out[pos++] = 4 + r_len + r_pad + s_len + s_pad; // Total length
    out[pos++] = 0x02; // Integer tag for r
    out[pos++] = r_len + r_pad; // r length
    if (r_pad) out[pos++] = 0x00; // Leading zero if needed
    memcpy(out + pos, r, r_len); pos += r_len;
    out[pos++] = 0x02; // Integer tag for s
    out[pos++] = s_len + s_pad; // s length
    if (s_pad) out[pos++] = 0x00; // Leading zero if needed
    memcpy(out + pos, s, s_len); pos += s_len;

    return pos;
}

// Helper function to print the path array (assuming it exists elsewhere)
void print_path_array(uint32_t *path, size_t len) {
    printf("Parsed path array: {");
    for (size_t i = 0; i < len; i++) {
        printf("0x%08x", (unsigned int)path[i]);
        if (i < len - 1) printf(", ");
    }
    printf("}\n");
}

int sign_p2wpkh_input(BitcoinTxParseResult* tx_parse,
                      const uint8_t* privkey,
                      uint8_t* prev_amount,
                      uint8_t* prev_pubkeyhash,
					  uint8_t  prev_input_tx_nummber, //which input in the tx to sign
                      uint8_t* sig_out,
                      size_t* sig_len
					  ) {
    uint8_t sighash[32], msg[512], r[32], s[32], key_buffer[32];
    size_t pos = 0;
    uint8_t script_code[] = {0x19, 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac};

    // Input validation
    if (!tx_parse || !privkey || !prev_amount || !prev_pubkeyhash ||
        !sig_out || !sig_len || tx_parse->num_inputs == 0) {
        printf("sign_p2wpkh_input input error\n");
    	return 1;
    }

    // Prepare script code and private key
    memcpy(&script_code[4], prev_pubkeyhash, 20);
    memcpy(key_buffer, privkey, 32);
    swapEndian256(key_buffer);

    //print_hex(prev_amount, 8, "prev_amount");
    //print_hex(prev_pubkeyhash, 20, "prev_pubkeyhash");

	// 1. nVersion (hardcoded as 01000000)
	uint8_t version[] = { 0x01, 0x00, 0x00, 0x00 };
	memcpy(msg, version, 4);
	pos += 4;
	//print_hex(msg, 4, "nVersion");

    // 2. hashPrevouts
    uint8_t prevout[36];
    memcpy(prevout, tx_parse->input_tx_hashes[prev_input_tx_nummber], 32);  // TXID
    memcpy(prevout + 32, tx_parse->input_tx_hashes[prev_input_tx_nummber] + 32, 4);  // vout
    sha256Double(prevout, 36, msg + pos);
    pos += 32;
    //print_hex(prevout, 36, "prevout");
    //print_hex(msg + pos - 32, 32, "hashPrevouts");

    // 3. hashSequence (sequence is 4 bytes after txid + vout + scriptlen)
    uint8_t sequence[4];
    uint8_t script_len = *(tx_parse->input_tx_hashes[prev_input_tx_nummber] + 36);  // Assuming compact size of 1 byte
    memcpy(sequence, tx_parse->input_tx_hashes[prev_input_tx_nummber] + 37 + script_len, 4);
    sha256Double(sequence, 4, msg + pos);
    pos += 32;
    //print_hex(sequence, 4, "sequence");
    //print_hex(msg + pos - 32, 32, "hashSequence");

    // 4. outpoint (same as prevout)
    memcpy(msg + pos, prevout, 36);
    pos += 36;

    // 5. scriptCode
    memcpy(msg + pos, script_code, sizeof(script_code));
    pos += sizeof(script_code);

    // 6. amount
    memcpy(msg + pos, prev_amount, 8);
    pos += 8;

    // 7. nSequence (same as above)
    memcpy(msg + pos, sequence, 4);
    pos += 4;

    // 8. hashOutputs
    hash_outputs(tx_parse, msg, &pos);

    // 9. nLockTime
    memcpy(msg + pos, tx_parse->locktime, 4);
    pos += 4;
    //print_hex(msg + pos - 4, 4, "nLockTime");

    // 10. sighashType
    uint8_t sighash_type[] = {0x01, 0x00, 0x00, 0x00};
    memcpy(msg + pos, sighash_type, 4);
    pos += 4;

    // Compute sighash
    sha256Double(msg, pos, sighash);
    //print_hex(sighash, 32, "sighash");
    //print_hex(msg, pos, "msg");

    // Sign
    swapEndian256(sighash);  // To little-endian
    ecdsaSign(r, s, sighash, key_buffer);
    swapEndian256(r);  // To big-endian
    swapEndian256(s);  // To big-endian
    *sig_len = der_encode_signature(r, s, sig_out);

    return 0;
}


// Helper function to convert uint64_t to little-endian 8-byte array
void uint64_to_le_bytes(uint64_t value, uint8_t* bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[i] = (value >> (i * 8)) & 0xFF;
    }
}

void process_derivation_path(uint32_t *path, size_t max_len, size_t *path_len) {
    char input_buffer[256];  // Buffer for path input

    // Initialize path_len to 0
    *path_len = 0;

    // Prompt for derivation path
    printf("Enter signing key path (e.g., m/84'/1'/0'/0/0): ");
    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        printf("Error reading path\n");
        return;
    }
    input_buffer[strcspn(input_buffer, "\n")] = 0;  // Remove newline

    // Check for 'm/' prefix
    if (strncmp(input_buffer, "m/", 2) != 0) {
        printf("Invalid path format: Must start with 'm/'\n");
        return;
    }

    // Tokenize the path by '/'
    char *token = strtok(input_buffer + 2, "/");  // Skip 'm/'
    while (token != NULL && *path_len < max_len) {
        uint32_t index;
        int is_hardened = 0;

        // Check if the index is hardened (ends with ')
        size_t len = strlen(token);
        if (len > 0 && token[len - 1] == '\'') {
            is_hardened = 1;
            token[len - 1] = '\0';  // Remove the ' for parsing
        }

        // Parse the number
        if (sscanf(token, "%u", (unsigned int *)&index) != 1) {
            printf("Invalid index in path: %s\n", token);
            return;
        }

        // Apply hardening if applicable
        if (is_hardened) {
            index |= 0x80000000;  // Add hardening bit
        }

        path[*path_len] = index;
        (*path_len)++;  // Increment the caller's path_len
        token = strtok(NULL, "/");
    }

    if (*path_len == 0) {
        printf("No valid indices found in path\n");
        return;
    }

    // Print the resulting array
    print_path_array(path, *path_len);
}

// Function to handle the outputs hashing
void hash_outputs(BitcoinTxParseResult* tx_parse, uint8_t* msg, size_t* pos) {
    // For P2WPKH outputs, each output is typically:
    // 8 bytes value + 1 byte script len + 22 bytes scriptPubKey = 31 bytes
    // But we need to calculate actual length since script length can vary
    uint8_t outputs_buffer[31 * MAX_OUTPUTS]; // Max size for P2WPKH outputs
    size_t out_pos = 0;

    for (uint32_t i = 0; i < tx_parse->num_outputs; i++) {
        if (i >= MAX_OUTPUTS) break; // Safety check

        // Get the script length from the output
        uint8_t* output = tx_parse->outputs[i];
        uint8_t script_len = output[8]; // Script length is after 8-byte value

        // Total length = 8 bytes value + 1 byte length + script data
        size_t output_len = 8 + 1 + script_len;

        // Check if we have enough space
        if (out_pos + output_len > sizeof(outputs_buffer)) {
            printf("Error: Outputs buffer overflow\n");
            return;
        }

        // Copy the full output (value + scriptPubKey)
        memcpy(outputs_buffer + out_pos, output, output_len);
        out_pos += output_len;
    }

    // Double SHA256 hash of the outputs
    if (out_pos > 0) {  // Only hash if we have data
        sha256Double(outputs_buffer, out_pos, msg + *pos);
        *pos += 32;

        // Debug printing
        //print_hex(outputs_buffer, out_pos, "outputs");
        //print_hex(msg + *pos - 32, 32, "hashOutputs");
    }
}

int parse_bitcoin_tx(uint8_t* tx_data, size_t tx_size, BitcoinTxParseResult* result);

// Bech32 functions
uint32_t bech32_polymod(uint8_t *values, size_t len) {
    const uint32_t GEN[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[i];
        for (int j = 0; j < 5; j++) {
            chk ^= ((b >> j) & 1) ? GEN[j] : 0;
        }
    }
    return chk;
}

void bech32_hrp_expand(const char *hrp, uint8_t *out, size_t *out_len) {
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; i++) {
        out[i] = hrp[i] >> 5;
    }
    out[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        out[hrp_len + 1 + i] = hrp[i] & 31;
    }
    *out_len = hrp_len * 2 + 1;
}

int parse_bitcoin_tx(uint8_t* tx_data, size_t tx_size, BitcoinTxParseResult* result) {
    if (!result) return TX_PARSE_INVALID_INPUT;
    *result = (BitcoinTxParseResult){0};

    if (!tx_data || tx_size < 4) return TX_PARSE_INVALID_INPUT;

    size_t offset = 0;
    offset += 4;  // Skip version

    // Check for segwit marker and flag
    if (tx_data[4] == 0x00 && tx_data[5] == 0x01) {
        offset += 2;  // Skip marker and flag
    }

    uint32_t num_inputs = 0;
    if (tx_data[offset] < 0xfd) {
        num_inputs = tx_data[offset];
        offset += 1;
    } else if (tx_data[offset] == 0xfd) {
        num_inputs = *(uint16_t*)(tx_data + offset + 1);
        offset += 3;
    } else if (tx_data[offset] == 0xfe) {
        num_inputs = *(uint32_t*)(tx_data + offset + 1);
        offset += 5;
    }

    if (num_inputs > MAX_INPUTS) {
        return TX_PARSE_TOO_MANY_INPUTS;
    }
    result->num_inputs = num_inputs;

    for (uint32_t i = 0; i < result->num_inputs; i++) {
        result->input_tx_hashes[i] = tx_data + offset;
        offset += 32;  // TX hash
        offset += 4;   // Vout
        uint32_t script_len = 0;
        if (tx_data[offset] < 0xfd) {
            script_len = tx_data[offset];
            offset += 1;
        } else if (tx_data[offset] == 0xfd) {
            script_len = *(uint16_t*)(tx_data + offset + 1);
            offset += 3;
        } else if (tx_data[offset] == 0xfe) {
            script_len = *(uint32_t*)(tx_data + offset + 1);
            offset += 5;
        }
        offset += script_len;
        offset += 4;  // Sequence
    }

    uint32_t num_outputs = 0;
    if (tx_data[offset] < 0xfd) {
        num_outputs = tx_data[offset];
        offset += 1;
    } else if (tx_data[offset] == 0xfd) {
        num_outputs = *(uint16_t*)(tx_data + offset + 1);
        offset += 3;
    } else if (tx_data[offset] == 0xfe) {
        num_outputs = *(uint32_t*)(tx_data + offset + 1);
        offset += 5;
    }

    if (num_outputs > MAX_OUTPUTS) {
        return TX_PARSE_TOO_MANY_OUTPUTS;
    }
    result->num_outputs = num_outputs;

    for (uint32_t i = 0; i < result->num_outputs; i++) {
        uint8_t* output_start = tx_data + offset;
        result->outputs[i] = output_start;  // optional legacy pointer
        result->output_info[i].pubkey_hash_ptr = output_start + 11; //point to start of pubkey hash (20 bytes)

        // Parse 8-byte little-endian value
        uint64_t value = 0;
        for (int j = 0; j < 8; j++) {
            value |= ((uint64_t)tx_data[offset + j]) << (8 * j);
        }
        result->output_info[i].value = value;
        offset += 8;

        uint32_t script_len = 0;
        if (tx_data[offset] < 0xfd) {
            script_len = tx_data[offset];
            offset += 1;
        } else if (tx_data[offset] == 0xfd) {
            script_len = *(uint16_t*)(tx_data + offset + 1);
            offset += 3;
        } else if (tx_data[offset] == 0xfe) {
            script_len = *(uint32_t*)(tx_data + offset + 1);
            offset += 5;
        }
        offset += script_len;
    }

    if (offset + 4 <= tx_size) {
        result->locktime = tx_data + offset;
    }

    return TX_PARSE_OK;
}

// Function to reverse byte order, safe for dest == src
void reverse_bytes(uint8_t *dest, const uint8_t *src, size_t len) {
    // If dest and src are the same, use a temporary buffer
    if (dest == src) {
        uint8_t *temp = malloc(len);
        if (temp == NULL) {
            // Handle memory allocation failure (optional: could abort or return)
            return;
        }

        // Reverse into temp
        for (size_t i = 0; i < len; i++) {
            temp[i] = src[len - 1 - i];
        }

        // Copy back to dest
        memcpy(dest, temp, len);

        free(temp);
    } else {
        // If dest and src are different, reverse directly
        for (size_t i = 0; i < len; i++) {
            dest[i] = src[len - 1 - i];
        }
    }
}

void encode_base58check(const uint8_t* data, size_t len, char* output) {
    const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t temp[82];
    memcpy(temp, data, len);

    size_t leading_zeros = 0;
    while (leading_zeros < len && temp[leading_zeros] == 0) leading_zeros++;

    uint8_t result[114] = {0};
    size_t result_len = 0;
    uint64_t carry;

    for (size_t i = 0; i < len; i++) {
        carry = temp[i];
        for (size_t j = 0; j < result_len || carry; j++) {
            if (j >= result_len) result_len++;
            carry += (uint64_t)(result[j]) * 256;
            result[j] = carry % 58;
            carry /= 58;
        }
    }

    size_t out_pos = 0;
    for (size_t i = 0; i < leading_zeros; i++) output[out_pos++] = '1';
    for (size_t i = 0; i < result_len; i++) {
        output[out_pos++] = alphabet[result[result_len - 1 - i]];
    }
    output[out_pos] = '\0';
}

void bech32_create_checksum(const char *hrp, uint8_t *data, size_t data_len, uint8_t *checksum) {
    uint8_t hrp_expanded[10]; // "tb" -> 5 bytes max
    size_t hrp_exp_len;
    bech32_hrp_expand(hrp, hrp_expanded, &hrp_exp_len);

    uint8_t values[50]; // Max reasonable size for hrp + data + 6 checksum bytes

    memcpy(values, hrp_expanded, hrp_exp_len);
    memcpy(values + hrp_exp_len, data, data_len);
    memset(values + hrp_exp_len + data_len, 0, 6);

    uint32_t polymod = bech32_polymod(values, hrp_exp_len + data_len + 6) ^ 1;
    for (int i = 0; i < 6; i++) {
        checksum[i] = (polymod >> 5 * (5 - i)) & 31;
    }
}

void convertbits(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len, int frombits, int tobits, int pad) {
    uint32_t acc = 0;
    int bits = 0;

    size_t pos = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out[pos++] = (acc >> bits) & ((1 << tobits) - 1);
        }
    }
    if (pad && bits) {
        out[pos++] = (acc << (tobits - bits)) & ((1 << tobits) - 1);
    }
    *out_len = pos;
}

void bech32_encode(char *output, const char *hrp, uint8_t *data, size_t data_len) {
    const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint8_t checksum[6];
    bech32_create_checksum(hrp, data, data_len, checksum);

    size_t hrp_len = strlen(hrp);
    memcpy(output, hrp, hrp_len);
    output[hrp_len] = '1';

    for (size_t i = 0; i < data_len; i++) {
        output[hrp_len + 1 + i] = charset[data[i]];
    }
    for (size_t i = 0; i < 6; i++) {
        output[hrp_len + 1 + data_len + i] = charset[checksum[i]];
    }
    output[hrp_len + 1 + data_len + 6] = '\0';
}

void test_vector_xpub(void) {

	//uint8_t seed[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    //print_hex(seed, sizeof(seed), "seed");

    ////uint8_t node[64];

    //bip32SeedToNode(node, seed, sizeof (seed));

    //ok need to modify my code to use a path depth of "'m/'0"
	//I think the issue was calculating the finger print of the parent while iterating
	//so in serialize_extended_key i need to look at fingerprint setting....
	//Chain m/0H ext pub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw
    //uint32_t path2[4] = {0x80000000, 0x80000001, 0x80000000, 0};
    uint8_t private[32];
	bip32DerivePrivate(private, &wallet.master_node[32], wallet.master_node, path, 2); //get parent for path

    uint8_t xbpub_out[112];
    calculate_master_xpub(private, xbpub_out, 112);
    //printf("Done\n");
}

// Function to calculate master xpub from a seed
int calculate_master_xpub(uint8_t * node, unsigned char *xpub_out, size_t xpub_out_len) {
    // Constants
    unsigned char master_pub_key[PUBKEY_LEN];  // Compressed public key (33 bytes)
    uint8_t buffer[32];

    PointAffine pub_point;                      // Curve point for public key

    // Step 3: Set up secp256k1 field (if required by your library)
    setFieldToN();  // Initialize secp256k1 field parameters

    // Step 4: Generate public key from private key
    setToG(&pub_point);
    reverse_bytes(buffer, node, 32);
    pointMultiply(&pub_point, buffer);  // Multiply G by private key

    // Step 5: Serialize public key (compressed, 33 bytes)
    if (ecdsaSerialise(master_pub_key, &pub_point, true) != PUBKEY_LEN) {
        printf("Failed to serialize public key\n");
        return -1;
    }

    // Step 6: Serialize to xpub
    //print_hex(master_pub_key, PUBKEY_LEN, "master_pub_key");
    int result = serialize_extended_key(TESTNET_VPUB_VERSION, master_pub_key, &node[32], xpub_out, xpub_out_len, 0);

    if (result < 0) {
        printf("Failed to serialize extended public key\n");
        return -1;
    }

    printf("Serialize Public Key: \n\n%s\n", xpub_out);

    return result;  // Length of xpub string or error code
}

// Function to serialize and encode an extended key (xprv or xpub)
int serialize_extended_key(uint32_t version, const unsigned char *key, const unsigned char *chain_code,
                           unsigned char *xkey_out, size_t xkey_out_len, int is_private_key) {

    unsigned char serialized_xkey[SERIALIZED_LEN] = {0};
    unsigned char checksum[SHA256_DIGEST_SIZE];

    // Validate inputs
    if (!key || !chain_code || !xkey_out) {
        fprintf(stderr, "Error: Null input pointers\n");
        return -1;
    }
    if (xkey_out_len < 112) {  // Base58-encoded xkey is typically 111-112 chars
        fprintf(stderr, "Error: Output buffer too small (need >= 112 bytes)\n");
        return -1;
    }

    // 1. Serialize the extended key
    // Version (4 bytes)
    serialized_xkey[0] = (version >> 24) & 0xFF;
    serialized_xkey[1] = (version >> 16) & 0xFF;
    serialized_xkey[2] = (version >> 8) & 0xFF;
    serialized_xkey[3] = version & 0xFF;

    // Depth (1 byte, 0 for master)
    serialized_xkey[DEPTH_OFFSET] = 3;

    // Parent fingerprint (4 bytes, 0 for master)
    memset(serialized_xkey + FINGERPRINT_OFFSET, 0, 4);

    // Child number (4 bytes, 0 for master)
    uint32_t child = 0x80000000;
    serialized_xkey[CHILD_NUM_OFFSET + 0] = (child >> 24) & 0xFF;
    serialized_xkey[CHILD_NUM_OFFSET + 1] = (child >> 16) & 0xFF;
    serialized_xkey[CHILD_NUM_OFFSET + 2] = (child >> 8) & 0xFF;
    serialized_xkey[CHILD_NUM_OFFSET + 3] = child & 0xFF;

    // Chain code (32 bytes)
    memcpy(serialized_xkey + CHAINCODE_OFFSET, chain_code, CHAINCODE_LEN);

    if (is_private_key) {
        // XPRV: Add padding byte (1 byte)
        serialized_xkey[KEY_OFFSET] = 0x00;
        // Copy private key (32 bytes)
        memcpy(serialized_xkey + KEY_OFFSET + 1, key, KEY_LEN);
    } else {
        // XPUB: Copy compressed public key (33 bytes)
        memcpy(serialized_xkey + KEY_OFFSET, key, PUBKEY_LEN);
    }

    // 2. Compute checksum (double SHA-256)
    sha256Double(serialized_xkey, CHECKSUM_OFFSET, checksum);
    //print_hex(checksum, 32, "checksum");

    // Append first 4 bytes of checksum
    memcpy(serialized_xkey + CHECKSUM_OFFSET, checksum, CHECKSUM_LEN);

    //print_hex(serialized_xkey, SERIALISED_BIP32_KEY_LENGTH, "serialized_xkey");

    // 3. Encode to Base58Check
    encode_base58check((const unsigned char*)serialized_xkey, SERIALIZED_LEN, (char*)xkey_out);

    return 0;  // Success
}

void derive_testnet_public_address(const uint8_t *private_key, uint8_t * address43) {
	 uint8_t compressedpubkey[33];
	 uint8_t digest[32];
	 derive_testnet_public_key(private_key, compressedpubkey, NULL, NULL);
	 derive_testnet_public_hash(compressedpubkey, digest);
	 derive_testnet_address(digest, address43);
}

void derive_testnet_public_key(const uint8_t *private_key, uint8_t * compressedpubkey, uint8_t * x, uint8_t * y) {
    uint8_t reversed_key[32];
    uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE];
    uint8_t serialised_size;

    PointAffine out_public_key;

    // Input private key
    memcpy(reversed_key, private_key, 32);

    // Reverse byte order
    reverse_bytes(reversed_key, private_key, 32);

    // Calculate public key
    setToG(&out_public_key);
    pointMultiply(&out_public_key, reversed_key);
    serialised_size = ecdsaSerialise(serialised, &out_public_key, true);
    if (serialised_size < 2) {
        printf("Serialised size error: %d\n", serialised_size);
        while (1);
    }

    swapEndian256(out_public_key.x);
    swapEndian256(out_public_key.y);

    if(x != NULL) memcpy(x, out_public_key.x, 32);
    if(y != NULL) memcpy(y, out_public_key.y, 32);
    if(compressedpubkey != NULL) memcpy(compressedpubkey, serialised, 33);

    return;
}

void derive_testnet_public_hash(const uint8_t *compressedpubkey, uint8_t * digest20) {

	// SHA256 hash
	uint8_t buffer[32];
    sha256((uint8_t *)compressedpubkey, 33, buffer);

    // RIPEMD160 hash
    HashState hs;
    ripemd160Begin(&hs);
    for (int i = 0; i < 32; i++) {
        ripemd160WriteByte(&hs, buffer[i]);
    }
    ripemd160Finish(&hs);
    writeHashToByteArray(digest20, &hs, true);
    //print_hex(digest20, 20, "RIPEMD160 Hash");

    return;
}

void derive_testnet_address(const uint8_t *digest20, uint8_t *address) {
    // Bech32 encoding
    uint8_t witness_data[40];
    size_t witness_data_len;
    witness_data[0] = 0; // Witness version 0
    convertbits(witness_data + 1, &witness_data_len, digest20, 20, 8, 5, 1);
    witness_data_len += 1; // Include version byte

    bech32_encode((char*)address, "tb", witness_data, witness_data_len);
    //printf("Testnet Address: %s\n", address);

}
