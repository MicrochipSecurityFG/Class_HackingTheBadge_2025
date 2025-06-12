/* ************************************************************************** */
/** Descriptive File Name

  @Company
    Company Name

  @File Name
    filename.h

  @Summary
    Brief description of the file.

  @Description
    Describe the purpose of this file.
 */
/* ************************************************************************** */

#ifndef _BITCOIN_UTIL_H    /* Guard against multiple inclusion */
#define _BITCOIN_UTIL_H
#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include "ecdsa.h"
#include "bip32.h"
#include "bip39.h"
#include "sha256.h"
#include "ripemd160.h"
#include "bignum256.h"
#include "ripemd160.h"

typedef struct {
    uint64_t value;
    uint8_t* pubkey_hash_ptr;  // Points to start of this output (value + script)
} BitcoinTxOutputInfo;

#define MAX_INPUTS 4
#define MAX_OUTPUTS 4

typedef struct {
    uint8_t* input_tx_hashes[MAX_INPUTS];
    uint32_t num_inputs;
    uint8_t* locktime;
    uint8_t* outputs[MAX_OUTPUTS];  // still fine to keep this if needed
    BitcoinTxOutputInfo output_info[MAX_OUTPUTS];
    uint32_t num_outputs;
} BitcoinTxParseResult;

typedef struct {

	bool isLoaded; //if master_node and name hmac check ok
	uint8_t master_node[NODE_LENGTH]; //hmac out, master secret
	uint8_t main_account_parent_node[NODE_LENGTH];
	uint8_t change_account_parent_node[NODE_LENGTH];
	char words[128];
	char name[5]; //hmac master_node

} WALLET_t;
#define PUBKEY_LEN 33
#define TESTNET_VPUB_VERSION 0x045F1CF6 // vpub m/84'/1'

#define XPRV_VERSION        0x0488ADE4  // Mainnet private key version (little-endian)
#define DEPTH_OFFSET        4
#define FINGERPRINT_OFFSET  5
#define CHILD_NUM_OFFSET    9
#define CHAINCODE_OFFSET    13
#define KEY_OFFSET          45
#define CHECKSUM_OFFSET     78
#define SERIALIZED_LEN      82
#define CHAINCODE_LEN       32
#define KEY_LEN             32
#define CHECKSUM_LEN        4
#define SHA256_DIGEST_SIZE  32

void derive_testnet_public_key(const uint8_t *private_key, uint8_t * compressedpubkey, uint8_t * x, uint8_t * y);
void derive_testnet_public_hash(const uint8_t *compressedpubkey, uint8_t * digest20);
void derive_testnet_address(const uint8_t *digest20, uint8_t *address);
void derive_testnet_public_address(const uint8_t *private_key, uint8_t * address43);

void bech32_create_checksum(const char *hrp, uint8_t *data, size_t data_len, uint8_t *checksum);
int calculate_master_xpub(uint8_t * node, unsigned char *xpub_out, size_t xpub_out_len);

void encode_base58check(const uint8_t* data, size_t len, char* output);
void reverse_bytes(uint8_t *dest, const uint8_t *src, size_t len);
int sign_p2wpkh_input(BitcoinTxParseResult* tx_parse,
                      const uint8_t* privkey,
                      uint8_t* prev_amount,
                      uint8_t* prev_pubkeyhash,
					  uint8_t  prev_input_tx_nummber, //which input in the tx to sign
                      uint8_t* sig_out,
                      size_t* sig_len
					  );
int serialize_extended_key(uint32_t version, const unsigned char *key, const unsigned char *chain_code,
                           unsigned char *xkey_out, size_t xkey_out_len, int is_private_key);
int parse_bitcoin_tx(uint8_t* tx_data, size_t tx_size, BitcoinTxParseResult* result);
void uint64_to_le_bytes(uint64_t value, uint8_t* bytes);
void hash_outputs(BitcoinTxParseResult* tx_parse, uint8_t* msg, size_t* pos);
bool BTC_RestoreWallet(const char* mnemonic, char* passphrase, WALLET_t *w);

#endif /* _BITCOIN_UTIL_H */

/* *****************************************************************************
 End of File
 */
