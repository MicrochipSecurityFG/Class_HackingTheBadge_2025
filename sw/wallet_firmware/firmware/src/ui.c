/* ************************************************************************** */
/** Descriptive File Name

  @Company
    Company Name

  @File Name
    filename.c

  @Summary
    Brief description of the file.

  @Description
    Describe the purpose of this file.
 */
/* ************************************************************************** */

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

/* This section lists the other files that are included in this file.
 */
#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include "lcd_menu.h"
#include "cryptoauthlib.h"
#include "secure_element.h"
#include "ui.h"
#include "util.h"
#include "ir.h"
#include "bitcoin_util.h"
#include "multi_comm.h"
 
#define MAX_RAW_TX_SIZE 256  // Fixed size for raw transaction in bytes (adjust as needed)
#define MAX_HEX_INPUT_SIZE (MAX_RAW_TX_SIZE * 2 + 1)  // Hex string length + null terminator
 
//Brad Code

long timestamp() {
    static long fake_time = 0;
    return ++fake_time; // Increments each time it's called to simulate passage of time
}

int strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) {
        //correct character accepted
        AUDIT_LOG("[Audit @ %ld] Correct character accepted.\r\n", timestamp());        
        a++;
        b++;
    }
    return *(unsigned char *)a - *(unsigned char *)b;
}
//End Brad Code
#define NODE_LENGTH		64

extern WALLET_t wallet;
extern rx_t rx;
extern char secretPassword[];

uint8_t passwordAttackState = 0;

char ui_screen_text[128] = {0};

#define DEBUG_BUFFER_SIZE 40
#define DEBUG_PRINT(...)                     \
    do {                                      \
        char dbg_buf[DEBUG_BUFFER_SIZE];      \
        snprintf(dbg_buf, sizeof(dbg_buf), __VA_ARGS__); \
		/*printf("%s", dbg_buf);*/                \
    } while (0)


void print_hex(const uint8_t* data, size_t len, const char* label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper function to convert hex string to byte array
int hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0 || len / 2 > max_len) return -1;  // Invalid length
    for (size_t i = 0; i < len / 2; i++) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) return -1;
    }
    return len / 2;
}

void hex_string_to_bytes(const char *hex, uint8_t *out, size_t *out_len) {
    size_t len = strlen(hex);
    *out_len = len / 2;

    for (size_t i = 0; i < *out_len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &out[i]);
    }
}

void UI_CLI_IrPower(void) {

    char input[32] = {0};

    printf("Current IR Power: %ld\n", ir_power);
    printf("New IR Power raw count (631 50%%): ");
    fgets(input, sizeof (input), stdin);

    if (sscanf(input, "%lu", (unsigned long *)&ir_power) == 1) {
        printf("New Power %lu\n", (unsigned long)ir_power);
    } else {
        printf("\nInvalid input format. Expected number\n");
    }

    printf("\n");

}

void UI_SaveWallet(void) {
	//TODO
}

void UI_CLI_ResetLimit(void) {

    ATCA_STATUS status = ATCA_SUCCESS;
    uint32_t counterValue = 0;
    status = atcab_counter_read(0, &counterValue);
    CHECK_STATUS(status);

    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 5, 0, (uint8_t*)&counterValue, 4);
    CHECK_STATUS(status);

}

void UI_IrIncrease() {
    static char text[48] = "this is a test of displaying some data";
    ir_power += 20;

    if(ir_power > 600) ir_power = 600;
    
    TCC2_REGS->TCC_CC[0] = ir_power;
    while (TCC2_REGS->TCC_SYNCBUSY != 0U);
    sprintf(text, "Power +     %lu", (unsigned long)ir_power);
    printf("IR Power : %lu", (unsigned long)ir_power);
    printf("\n");
    settingsSubMenu[0].displayText = text;
    //buffer_to_display(text, strlen(text));    
}

void UI_IrDecrease() {
    static char text[48] = "this is a test of displaying some data";
    ir_power -= 20;
    
    if(ir_power > 600) ir_power = 0;
    
    TCC2_REGS->TCC_CC[0] = ir_power;
    while (TCC2_REGS->TCC_SYNCBUSY != 0U);
    sprintf(text, "Power +     %lu", ir_power);
    printf("IR Power : %lu", ir_power);
    printf("\n");
    settingsSubMenu[0].displayText = text;
    //buffer_to_display(text, strlen(text));    
}

void UI_IrMenuSendMessageExit(char * message) {
    IR_SendMessage(message, 0, NULL);
}

void UI_IrMenuSendMessage() {
    static char text[48] = "test 1234";

    LCD_MENU_RegisterDataEntryExit(UI_IrMenuSendMessageExit);
    LCD_MENU_BufferToDisplayText(text, strlen(text), MENU_MODE_DATA_ENTRY);
}

void format_mnemonic_flat(const char *input, char output[126]) {
    char words[12][9];
    int word_count = 0;

    char buffer[256] = {0};
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *token = strtok(buffer, " ");
    while (token && word_count < 12) {
        strncpy(words[word_count], token, 8);
        words[word_count][8] = '\0';
        token = strtok(NULL, " ");
        word_count++;
    }

    char *ptr = output;
    for (int i = 0; i < 6; i++) {
        int written = sprintf(ptr, "%d.%s %d.%s\n",
                              i * 2 + 1, words[i * 2],
                              i * 2 + 2, words[i * 2 + 1]);
        ptr += written;
    }
}

void UI_CreateLogin(void) {

	int error = bip39_generate_mnemonic(wallet.words);

	if(error) {
		printf("error %d", error);
        return;
	}

	format_mnemonic_flat(wallet.words, ui_screen_text);
    
	LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
    LCD_MENU_EnterSubMenu();
}

void UI_CLI_RestoreWalletFromWords(void) {
    char mnemonic[256] = {0};
    char passphrase[256] = {0};

    printf("Load wallet from words\n");

    printf("Enter mnemonic phrase (12 or 24 words): ");
    if (!MULTI_COMM_GetLine(mnemonic, sizeof(mnemonic))) {
        printf("\nError reading mnemonic.\n");
        return;
    }

#if 0
    printf("Enter passphrase: ");
    if (!MULTI_COMM_GetLine(passphrase, sizeof(passphrase))) {
        printf("\nError reading passphrase.\n");
        return;
    }
#endif

    if (BTC_RestoreWallet(mnemonic, passphrase, &wallet)) {
        printf("Wallet restored successfully.\n");
    } else {
        printf("Failed to restore wallet.\n");
    }
}

void UI_RestoreWalletFromPIN(void) {

	LCD_MENU_EnterSubMenu();

    //add read PIN menu
    SECURE_ELEMENT_ReadSlot8((uint8_t *)&wallet, sizeof(wallet));

    bool valid = bip39_validate_mnemonic(wallet.words);
    
    if(!valid) {
    	memset(&wallet, 0x00, sizeof(wallet));

        sprintf(ui_screen_text, "Failed to load");
        LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
        LCD_MENU_RefreshScreen();
        return;
    }
    
    sprintf(ui_screen_text, "Wallet: %s\nClick here to load", wallet.name);
    
    MenuItem item;
    item.subMenu = accountMenu; //enable dynamic here
    item.action = LCD_MENU_Init_Account;
    LCD_MENU_Set_MenuItem(&item, 1); //update second menu row to send user to account view
    
    LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
}

void UI_ShowWords(void) {
    
    LCD_MENU_EnterSubMenu();
    
    format_mnemonic_flat(wallet.words, ui_screen_text);
    LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
}

void UI_CLI_ExportAccountPublicKey(void) {
    printf("Exporting XPUB...\n");

    //print_hex(wallet.master_node, 64, "wallet.master_node");
    uint32_t path[4] = {0x80000054, 0x80000001, 0x80000000, 0};

    uint8_t node[64];
	bip32DerivePrivate(node, &node[32], wallet.master_node, path, 3); //get parent for path

	//print_hex(node, 64, "node");

    uint8_t xbpub_out[112];
    calculate_master_xpub(node, xbpub_out, 112);
    //printf("Done\n");
}

void UI_ExportPublicKey(void) {
    
    uint32_t path[4] = {0x80000054, 0x80000001, 0x80000000, 0};
    
    LCD_MENU_EnterSubMenu();
    printf("Exporting XPUB...\n");

    LCD_MENU_DisplayTextBuffer("wait...", 0);
    LCD_MENU_RefreshScreen();

    uint8_t node[64];
	bip32DerivePrivate(node, &node[32], wallet.master_node, path, 3); //get parent for path

	//print_hex(node, 64, "node");

    calculate_master_xpub(node, (unsigned char *)ui_screen_text, 112);
    
    LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);  
}

void UI_RestoreWalletFromWords(void) {
    char passphrase[8] = {0};
    static char text[128] = {0};
    
    LCD_MENU_EnterSubMenu(); //set display to show sub menu data
    
    printf("TBD - Just load from new saved words only now....\n");

	bool valid = bip39_validate_mnemonic(wallet.words);

	if(!valid) {
		printf("Error - Bad mnemonic\n");
        sprintf(text, "Bad mnemonic");
        LCD_MENU_BufferToDisplayText(text, strlen(text), MENU_MODE_RESULTS);
		return;
	}
    
	bool ok = false;
	if(!wallet.isLoaded) {
    sprintf(text, "Mnemonic good\nCalculating secrets (wait)");
    LCD_MENU_BufferToDisplayText(text, strlen(text), MENU_MODE_RESULTS);
    LCD_MENU_RefreshScreen();

    ok = BTC_RestoreWallet(wallet.words, passphrase, &wallet);

	} else {
		ok = true;

	}

    if(ok) {
    	sprintf(text, "Wallet: %s\nClick here to load", wallet.name);
        MenuItem item;
        item.subMenu = accountMenu; //enable dynamic here
    	item.action = LCD_MENU_Init_Account;
        LCD_MENU_Set_MenuItem(&item, 1); //update second menu row to send user to account view

    } else {
    	sprintf(text, "Error");
    }
    
    LCD_MENU_BufferToDisplayText(text, strlen(text), MENU_MODE_RESULTS);
}

void UI_CLI_VerifyMessage(void) {
    printf("=== Verify Message ===\n");

    // --- Get message from user ---
    char msg[128];
    printf("Enter message: ");
    fgets(msg, sizeof(msg), stdin);
    msg[strcspn(msg, "\n")] = 0;  // Remove newline

    // --- Get r ---
    char input_hex[66];
    uint8_t r[32], s[32], pub_x[32], pub_y[32];

    printf("Enter signature r (32-byte hex): ");
    fgets(input_hex, sizeof(input_hex), stdin);
    input_hex[strcspn(input_hex, "\n")] = 0;
    hex_to_bytes(input_hex, r, 32);

    printf("Enter signature s (32-byte hex): ");
    fgets(input_hex, sizeof(input_hex), stdin);
    input_hex[strcspn(input_hex, "\n")] = 0;
    hex_to_bytes(input_hex, s, 32);

    // --- Get public key x ---
    printf("Enter public key X (32-byte hex): ");
    fgets(input_hex, sizeof(input_hex), stdin);
    input_hex[strcspn(input_hex, "\n")] = 0;
    hex_to_bytes(input_hex, pub_x, 32);

    // --- Get public key y ---
    printf("Enter public key Y (32-byte hex): ");
    fgets(input_hex, sizeof(input_hex), stdin);
    input_hex[strcspn(input_hex, "\n")] = 0;
    hex_to_bytes(input_hex, pub_y, 32);

    // --- Hash the message (SHA256) ---
    uint8_t msghash[32];
    sha256((uint8_t *)msg, strlen(msg), msghash);

    // --- Byte order: adjust for library if needed ---
    swapEndian256(msghash);  // to little-endian
    swapEndian256(r);
    swapEndian256(s);
    swapEndian256(pub_x);
    swapEndian256(pub_y);

    // --- Verify ---
    int error = crappyVerifySignature(r, s, msghash, pub_x, pub_y);

    if (error == 0) {
        printf("Signature is VALID.\n");
    } else {
        printf("Signature is INVALID.\n");
    }
}

void UI_CLI_SignMessage(void) {
    printf("=== Sign Message ===\n");

    // --- Get address index ---
    char input_buf[4];
    printf("Enter address index (m/84'/1'/0'/0/N): ");
    fgets(input_buf, sizeof(input_buf), stdin);
    int index = atoi(input_buf);

    if (index < 0 || index > 100) {
        printf("Invalid index. Must be between 0 and 100.\n");
        return;
    }

    // --- Get message from user ---
    char msg[128];
    printf("Enter message to sign: ");
    fgets(msg, sizeof(msg), stdin);
    msg[strcspn(msg, "\n")] = 0;  // Remove newline if present

    // --- Derive private key for given index ---
    uint8_t private[32];
    bip32DeriveNextPrivate(private, NULL, wallet.main_account_parent_node, index);

	// --- Derive address ---
	uint8_t address[43] = { 0 };
	uint8_t x[32], y[32];
	uint8_t compressedpubkey[33];
	uint8_t digest[32];
	derive_testnet_public_key(private, compressedpubkey, x, y);
	derive_testnet_public_hash(compressedpubkey, digest);
	derive_testnet_address(digest, address);

    // --- Hash the message (SHA256) ---
    uint8_t msghash[32];
    sha256((uint8_t *)msg, strlen(msg), msghash);

    // --- Sign the message ---
    uint8_t r[32], s[32];

    swapEndian256(private);
    swapEndian256(msghash);  // To little-endian before signing

    ecdsaSign(r, s, msghash, private);

    swapEndian256(r);  // Back to big-endian
    swapEndian256(s);  // Back to big-endian

    // --- Output signature ---
    printf("\n\n");
    print_hex(x, 32, "x");
    print_hex(y, 32, "y");
    printf("\n");
    print_hex(r, 32, "Signature r");
    print_hex(s, 32, "Signature s");

    printf("\nMessage signed successfully.\n\n");
}

void UI_CLI_SignRawTransaction(void) {
    printf("Sign transaction from wallet_client.py\n\n");

    int errors = 1;
    uint8_t sig[80];
    size_t sig_len;

    // Fixed-size buffer for raw transaction
    uint8_t raw_tx_str[MAX_RAW_TX_SIZE*2];
    uint8_t raw_tx[MAX_RAW_TX_SIZE];
    size_t raw_tx_len = 0;
    uint8_t privkey_hex[32];
    uint32_t path[2];

    // Prompt for raw transaction as hex string, terminated by Enter
    char input_buffer[MAX_RAW_TX_SIZE*2];

	// Prompt for single-line input
	uint32_t prev_amount_int, out1_amount_int, out2_amount_int;
    uint8_t prev_amount[8];
    uint32_t prev_output_point = 0;

    printf("Paste data here > ");

    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        printf("Error reading input\n");
        return;
    }

    input_buffer[strcspn(input_buffer, "\n")] = 0;  // Strip newline

    int items = sscanf(input_buffer, "%u:%u:%u:%u:%s", (unsigned int *)&path[0], (unsigned int *)&path[1], (unsigned int *)&prev_amount_int, (unsigned int *)&prev_output_point, raw_tx_str);

    if (items != 5) {
        printf("Debug: sscanf parsed %d items\n", items);
        printf("Invalid input format?");
        return;
    }

    // Convert hex string to raw bytes
    hex_string_to_bytes((const char *)raw_tx_str, raw_tx, &raw_tx_len);

    if(path[0] == 0) {
    	bip32DeriveNextPrivate(privkey_hex, NULL, wallet.main_account_parent_node, path[1]);
    } else {
    	bip32DeriveNextPrivate(privkey_hex, NULL, wallet.change_account_parent_node, path[1]);
    }

    uint8_t compressedpubkey[33];
    uint8_t scriptpubkey[32];

    derive_testnet_public_key(privkey_hex, compressedpubkey, NULL, NULL);
    derive_testnet_public_hash(compressedpubkey, scriptpubkey);

    printf("Parsing data....\n");

    // Parse the raw transaction
    BitcoinTxParseResult result;
    errors = parse_bitcoin_tx(raw_tx, raw_tx_len, &result);

	// Convert amount to little-endian bytes
	uint64_to_le_bytes((uint64_t)prev_amount_int, prev_amount);

	out1_amount_int = result.output_info[0].value;
	out2_amount_int = result.output_info[1].value;

	uint8_t address1[43], address2[43];
	derive_testnet_address(result.output_info[0].pubkey_hash_ptr, address1); //get output addresses
	derive_testnet_address(result.output_info[1].pubkey_hash_ptr, address2); //get output addresses

    printf("\nData format ok\n");

	// Debug print

    printf("\n");
    printf("Amount in:          %u\n", (unsigned int)prev_amount_int);
	printf("Amount out:         %u -> %s\n", (unsigned int)out1_amount_int, address1);
	printf("Amount out:         %u -> %s\n", (unsigned int)out2_amount_int, address2);

	int fee = prev_amount_int - (out1_amount_int + out2_amount_int);

	printf("\nFee:                %u\n", fee);

	printf("\n");

    if (errors == 0) {
        errors = sign_p2wpkh_input(&result, privkey_hex, prev_amount, scriptpubkey, 0, sig, &sig_len);
    }

    if (errors != 0) {
        printf("errors = %d\n", errors);
    } else {
        printf("\nSigned transaction below:\n\n");

        // Output raw tx up to locktime
        for (size_t i = 0; i < raw_tx_len - 4 - 1; i++) {
            printf("%02x", raw_tx[i]);
        }

        // Add witness data
        printf("02%02x", sig_len - 1 + 2);  // add der wrapper for sig
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02x", sig[i]);
        }
        printf("0121");  // Pubkey length (33 bytes)
        for (size_t i = 0; i < 33; i++) {
            printf("%02x", compressedpubkey[i]);
        }

        // Add locktime
        for (size_t i = raw_tx_len - 4; i < raw_tx_len; i++) {
            printf("%02x", raw_tx[i]);
        }

        printf("\n");
    }

    //printf("Done\n");
}

void UI_CLI_ShowSeedOrKey(void) {
    printf("*** Sensitive Information - BIP39 Words ***\n");
    print_hex(wallet.master_node, 64, "master");
    printf("\n\n%s\n\n", wallet.words);
}

/* *****************************************************************************
 End of File
 */
