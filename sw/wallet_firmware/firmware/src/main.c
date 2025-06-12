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

void SECURE_ELEMENT_GetRandom(uint8_t * random) {
    //Step Random 4

    }

bool BTC_RestoreWallet(const char* mnemonic, char* passphrase, WALLET_t *w) {

    //Step Random 6

    return true;
}

void UI_CLI_DisplayAddresses(void) {
    printf("Get wallet address\n");

    //Step Random 7

}

void UI_CLI_RestoreWalletFromPIN(void) {
	//Step 2.0 Load Wallet

        }

/* Placeholder functions for wallet operations */
void UI_CLI_CreateLogin(void) {

	printf("Generating Account Login...\n");

    //Step Random 3

    return;
}


void UI_SaveWallet(void) {
	//Step 3.1 Add Encryption

}

void UI_SendAddress(void) {
	printf("Address: ");
    MULTI_COMM_Print(ui_screen_text, true);
    printf("\n");
}

void UI_DisplayAddress(void) {
    LCD_MENU_EnterSubMenu();

    //Step Random 8

    //dynamically set the address to be printed when enter is pressed
    resultsSubMenu[0].action = UI_SendAddress;

    LCD_MENU_BufferToDisplayText(ui_screen_text, strlen(ui_screen_text), MENU_MODE_RESULTS);
}

void UI_TimingAttack(void) {
	// Step Timing Bonus 1

    return;
}

//Step 3.0 Add Encryption

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
				printf("\nNo Wallet Loaded\n");
                //Step Random 1
                printf("1 - TODO\n");
                printf("2 - Load Wallet\n");

				//Step 2.2 Load Wallet
                printf("3 - TODO\n");

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

						break;
					case '2':
						//Step Random 5

						break;
					case '3':
						//Step 2.1 Load Wallet

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
