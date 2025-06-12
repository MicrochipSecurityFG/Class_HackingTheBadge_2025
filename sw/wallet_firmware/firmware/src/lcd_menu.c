#include <stdint.h>
#include <stdlib.h>  // For atoi function
#include "definitions.h"  // SYS function prototypes
#include "time.h"
#include "ir.h"
#include "ui.h"
#include "lcd_menu.h"

#define MENU_PAGE_SIZE 3
#define MAX_MENU_DEPTH 10  // Maximum depth of menu navigation
#define APP_FIXED_STR_SIZE 20
#define DEBOUNCE_TIME 120  // xx milliseconds

extern MenuItem mainMenu[];

typedef struct {
    MenuItem *menu;  // Pointer to the current menu
    int menuSize;    // Size of the current menu
    int selectedItem;  // Currently selected item in this menu
} MenuContext;

typedef struct {
    char* displayText;  // To allow dynamic updates
} DynamicMenuItem;

typedef enum {
    BUTTON_ID_UP = 0,
    BUTTON_ID_DOWN,
    BUTTON_ID_LEFT,
    BUTTON_ID_RIGHT,
    BUTTON_ID_ENTER,
	BUTTON_ID_None,
    BUTTON_ID_TOTAL // Total number of buttons
} ButtonId;

// Global Variables
static int currentScreenState = 0;
static MenuMode menuMode = MENU_MODE_RESULTS;
static int dataEntryCursorIndex = 0;
static uint32_t lastButtonPressTime = 0;
static int selectedItemIndex = 0; // Index of the currently selected menu item
static int currentMenuDepth = 0;  // Current depth in the menu stack
static MenuContext menuStack[MAX_MENU_DEPTH];  // Stack to keep track of menu contexts
static int currentPage = 0;
static int totalPages = 0;

static leLabelWidget* Screen0_MenuItem[MENU_PAGE_SIZE];
static leFixedString menuFixedStringObject[MENU_PAGE_SIZE];  // Fixed String with static data store
static leChar menuFixedStringBuffer[MENU_PAGE_SIZE][APP_FIXED_STR_SIZE] = {0};  // Fixed sized data store

MenuItem *startMenu;
static MenuItem *currentMenu;  // Start with the top-level menu
static int currentMenuSize = 6;    // Top-level menu size

ButtonId lastPressedButton = BUTTON_ID_None;

MenuItem resultsSubMenu[] = {
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0},
};

MenuItem mainMenu[] = {
    {"Create Login", UI_CreateLogin, resultsSubMenu, 6, (leFont*) & Font0},
    {"Load Wallet", UI_RestoreWalletFromWords, resultsSubMenu, 2, (leFont*) & Font0},
    {"Load Saved", UI_RestoreWalletFromPIN, resultsSubMenu, 2, (leFont*) & Font0},
	{"Timing Attack", UI_TimingAttack, resultsSubMenu, 3, (leFont*) & Font0},
};

MenuItem accountMenu[] = {
    {"Export Public",   UI_ExportPublicKey, resultsSubMenu, 6, (leFont*) & Font0},
    {"Display Address", UI_DisplayAddress, resultsSubMenu, 3, (leFont*) & Font0},
    {"Sign Transaction",NULL, NULL, 3, (leFont*) & Font0},
    {"Show Words",      UI_ShowWords, resultsSubMenu, 3, (leFont*) & Font0},
    {"Save Wallet",    UI_SaveWallet, resultsSubMenu, 3, (leFont*) & Font0},
    {"Sign Message",    NULL, NULL, 3, (leFont*) & Font0},
    {"Verify Message",  NULL, NULL, 3, (leFont*) & Font0},
    {"empty",           NULL, NULL, 3, (leFont*) & Font0},
    {"Exit Account",    NULL, NULL, 3, (leFont*) & Font0},
};

DataEntryExitFunc exitFunc;

// Function Prototypes
void LCD_MENU_EnterSubMenu();
void LCD_MENU_ReturnToParentMenu();
void LCD_MENU_EnterDataEntryMenuMode(void);
void LCD_MENU_BufferToDisplayText(char *buffer, size_t bufferLength, MenuMode mode);
void LCD_MENU_RegisterDataEntryExit(DataEntryExitFunc func);
void LCD_MENU_DataEntryMenuModeButtonHandler(ButtonId buttonId);
bool LCD_MENU_DebounceHandler(void);
void LCD_MENU_LeftButtonPressCallback(uintptr_t context);
void LCD_MENU_RightButtonPressCallback(uintptr_t context);
void LCD_MENU_EnterButtonPressCallback(uintptr_t context);
void LCD_MENU_UpButtonPressCallback(uintptr_t context);
void LCD_MENU_DownButtonPressCallback(uintptr_t context);
void Screen0_OnShow(void);
void Screen0_OnUpdate(void);
void Screen0_OnHide(void);

MenuItem dataEntrySubMenu[] = {
    {"Enter Below:", NULL, NULL, 0, (leFont*)&Font0},
    {NULL, NULL, NULL, 0, (leFont*)&Font0}, // Placeholder for data
    {NULL, NULL, NULL, 0, (leFont*)&Font0}, // Placeholder for data
};

void LCD_MENU_RxMessage() {

	static char * temp = "Rx Message:";

    ir_packet.buffer[0] = 0x00;
    
	LCD_MENU_DisplayTextBuffer(temp, 0);
    LCD_MENU_DisplayTextBuffer((char *)ir_packet.buffer, 1);

	LCD_MENU_EnterSubMenu();

	return;
}

void LCD_MENU_DisplayTextBuffer(char *buffer, uint8_t line) {
    resultsSubMenu[line].displayText = buffer;
}

void LCD_MENU_BufferToDisplayText(char *buffer, size_t bufferLength,
		MenuMode mode) {
	if (mode == MENU_MODE_RESULTS) {
		int row = 0;
		int segmentLength = APP_FIXED_STR_SIZE;
		char *start = buffer;

		for (size_t i = 0; i < bufferLength && row < 6; i++) {
			if (buffer[i] == '\n') {
				buffer[i] = '\0'; // Replace newline with null terminator
				resultsSubMenu[row].displayText = start;
				row++;
				start = &buffer[i + 1]; // Start of next segment
			}
		}

		if (row != 0) {
			// Handle case where buffer ends without a newline
			if (row < 6 && start < buffer + bufferLength && *start != '\0') {
				resultsSubMenu[row++].displayText = start;
			}

			// Nullify remaining rows if fewer than 6
			for (; row < 6; row++) {
				resultsSubMenu[row].displayText = NULL;
			}
		} else {

			// Assign buffer segments to displayText in resultsSubMenu
			for (int row = 0; row < 6; row++) {
				if ((row * segmentLength) < bufferLength) {
					resultsSubMenu[row].displayText = &buffer[row
							* segmentLength];
				} else {
					resultsSubMenu[row].displayText = NULL; // Handle short buffers
				}
			}
		}
		LCD_MENU_EnterSubMenu();
	} else if (mode == MENU_MODE_DATA_ENTRY) {
		dataEntrySubMenu[1].displayText = buffer;
		LCD_MENU_EnterDataEntryMenuMode();
	}
}

void LCD_MENU_Init(void) {
    
    startMenu = mainMenu;
    currentMenuSize = sizeof (mainMenu) / sizeof (mainMenu[0]);
    totalPages = (currentMenuSize + MENU_PAGE_SIZE - 1) / MENU_PAGE_SIZE;  // Calculate total pages
    currentPage = 0;  // Start at the first page    
    currentScreenState = 0;
}

void LCD_MENU_Set_MenuItem(MenuItem *item, int itemNumber) {
    
    currentMenu[itemNumber].subMenu = item->subMenu; //enable dynamic here
    currentMenu[itemNumber].action = item->action;
}

void LCD_MENU_RefreshScreen(void) {
    Legato_Tasks(); //refresh screen
}
void LCD_MENU_Init_Account(void) {

	startMenu = accountMenu;
	currentMenuSize = sizeof(accountMenu) / sizeof(accountMenu[0]);
	totalPages = (currentMenuSize + MENU_PAGE_SIZE - 1) / MENU_PAGE_SIZE; // Calculate total pages
	currentPage = 0;  // Start at the first page
	currentScreenState = 0;
    
    memset(menuStack, 0x00, sizeof(menuStack));
    
    currentMenuDepth = 0;
    selectedItemIndex = 0;
    currentMenu = startMenu;
}

void LCD_MENU_EnterDataEntryMenuMode(void) {
    if (currentMenu[selectedItemIndex].subMenu != NULL) {
        if (currentMenuDepth < MAX_MENU_DEPTH - 1) {
            // Save current context before navigating to sub-menu
            menuStack[currentMenuDepth].menu = currentMenu;
            menuStack[currentMenuDepth].menuSize = currentMenuSize;
            menuStack[currentMenuDepth].selectedItem = selectedItemIndex;
            currentMenuDepth++;
            
            currentMenuSize = currentMenu[selectedItemIndex].subMenuSize;
            currentMenu = currentMenu[selectedItemIndex].subMenu;
            
            selectedItemIndex = 0;
            currentPage = 0;  // Reset to the first page
            totalPages = (currentMenuSize + MENU_PAGE_SIZE - 1) / MENU_PAGE_SIZE;  // Calculate total pages
            currentScreenState = 0;
            
            menuMode = MENU_MODE_DATA_ENTRY;  // Change behavior of buttons
            dataEntryCursorIndex = 0;
            selectedItemIndex = 1;
        } 
    }
}

void LCD_MENU_RegisterDataEntryExit(DataEntryExitFunc func) {
    if (func != NULL) {
        exitFunc = func;
    }
}

void LCD_MENU_DataEntryMenuModeButtonHandler(ButtonId buttonId) {
    char * dataBuffer = dataEntrySubMenu[1].displayText;
    bool exitFlag = false;

    // Ensure the current character is within the valid range
    if (!((dataBuffer[dataEntryCursorIndex] >= '0' && dataBuffer[dataEntryCursorIndex] <= '9') ||
          (dataBuffer[dataEntryCursorIndex] >= 'a' && dataBuffer[dataEntryCursorIndex] <= 'z'))) {
        dataBuffer[dataEntryCursorIndex] = '0'; // Default to '0' if out of range
    }
    
    switch(buttonId) {
        case BUTTON_ID_UP:
            if (dataBuffer[dataEntryCursorIndex] < '9') {
                dataBuffer[dataEntryCursorIndex]++;
            } else if (dataBuffer[dataEntryCursorIndex] == '9') {
                dataBuffer[dataEntryCursorIndex] = 'a';
            } else if (dataBuffer[dataEntryCursorIndex] < 'z') {
                dataBuffer[dataEntryCursorIndex]++;
            } else {
                dataBuffer[dataEntryCursorIndex] = '0';
            }
            break;

        case BUTTON_ID_DOWN:
            if (dataBuffer[dataEntryCursorIndex] > 'a') {
                dataBuffer[dataEntryCursorIndex]--;
            } else if (dataBuffer[dataEntryCursorIndex] == 'a') {
                dataBuffer[dataEntryCursorIndex] = '9';
            } else if (dataBuffer[dataEntryCursorIndex] > '0') {
                dataBuffer[dataEntryCursorIndex]--;
            } else {
                dataBuffer[dataEntryCursorIndex] = 'z';
            }
            break;

        case BUTTON_ID_RIGHT:
            if (dataEntryCursorIndex < APP_FIXED_STR_SIZE - 1) {
                dataEntryCursorIndex++;
                if (!((dataBuffer[dataEntryCursorIndex] >= '0' && dataBuffer[dataEntryCursorIndex] <= '9') ||
                        (dataBuffer[dataEntryCursorIndex] >= 'a' && dataBuffer[dataEntryCursorIndex] <= 'z'))) {
                    dataBuffer[dataEntryCursorIndex] = '0'; // Default to '0' if out of range
                }
            }
            break;
            
        case BUTTON_ID_LEFT:
            if (dataEntryCursorIndex > 0) {
                dataEntryCursorIndex--;
            } else {
                exitFlag = true;
            }
            break;
            
        case BUTTON_ID_ENTER:
            if(exitFunc != NULL) exitFunc(dataBuffer); // Pass the buffer to the callback
            exitFlag = true;
            break;

        default:
            break;
    }

    if(exitFlag) {
        LCD_MENU_ReturnToParentMenu();
        exitFunc = NULL;
        menuMode = MENU_MODE_RESULTS; // Exit data entry mode
    }
    
    currentScreenState = 0; // Trigger screen update  
}

bool LCD_MENU_DebounceHandler() {
    uint32_t currentTime = SYS_TIME_CountToMS(SYS_TIME_CounterGet());
    if ((currentTime - lastButtonPressTime) > DEBOUNCE_TIME) {
        lastButtonPressTime = currentTime;
        return true;
    }
    return false;
}

void LCD_MENU_EnterSubMenu() {
    if (currentMenu[selectedItemIndex].subMenu != NULL) {
        if (currentMenuDepth < MAX_MENU_DEPTH - 1) {
            // Save current context before navigating to sub-menu
            menuStack[currentMenuDepth].menu = currentMenu;
            menuStack[currentMenuDepth].menuSize = currentMenuSize;
            menuStack[currentMenuDepth].selectedItem = selectedItemIndex;
            currentMenuDepth++;
            
            currentMenuSize = currentMenu[selectedItemIndex].subMenuSize;
            currentMenu = currentMenu[selectedItemIndex].subMenu;
            
            selectedItemIndex = 0;
            currentPage = 0;  // Reset to the first page
            totalPages = (currentMenuSize + MENU_PAGE_SIZE - 1) / MENU_PAGE_SIZE;  // Calculate total pages
            currentScreenState = 0;
        } 
    }
}

void LCD_MENU_ReturnToParentMenu() {
    if (currentMenuDepth > 0) {
        currentMenuDepth--;  // Decrement first to get the correct previous context
        MenuContext prevContext = menuStack[currentMenuDepth];
        currentMenu = prevContext.menu;
        currentMenuSize = prevContext.menuSize;
        selectedItemIndex = prevContext.selectedItem;
        currentPage = (selectedItemIndex / MENU_PAGE_SIZE);
        totalPages = (currentMenuSize + MENU_PAGE_SIZE - 1) / MENU_PAGE_SIZE;  // Calculate total pages
        currentScreenState = 0;
    }
}

void LCD_MENU_LeftButtonPressCallback(uintptr_t context) {
	if (LCD_MENU_DebounceHandler()) {
		lastPressedButton = BUTTON_ID_LEFT;
	}
}

void LCD_MENU_RightButtonPressCallback(uintptr_t context) {
	if (LCD_MENU_DebounceHandler()) {
		lastPressedButton = BUTTON_ID_RIGHT;
	}
}
 
void LCD_MENU_EnterButtonPressCallback(uintptr_t context) {
	if (LCD_MENU_DebounceHandler()) {
		lastPressedButton = BUTTON_ID_ENTER;
	}
}

void LCD_MENU_UpButtonPressCallback(uintptr_t context) {
	if (LCD_MENU_DebounceHandler()) {
		lastPressedButton = BUTTON_ID_UP;
	}
}

void LCD_MENU_DownButtonPressCallback(uintptr_t context) {
	if (LCD_MENU_DebounceHandler()) {
		lastPressedButton = BUTTON_ID_DOWN;
	}
}

void LCD_MENU_ButtonTasks(void) {
	switch (lastPressedButton) {
	case BUTTON_ID_LEFT:
		if (menuMode == MENU_MODE_DATA_ENTRY) {
			LCD_MENU_DataEntryMenuModeButtonHandler(BUTTON_ID_LEFT);
		} else {
			LCD_MENU_ReturnToParentMenu();
			currentScreenState = 0; // Ensure the screen state is reset to trigger an update
		}
		break;

	case BUTTON_ID_RIGHT:
		if (menuMode == MENU_MODE_DATA_ENTRY) {
			LCD_MENU_DataEntryMenuModeButtonHandler(BUTTON_ID_RIGHT);
		} else {
			// Only go to submenu if one exists (if action then no submenu)
			if (!currentMenu[selectedItemIndex].action) {
				LCD_MENU_EnterSubMenu();
			}
			currentScreenState = 0;

			LED5_Set();
			SYSTICK_DelayMs(100);
			LED5_Clear();
		}
		break;

	case BUTTON_ID_ENTER:
		if (menuMode == MENU_MODE_DATA_ENTRY) {
			LCD_MENU_DataEntryMenuModeButtonHandler(BUTTON_ID_ENTER);
		} else {
			// Call the action if no sub-menu is present, or enter sub-menu if available
			if (currentMenu[selectedItemIndex].action) {
				currentMenu[selectedItemIndex].action();
			} else {
				LCD_MENU_EnterSubMenu();
			}
			currentScreenState = 0;

			LED5_Set();
			SYSTICK_DelayMs(100);
			LED5_Clear();
		}
		break;

	case BUTTON_ID_UP:
		if (menuMode == MENU_MODE_DATA_ENTRY) {
			LCD_MENU_DataEntryMenuModeButtonHandler(BUTTON_ID_UP);
		} else {
			if (selectedItemIndex > 0) {
				selectedItemIndex--;
				if (selectedItemIndex < currentPage * MENU_PAGE_SIZE) {
					currentPage--;
					currentScreenState = 0; // Trigger screen update
				}
			} else {
				// Handle wrap-around to the last item if needed
				selectedItemIndex = currentMenuSize - 1;
				currentPage = (selectedItemIndex / MENU_PAGE_SIZE);
				currentScreenState = 0; // Trigger screen update
			}

			LED1_Set();
			SYSTICK_DelayMs(100);
			LED1_Clear();
		}
		break;

	case BUTTON_ID_DOWN:
		if (menuMode == MENU_MODE_DATA_ENTRY) {
			LCD_MENU_DataEntryMenuModeButtonHandler(BUTTON_ID_DOWN);
		} else {
			if (selectedItemIndex < currentMenuSize - 1) {
				selectedItemIndex++;
				if (selectedItemIndex >= (currentPage + 1) * MENU_PAGE_SIZE) {
					currentPage++;
					currentScreenState = 0; // Trigger screen update
				}
			} else {
				// Handle wrap-around to the first item if needed
				selectedItemIndex = 0;
				currentPage = 0;
				currentScreenState = 0; // Trigger screen update
			}

			LED2_Set();
			SYSTICK_DelayMs(100);
			LED2_Clear();
		}
		break;
	default:
		lastPressedButton = BUTTON_ID_None;
		break;
	}

	lastPressedButton = BUTTON_ID_None;
}

void Screen0_OnShow(void) {
    // Initialize Fixed String with statically allocated data store
    for (int i = 0; i < MENU_PAGE_SIZE; i++) {
        leFixedString_Constructor(&menuFixedStringObject[i], menuFixedStringBuffer[i], APP_FIXED_STR_SIZE);  // Set data store
        menuFixedStringObject[i].fn->setFont(&menuFixedStringObject[i], startMenu[i].font);  // Set Font
    }

    Screen0_MenuItem[0] = Screen0_MenuItem_0;
    Screen0_MenuItem[1] = Screen0_MenuItem_1;
    Screen0_MenuItem[2] = Screen0_MenuItem_2;
    
    currentMenu = startMenu;
}

void Screen0_OnUpdate(void) {
    if (1) { //currentScreenState == 0) {
        int startItem = currentPage * MENU_PAGE_SIZE;
        int endItem = startItem + MENU_PAGE_SIZE;
        if (endItem > currentMenuSize) {
            endItem = currentMenuSize;
        }

        for (int i = 0; i < MENU_PAGE_SIZE; i++) {
            int itemIndex = startItem + i;
            if (itemIndex < endItem && currentMenu[itemIndex].displayText != NULL) {
                menuFixedStringObject[i].fn->setFromCStr(&menuFixedStringObject[i], currentMenu[itemIndex].displayText);
                Screen0_MenuItem[i]->fn->setString(Screen0_MenuItem[i], (leString*)&menuFixedStringObject[i]);
                Screen0_MenuItem[i]->fn->setVisible(Screen0_MenuItem[i], LE_TRUE);
            } else {
                Screen0_MenuItem[i]->fn->setVisible(Screen0_MenuItem[i], LE_FALSE);
            }
        }
        
        currentScreenState = 1;
    }

    int relativeSelectedItemIndex = selectedItemIndex % MENU_PAGE_SIZE;
    Screen0_RadioButtonWidget_0->fn->setPosition(Screen0_RadioButtonWidget_0, 0, 30 + (16 * relativeSelectedItemIndex));
}

void Screen0_OnHide(void) {
    // Free dynamic string allocations if needed
}
