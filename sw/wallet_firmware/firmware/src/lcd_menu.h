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

#ifndef _LCD_MENU_H    /* Guard against multiple inclusion */
#define _LCD_MENU_H


/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

/* This section lists the other files that are included in this file.
 */



typedef void (*ActionCallback)(void);

typedef struct MenuItem {
    char* displayText;    // Menu item display text
    ActionCallback action;      // Function to call when item is selected
    struct MenuItem* subMenu;   // Pointer to sub-menu
    int subMenuSize;            // Size of the sub-menu
    leFont* font;               // Font for display
    bool actionWithSubMenu;
} MenuItem;

typedef enum {
    MENU_MODE_RESULTS,
    MENU_MODE_DATA_ENTRY
} MenuMode;

extern MenuItem mainMenu[];
extern MenuItem accountMenu[];
extern MenuItem *startMenu;
extern MenuItem resultsSubMenu[];
extern MenuItem dataEntrySubMenu[];
extern MenuItem settingsSubMenu[];



void LCD_MENU_UpButtonPressCallback(uintptr_t context);
void LCD_MENU_DownButtonPressCallback(uintptr_t context);
void LCD_MENU_LeftButtonPressCallback(uintptr_t context);
void LCD_MENU_RightButtonPressCallback(uintptr_t context);
void LCD_MENU_EnterButtonPressCallback(uintptr_t context);

void LCD_MENU_ButtonTasks(void);

void LCD_MENU_Init(void);
void LCD_MENU_Init_Account(void);
void LCD_MENU_BufferToDisplayText(char *buffer, size_t bufferLength, MenuMode menuMode);
void LCD_MENU_EnterDataEntryMenuMode(void);

void LCD_MENU_Set_MenuItem(MenuItem *item, int itemNumber);
void LCD_MENU_RefreshScreen(void);

void LCD_MENU_RxMessage();
void UI_PasswordAttackMenu();

void LCD_MENU_DisplayTextBuffer(char *buffer, uint8_t line);

void LCD_MENU_EnterSubMenu();

// Define the type for the function pointer
typedef void (*DataEntryExitFunc)(char* buffer);

// Declare the setDataEntryExit function with a function pointer parameter
void LCD_MENU_RegisterDataEntryExit(DataEntryExitFunc exitFunc);

void LCD_MENU_ButtonTasks(void);

#endif /* _LCD_MENU_H */

/* *****************************************************************************
 End of File
 */
