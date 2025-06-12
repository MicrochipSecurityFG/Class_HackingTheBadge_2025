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

#ifndef MULTI_COM_H    /* Guard against multiple inclusion */
#define MULTI_COM_H

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include "lcd_menu.h"
#include "cryptoauthlib.h"
#include "secure_element.h"
#include "ui.h"
#include "ir.h"

#define LINE_FEED 0x0a

bool MULTI_COMM_ReceiverIsReady();
uint8_t MULTI_COMM_ReadByte(bool* isUART);
void MULTI_COMM_Print(const char *str, bool outputSerial);
uint8_t MULTI_COMM_GetUserInput(uint8_t menuModeFlag);
bool MULTI_COMM_GetLine(char* buffer, size_t max_len);



#endif /* MULTI_COM_H */

/* *****************************************************************************
 End of File
 */
