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

#ifndef _UI_H    /* Guard against multiple inclusion */
#define _UI_H

#include "../src/config/default/peripheral/systick/plib_systick.h"
#include <stdio.h>

void UI_CLI_BackupMenu();
void UI_CLI_MemoryCheck();
void UI_CLI_IrPower(void);
void UI_CLI_ResetLimit(void);
void UI_IrDecrease();
void UI_IrIncrease();
void UI_IrMenuSendMessageExit(char * message);
void UI_IrMenuSendMessage();
void UI_PasswordAttackStart();
void UI_PasswordAttackMenu();
void UI_IrPasswordAttack();

void UI_CLI_CreateLogin(void);
void UI_CreateLogin(void);
void UI_CLI_RestoreWalletFromWords(void);
void UI_RestoreWalletFromWords(void);
void UI_CLI_ExportAccountPublicKey(void);
void UI_CLI_DisplayAddresses(void);

void UI_CLI_RestoreWalletFromPIN(void);
void UI_RestoreWalletFromPIN(void);

void UI_ShowWords(void);

void UI_SaveWallet(void);
void UI_DisplayAddress(void);
void UI_ExportPublicKey(void);

void UI_CLI_SignMessage(void);
void UI_CLI_VerifyMessage(void);

void UI_CLI_ShowSeedOrKey(void);
void UI_CLI_SignRawTransaction(void);

void UI_TimingAttack(void);
void UI_CLI_ReadWallet(void);

//Added Prototype - Brad 4/30 TODO: Remove this line
int strcmp(const char *a, const char *b);
long timestamp();
void print_hex(const uint8_t* data, size_t len, const char* label);

//Added Define - Brad 4/30 TODO: Remove this line
#define AUDIT_LOG(...)                                      \
    do {                                                    \
        SYSTICK_DelayUs(700);                               \
        char dbg_buf[64];                                   \
        snprintf(dbg_buf, sizeof(dbg_buf), __VA_ARGS__);    \
        /* Optionally, send dbg_buf to UART or log system */\
    } while(0)



#endif /* _UI_H */

/* *****************************************************************************
 End of File
 */
