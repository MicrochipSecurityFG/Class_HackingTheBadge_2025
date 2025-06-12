/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app.c

  Summary:
    This file contains the source code for the MPLAB Harmony application.

  Description:
    This file contains the source code for the MPLAB Harmony application.  It
    implements the logic of the application's state machine and it may call
    API routines of other MPLAB Harmony modules in the system, such as drivers,
    system services, and middleware.  However, it does not call any of the
    system interfaces (such as the "Initialize" and "Tasks" functions) of any of
    the modules in the system or make any assumptions about when those functions
    are called.  That is the responsibility of the configuration-specific system
    files.
 *******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stdio.h>
#include "ir.h"
#include "lcd_menu.h"
#include "util.h"

uint32_t ir_power = 300;
ir_packet_t ir_packet;
extern rx_t rx;

void IR_Receive(uintptr_t event) {


    TC4_TimerStart();
    uint8_t byte;
    //Read Received Byte
    // size_t size = strlen(rx.receiveBuffer);
    byte = rx.receiveBuffer[0]; //rx.receivedCount++];
    //printf("\n# 0x%02X : 0x%02X", rx.receivedCount,byte);

    //printf("%d", ir_packet.data_index);

    if (rx.receivedCount >= sizeof (rx.receiveBuffer)) {
        SERCOM5_REGS->USART_INT.SERCOM_DATA = 'X';
        rx.receivedCount = 0;
        //memset(rx.receiveBuffer, 0x00, sizeof (rx.receiveBuffer));
    }

    switch (ir_packet.state) {
            //        case WAITING_FOR_BREAK:
            //            if (byte == 0x00 && (SERCOM2_REGS->USART_INT.SERCOM_STATUS & SERCOM_USART_INT_STATUS_FERR_Msk)) { // if 0x00 and framing error
            //                uart_packet.state = WAITING_FOR_SYNC;
            //            }
            //            break;

        case WAITING_FOR_SYNC:
            if (byte == 0x55) {
                //SERCOM5_REGS->USART_INT.SERCOM_DATA = 's';
                ir_packet.state = RECEIVING_LENGTH_BYTE;
                ir_packet.data_index = 0;
                ir_packet.valid_packet = false;
                rx.receivedCount = 0;
            } //else {
            //  uart_packet.state = WAITING_FOR_BREAK;
            //}
            break;

        case RECEIVING_LENGTH_BYTE:
            //SERCOM5_REGS->USART_INT.SERCOM_DATA = 'L';
            ir_packet.length = byte - 1;
            ir_packet.state = RECEIVING_CONTROL_BYTE;
            //uart_packet.data_index = 0; // Reset index for CRC
            break;

        case RECEIVING_CONTROL_BYTE:
            //SERCOM5_REGS->USART_INT.SERCOM_DATA = 'i';
            ir_packet.info_byte = byte;
            ir_packet.state = RECEIVING_DATA;
            break;

        case RECEIVING_DATA:
            //SERCOM5_REGS->USART_INT.SERCOM_DATA = 'd';
            ir_packet.buffer[ir_packet.data_index++] = byte;
            if (ir_packet.data_index >= (ir_packet.length - 2)) {
                ir_packet.state = RECEIVING_CRC;
            }
            break;

        case RECEIVING_CRC:
            //printf("*");
            //SERCOM5_REGS->USART_INT.SERCOM_DATA = 'c';
            ir_packet.buffer[ir_packet.data_index++] = byte;
            if (ir_packet.data_index >= ir_packet.length) {
                ir_packet.crc = (ir_packet.buffer[ir_packet.length - 2] << 8) | ir_packet.buffer[ir_packet.length - 1];
                ir_packet.state = WAITING_FOR_SYNC;
                // Verify CRC here
                if (ir_packet.crc == UTIL_crc16_CCITT(ir_packet.buffer, ir_packet.length - 2)) {
                    //Packet is valid
                    TC4_TimerStop();
                    TC4_Timer32bitCounterSet(0x0000);
                    ir_packet.valid_packet = true;
                    //? SERCOM2_USART_ReceiverDisable();
                    ir_packet.buffer[ir_packet.data_index - 2] = 0x00;
                    resultsSubMenu[1].displayText = (char *)ir_packet.buffer;
                    printf("IR: ");
                    _ir_rx_disable();
                    for (int i = 0; i != ir_packet.length - 2; i++) {
                        printf("%c", ir_packet.buffer[i]);
                    }
                    _ir_rx_enable();
                    printf("\n");
                } else {
                    ir_packet.state = WAITING_FOR_SYNC;
                    //printf("ng\n");
                }
            }
            break;

        default:
            ir_packet.state = WAITING_FOR_SYNC;
            break;
    }
    //Re-arm reception
    // if(ir_packet.valid_packet == false)
    {
        //SERCOM2_USART_Read(&rx.receiveBuffer[rx.receivedCount], 1);
        SERCOM2_USART_Read(&rx.receiveBuffer[0], 1);
    }
}

bool IR_SendMessage(const char *str, int8_t retry_count, const char *expected_response) {
    uint8_t u8_attempts = 0;
    while (u8_attempts <= retry_count) {
        TC4_TimerStop();
        TC4_Timer32bitCounterSet(0x0000);
        TC4_REGS->COUNT32.TC_INTFLAG = 1; //Clear OVF Flag
        
        ir_packet.valid_packet = false;
        ir_packet.info_byte = 0x00;
        memcpy(ir_packet.buffer, str, strlen(str));
        ir_packet.data_index = strlen(str);
        ir_packet.length = (uint16_t) strlen(str) + 3;
        ir_packet.crc = UTIL_crc16_CCITT(ir_packet.buffer, strlen(str));
        ir_packet.buffer[ir_packet.data_index++] = (uint8_t) (ir_packet.crc >> 8);
        ir_packet.buffer[ir_packet.data_index++] = (uint8_t) (ir_packet.crc);
        IR_SendPacket(&ir_packet);
        TC4_TimerStart();
        while ((TC4_TimerPeriodHasExpired() == false) && (ir_packet.valid_packet == false)); //Always wait for either valid IR packet or timer expire
        
        if (expected_response == NULL) {
            return true;
        } 
        else {
            if (ir_packet.valid_packet == true && UTIL_StringContains((char *) ir_packet.buffer, expected_response) == true) {
                return true;
            } else {
                printf("\nRetrying...");
                IR_FlushReceiver();
                u8_attempts++;
            }
        }
    }
    return false;
}

void IR_SendPacket(ir_packet_t * packet) {
    SERCOM2_USART_ReceiverDisable();
    IR_Send(0x55);
    IR_Send(packet->length);
    IR_Send(packet->info_byte);
    for (int i = 0; i < packet->length - 1; i++) {
        IR_Send(packet->buffer[i]);
    }
    SERCOM2_USART_ReceiverEnable();
}

void IR_Send(uint8_t byte) {
    int i = 0;
    //send start bit

    //SYSTICK_DelayMs(10);

    PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;
    TCC2_REGS->TCC_CC[0] = ir_power; //631
    TCC2_PWMStart();

    PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x4U;
    SYSTICK_DelayUs(DELAY_TIME);
    PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;

    for (i = 0; i < 8; i++) {
        if (((byte >> i) & 0x01) == 0) {
            //send 1          
            PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x4U;
            SYSTICK_DelayUs(DELAY_TIME);
            //PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;
        } else {
            //send 0
            PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;
            SYSTICK_DelayUs(DELAY_TIME);
        }
    }

    PORT_REGS->GROUP[0].PORT_PMUX[6] = 0x0U;
    SYSTICK_DelayUs(DELAY_TIME);
    TCC2_PWMStop();

    //SYSTICK_DelayMs(1);
}    

void IR_EnableReceive() {
    //static char text[32] = "IR Enabled [x]";
    static bool bool_IR_Enabled = false;

    if (bool_IR_Enabled == true) {
        bool_IR_Enabled = false;
        //Want to disable
        SERCOM2_USART_ReceiverDisable();
        SERCOM2_USART_Disable();
        IR_RX_ON_Clear();
    } else {
        bool_IR_Enabled = true;
        //Want to enable;
        SERCOM2_REGS->USART_INT.SERCOM_INTFLAG = SERCOM_USART_INT_INTENSET_ERROR_Msk;
        SERCOM2_REGS->USART_INT.SERCOM_INTENSET = SERCOM_USART_INT_INTENSET_ERROR_Msk;
        IR_RX_ON_Set(); // move before enable uart
        SERCOM2_USART_Enable();
        SERCOM2_USART_ReceiverEnable();
        memset(rx.receiveBuffer, 0x00, sizeof (rx.receiveBuffer));
        SERCOM2_USART_Read(rx.receiveBuffer, 1);
        resultsSubMenu[1].displayText = (char *)ir_packet.buffer;
    }
}

void IR_FlushReceiver() {
    /* Clear error flag */
    SERCOM2_REGS->USART_INT.SERCOM_INTFLAG = (uint8_t) SERCOM_USART_INT_INTFLAG_ERROR_Msk;
    /* Clear all errors */
    SERCOM2_REGS->USART_INT.SERCOM_STATUS = (uint16_t) (SERCOM_USART_INT_STATUS_PERR_Msk | SERCOM_USART_INT_STATUS_FERR_Msk | SERCOM_USART_INT_STATUS_BUFOVF_Msk);

    /* Flush existing error bytes from the RX FIFO */
    while ((SERCOM2_REGS->USART_INT.SERCOM_INTFLAG & (uint8_t) SERCOM_USART_INT_INTFLAG_RXC_Msk) == (uint8_t) SERCOM_USART_INT_INTFLAG_RXC_Msk) {
        uint8_t u8dummyData = (uint8_t) SERCOM2_REGS->USART_INT.SERCOM_DATA;
        (void)u8dummyData;  // Suppress unused variable warning
    }
    
    SERCOM2_USART_Disable();
    SERCOM2_USART_Enable();
}

void IR_CheckTimeOut() {
    if (TC4_TimerPeriodHasExpired()) {
        TC4_TimerStop();
        TC4_Timer32bitCounterSet(0x0000);
        TC4_REGS->COUNT32.TC_INTFLAG = (TC4_REGS->COUNT32.TC_INTFLAG) & TC_INTFLAG_OVF_Msk;
        ir_packet.state = WAITING_FOR_SYNC;
        IR_FlushReceiver();
    }
}

/*******************************************************************************
 End of File
 */
