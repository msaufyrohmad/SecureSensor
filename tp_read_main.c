/* Touch Pad Read Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/touch_pad.h"
#include "cilipadi.h"
#include "crypto_aead.h"
#define TOUCH_PAD_NO_CHANGE   (-1)
#define TOUCH_THRESH_NO_USE   (0)
#define TOUCH_FILTER_MODE_EN  (1)
#define TOUCHPAD_FILTER_TOUCH_PERIOD (10)


/* const value for cilipadi v1 */
const unsigned char npub[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const unsigned char k[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const unsigned char ad[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned long long adlen = 8;
unsigned char m_dec[24];
unsigned char c[24];
unsigned long long clen;
unsigned long long mlen = 16;
unsigned long long mlen_dec;
unsigned char touch_plain[24]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
/*
  Read values sensed at all available touch pads.
 Print out values in a loop on a serial monitor.
 */
static void tp_example_read_task(void *pvParameter)
{
    uint16_t touch_value;
    uint16_t touch_filter_value;
    int i;
    printf("Touch Sensor normal mode read, the output format is: \nTouchpad num:[raw data]\n\n");
    while (1) {
        for (int i = 0; i < TOUCH_PAD_MAX; i++) {
            touch_pad_read(i, &touch_value);
             touch_plain[i*2+1]=touch_value;
                touch_plain[i*2]=touch_value>>8;
                printf("Read : T%d:[%0x%0x] ",i,touch_plain[i*2],touch_plain[i*2+1]);
        }
        printf("\n");
         crypto_aead_encrypt(c, &clen, touch_plain, mlen, ad, adlen, NULL, npub, k);
 	printf("\nCiphertext %llu bytes:",clen-8);
                for (i=0; i <clen-8; ++i) {
                        printf("%02x ",c[i]);
                }
                printf("\n");
        printf("\nTag 8 bytes:");
                for (i=16; i <clen; ++i) {
                        printf("%02x ",c[i]);
                }
                 printf("\n");

       if (crypto_aead_decrypt(m_dec, &mlen_dec, NULL, c, clen, ad, adlen, npub, k) == 0) {
                 printf("\nPlaintext %llu bytes: ",mlen_dec);
                 for (i = 0; i <mlen_dec; ++i) {
                        printf("%02x ", m_dec[i]);
                 }
                printf("\n");

	  }
        else{
               printf("Decryption Failed!\n");
	}
	vTaskDelay(200 / portTICK_PERIOD_MS);
    }
}

static void tp_example_touch_pad_init()
{
    for (int i = 0;i< TOUCH_PAD_MAX;i++) {
        touch_pad_config(i, TOUCH_THRESH_NO_USE);
    }
}

void app_main()
{
    // Initialize touch pad peripheral.
    // The default fsm mode is software trigger mode.
    touch_pad_init();
    // Set reference voltage for charging/discharging
    // In this case, the high reference valtage will be 2.7V - 1V = 1.7V
    // The low reference voltage will be 0.5
    // The larger the range, the larger the pulse count value.
    touch_pad_set_voltage(TOUCH_HVOLT_2V7, TOUCH_LVOLT_0V5, TOUCH_HVOLT_ATTEN_1V);
    tp_example_touch_pad_init();
#if TOUCH_FILTER_MODE_EN
    touch_pad_filter_start(TOUCHPAD_FILTER_TOUCH_PERIOD);
#endif
    // Start task to read values sensed by pads
    xTaskCreate(&tp_example_read_task, "touch_pad_read_task", 2048, NULL, 5, NULL);
}
