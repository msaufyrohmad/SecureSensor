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
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "tcpip_adapter.h"
#include "protocol_examples_common.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#define TOUCH_PAD_NO_CHANGE   (-1)
#define TOUCH_THRESH_NO_USE   (0)
#define TOUCH_FILTER_MODE_EN  (1)
#define TOUCHPAD_FILTER_TOUCH_PERIOD (10)

#ifdef CONFIG_EXAMPLE_IPV4
#define HOST_IP_ADDR CONFIG_EXAMPLE_IPV4_ADDR
#else
#define HOST_IP_ADDR CONFIG_EXAMPLE_IPV6_ADDR
#endif
#define PORT CONFIG_EXAMPLE_PORT

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


static const char *TAG = "example";
//static const char *payload = "Message from ESP32-sAUFY ";
char *payload="TESTING DUA";

/* 
 * read 8 touch sensor values and encrypt with cilipadi 
 * 24 bytes ciphertext with 16 bytes original plaintext
 */
unsigned char* read_encrypt_task(void *pvParameter)
{
    uint16_t touch_value;
    unsigned char touch_plain[24]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	    				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	    				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    int i;
    printf("Touch Sensor normal mode read, the output format is: \nTouchpad num:[raw data]\n\n");
    while (1) {
        	printf("\n");
	    for(i=0;i<8;i++){
		touch_pad_read(i,&touch_value);
	    	touch_plain[i*2+1]=touch_value;
		touch_plain[i*2]=touch_value>>8;
        	printf("T%d:[%0x%0x] ",i,touch_plain[i*2],touch_plain[i*2+1]);
	    }
        	printf("\n");
	crypto_aead_encrypt(c, &clen, touch_plain, mlen, ad, adlen, NULL, npub, k);
 
	printf("\nCiphertext %llu bytes:",mlen);
        for (i=0; i <16; ++i) {
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
    return c;
}

static void tcp_client_task(void *pvParameters)
{
    char rx_buffer[128];
    char addr_str[128];
    int addr_family;
    int ip_protocol;
    unsigned char *cipher=NULL;
    cipher = read_encrypt_task(NULL);
	printf("cipher pointer: %p \n",cipher);
	    
	int x;
	for (x=0;x<20;x++)
		printf("%04x ",*(cipher+x));
	printf("\n");
while (1) {

#ifdef CONFIG_EXAMPLE_IPV4
        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = inet_addr(HOST_IP_ADDR);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(PORT);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;
        inet_ntoa_r(dest_addr.sin_addr, addr_str, sizeof(addr_str) - 1);
#else // IPV6
        struct sockaddr_in6 dest_addr;
        inet6_aton(HOST_IP_ADDR, &dest_addr.sin6_addr);
        dest_addr.sin6_family = AF_INET6;
        dest_addr.sin6_port = htons(PORT);
        addr_family = AF_INET6;
        ip_protocol = IPPROTO_IPV6;
        inet6_ntoa_r(dest_addr.sin6_addr, addr_str, sizeof(addr_str) - 1);
#endif

        int sock =  socket(addr_family, SOCK_STREAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created, connecting to %s:%d", HOST_IP_ADDR, PORT);

        int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err != 0) {
            ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
            break;
        }

      ESP_LOGI(TAG, "Successfully connected");

        while (1) {
            int err = send(sock, payload, strlen(payload), 0);
            if (err < 0) {
                ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
                break;
            }

            int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(TAG, "recv failed: errno %d", errno);
                break;
            }
            // Data received
            else {
                rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string
                ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
                ESP_LOGI(TAG, "%s", rx_buffer);
            }

            vTaskDelay(2000 / portTICK_PERIOD_MS);
        }

        if (sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}
	
	
	

static void tp_example_touch_pad_init(void)
{
    for (int i = 0;i< TOUCH_PAD_MAX;i++) {
        touch_pad_config(i, TOUCH_THRESH_NO_USE);
    }
}

void app_main(void)
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
    ESP_ERROR_CHECK(nvs_flash_init());
  //  tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
//    tcpip_adapter_init();
//    ESP_ERROR_CHECK(example_connect());

    // Start task to read values sensed by pads
    xTaskCreate(&read_encrypt_task, "read and encrypt touch", 2048, NULL, 5, NULL);
 //   ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */

//    xTaskCreate(tcp_client_task, "tcp_client", 4096, NULL, 5, NULL);
}





