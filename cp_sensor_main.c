/* GPIO Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "tcpip_adapter.h"
#include "protocol_examples_common.h"
#include "esp_tls.h"
#include "esp_http_client.h"
#include "http.h"
#include "cilipadi.h"
#include "crypto_aead.h"
#include "http.h"




#define GPIO_OUTPUT_BUZZER    26
#define GPIO_OUTPUT_SERVO_1    21
#define GPIO_OUTPUT_SERVO_2    19
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_BUZZER) | (1ULL<<GPIO_OUTPUT_SERVO_1)|(1ULL<<GPIO_OUTPUT_SERVO_2))
#define GPIO_INPUT_IR_1     23
#define GPIO_INPUT_IR_2     22
#define GPIO_INPUT_VIBRATE     27
#define GPIO_INPUT_PIN_SEL  ((1ULL<<GPIO_INPUT_IR_1) | (1ULL<<GPIO_INPUT_IR_2)|(1ULL<<GPIO_INPUT_VIBRATE))
#define ESP_INTR_FLAG_DEFAULT 0

static xQueueHandle home_intr_queue = NULL;

static void IRAM_ATTR home_isr_handler(void* arg)
{
    uint32_t gpio_num = (uint32_t) arg;
    xQueueSendFromISR(home_intr_queue, &gpio_num, NULL);
}

static void home_task(void* arg)
{
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(home_intr_queue, &io_num, portMAX_DELAY)) {
            	printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
        	gpio_set_level(GPIO_OUTPUT_BUZZER,1);
        }
    }
}

void app_main(void)
{
    gpio_config_t io_conf;
    //disable interrupt
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;
    //disable pull-down mode
    io_conf.pull_down_en = 0;
    //disable pull-up mode
    io_conf.pull_up_en = 0;
    //configure GPIO with the given settings
    gpio_config(&io_conf);

    //interrupt of rising edge
    io_conf.intr_type = GPIO_PIN_INTR_ANYEDGE;
    //bit mask of the pins, use GPIO4/5 here
    io_conf.pin_bit_mask = GPIO_INPUT_PIN_SEL;
    //set as input mode    
    io_conf.mode = GPIO_MODE_INPUT;
    //enable pull-up mode
    io_conf.pull_up_en = 1;
    gpio_config(&io_conf);

    //change gpio intrrupt type for one pin
    gpio_set_intr_type(GPIO_INPUT_IR_1, GPIO_INTR_NEGEDGE);
    gpio_set_intr_type(GPIO_INPUT_IR_2, GPIO_INTR_NEGEDGE);
   // gpio_set_intr_type(GPIO_INPUT_VIBRATE, GPIO_INTR_POSEDGE);

    //create a queue to handle gpio event from isr
    home_intr_queue = xQueueCreate(10, sizeof(uint32_t));
    
   //start gpio task
    xTaskCreate(home_task, "home sensor processing task", 2048, NULL, 10, NULL);

    //install gpio isr service
    gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(GPIO_INPUT_IR_1, home_isr_handler, (void*) GPIO_INPUT_IR_1);
    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(GPIO_INPUT_IR_2, home_isr_handler, (void*) GPIO_INPUT_IR_2);
    gpio_isr_handler_add(GPIO_INPUT_VIBRATE, home_isr_handler, (void*) GPIO_INPUT_VIBRATE);

    //remove isr handler for gpio number.
    //gpio_isr_handler_remove(GPIO_INPUT_IO_0);
    //hook isr handler for specific gpio pin again
    //gpio_isr_handler_add(GPIO_INPUT_IO_0, gpio_isr_handler, (void*) GPIO_INPUT_IO_0);

    int cnt = 0;
    while(1) {
 //       printf("cnt: %d\n", cnt++);
       vTaskDelay(1000 / portTICK_RATE_MS);
//        gpio_set_level(GPIO_OUTPUT_SERVO_1, cnt % 2);
//        gpio_set_level(GPIO_OUTPUT_SERVO_2, cnt % 2);
        gpio_set_level(GPIO_OUTPUT_BUZZER, 0);
	http_main();
    }
}

