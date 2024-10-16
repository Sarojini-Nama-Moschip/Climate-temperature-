#if 1
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "AHT20_STM32.h"
#include <stdbool.h>

void test_packetization(char *json_string);
void generate_package_data(char *json_string);
extern I2C_HandleTypeDef hi2c1;
uint8_t MQTT_FLAG = 0;
void generate_motion_event()
{

	char json_string[256]={0};
	sprintf(json_string, "{\"MS\":{%s}}","\"MSG\":\"MOTION DETECTED\"");
	publish_message(json_string);
}
void generate_package_data(char *json_string)
{
		float temperature =0.0;
		float humidity =0.0;

		get_time_date();
		Read_TempAndHumiditySensor(&hi2c1,&temperature,&humidity);

		sprintf(json_string, "{\"IG\":{\"temperature\": %f, \"humidity\": %f}}", temperature, humidity);

		// Print the JSON object as a string
		//json_string = cJSON_Print(root);
		//printf("Generated JSON:\n%s\n\r", cJSON_Print(root));
}

void generate_heartbeat_package_data(char *json_string)
{
	    // get Current time and date
        // Create a JSON object
        cJSON *root = cJSON_CreateObject();
		cJSON_AddStringToObject(root, "type", "heartbeat");
		cJSON_AddStringToObject(root, "asset_model_short_code", "EM");


		cJSON_AddStringToObject(root, "ts", "1726827697.8591244");
		cJSON_AddStringToObject(root, "dt", "2024-09-20");

		cJSON_AddStringToObject(root, "ack_status", "no");
		cJSON_AddStringToObject(root, "clr_status", "no");

		cJSON_AddStringToObject(root, "ack_required_from_cloud", "yes");
		cJSON_AddStringToObject(root, "clar_required_from_cloud", "yes");

		cJSON_AddStringToObject(root, "iothub_device_id", "45-c4-75-f3-ca-4a");
		cJSON_AddStringToObject(root, "short_code", "IG");

		// Print the JSON object as a string
		json_string = cJSON_Print(root);
		printf("Generated JSON:\n%s\n", json_string);
		return ;
}

void generate_event_package_data()
{
        int rc;
        // Create a JSON object
        cJSON *root = cJSON_CreateObject();
		cJSON_AddStringToObject(root, "type", "event");
		cJSON_AddStringToObject(root, "asset_model_short_code", "EM");

		cJSON_AddStringToObject(root, "ts", "1726727697.8591244");
		cJSON_AddStringToObject(root, "dt", "2024-09-19");

		cJSON_AddStringToObject(root, "ack_status", "no");
		cJSON_AddStringToObject(root, "clr_status", "no");

		cJSON_AddStringToObject(root, "ack_required_from_cloud", "yes");
		cJSON_AddStringToObject(root, "clar_required_from_cloud", "yes");


		cJSON_AddStringToObject(root, "iothub_device_id", "45-c4-75-f3-ca-4a");

		cJSON *data = cJSON_CreateObject();
		cJSON *SA = cJSON_CreateObject();
		cJSON_AddItemToObject(data, "SA", SA);
		cJSON_AddItemToObject(root, "data", data);


		cJSON_AddStringToObject(SA, "ecode", "MD");
		cJSON_AddStringToObject(SA, "emessage", "Motion detected within 1 feet range with 100 % confidence");
		cJSON_AddStringToObject(SA, "eseverity", "Critical");

		// Print the JSON object as a string
		char *json_string = cJSON_Print(root);
		printf("Generated JSON:\n%s\n", json_string);
}
#endif
