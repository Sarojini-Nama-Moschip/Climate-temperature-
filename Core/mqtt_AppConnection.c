#include "lwip/apps/mqtt.h"
#include "lwip/netif.h"
#include "lwip/api.h"
#include "lwip/err.h"
#include "lwip/tcp.h"

mqtt_client_t *mqtt_client;
ip_addr_t mqtt_broker_ip;
#if 0
//HostName=PoCIoTHubSoftnautics.azure-devices.net;DeviceId=SampleDevice;SharedAccessKey=EM/0EIK+Kz8Nci5CYXBv6sXZ4eiwjT7uYAIoTKKynAU=
//az iot hub generate-sas-token --device-id SampleDevice --hub-name PoCIoTHubSoftnautics --duration 360000
//"SharedAccessSignature sr=PoCIoTHubSoftnautics.azure-devices.net%2Fdevices%2FSampleDevice&sig=TfF6Pvl4moh5rNqpTSgXsM8SZKrOWTIHx9CBD5mVh9s%3D&se=1727368524"
//PoCIoTHubSoftnautics.azure-devices.net/SampleDevice/?api-version=2020-09-30
//devices/SampleDevice/messages/events/

// Azure IoT Hub configuration
#define IOT_HUB_HOSTNAME "PoCIoTHubSoftnautics.azure-devices.net"
#define DEVICE_ID "SampleDevice"
#define SAS_TOKEN "SharedAccessSignature sr=PoCIoTHubSoftnautics.azure-devices.net%2Fdevices%2FSampleDevice&sig=TfF6Pvl4moh5rNqpTSgXsM8SZKrOWTIHx9CBD5mVh9s%3D&se=1727368524"

// MQTT configuration
#define MQTT_PORT 8883
#define MQTT_CLIENT_ID DEVICE_ID
#define MQTT_USERNAME "PoCIoTHubSoftnautics.azure-devices.net/SampleDevice/?api-version=2020-09-30"
#define MQTT_PASSWORD SAS_TOKEN

// Baltimore CyberTrust Root certificate (in PEM format)
const char *azure_root_ca =
"-----BEGIN CERTIFICATE-----\n"
"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n"
"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n"
"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\n"
"DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\n"
"ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\n"
"VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\n"
"mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\n"
"IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\n"
"mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\n"
"XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\n"
"dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\n"
"jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\n"
"BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\n"
"DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\n"
"9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\n"
"jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\n"
"Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\n"
"ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\n"
"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\n"
"-----END CERTIFICATE-----;\n";


void mqtt_tls_init(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_x509_crt *cacert) {
    int ret;
    //mbedtls_net_context net;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
   // mbedtls_net_init(&net);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(cacert);

    const char *pers = "mqtt_tls";
   // mbedtls_entropy_add_source(&entropy, mbedtls_platform_entropy_poll, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    // Load the Azure Root CA certificate
    ret = mbedtls_x509_crt_parse(cacert, (const unsigned char *)azure_root_ca, strlen(azure_root_ca) + 1);
    if (ret != 0) {
        printf("Failed to parse root CA certificate. Error: %d\n", ret);
        return;
    }

    // Set up the SSL configuration
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED); // Server verification required
    mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);

    // Set up SSL/TLS context
    if(mbedtls_ssl_setup(ssl, conf)!= 0)
    {
    	printf("Failed mbedtls_ssl_setup\n");
    }
    mbedtls_ssl_set_hostname(ssl,IOT_HUB_HOSTNAME);
}


#define MQTT_BROKER_IP "40.79.156.131" // Replace with your broker's IP or domain
#define MQTT_BROKER_PORT 8883          // Typically 1883 for non-TLS MQTT




void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status) {
	if (status == MQTT_CONNECT_ACCEPTED) {
		printf("MQTT connected successfully!\n");
	} else {
		printf("MQTT connection failed with status: %d\n", status);
	}
}


void mqtt_publish_cb(void *arg, err_t err) {
	if (err == ERR_OK) {
		printf("MQTT message published successfully!\n");
	} else {
		printf("Failed to publish message, error: %d\n", err);
	}
}


void mqtt_incoming_publish_cb(void *arg, const char *topic, u32_t tot_len) {
	printf("Incoming message received: topic='%s', length=%d\n", topic, tot_len);
}

void mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags) {
	printf("Message payload: %.*s\n", len, (const char*)data);
}

void publish_message(char* json_string) {
	const char *topic = "devices/SampleDevice/messages/events/";
	//const char *msg = "Hello from STM32 and LwIP!";
	err_t ret = mqtt_publish(mqtt_client, topic, json_string, strlen(json_string), 0, 0, mqtt_publish_cb, NULL);
	if (ret != 0) {
		printf("Failed to Publish!\n");
		return -1;
	}
}

int lwip_net_connect(mbedtls_net_context *ctx, struct sockaddr_in server_addr) {
    ip_addr_t server_ip;
    int ret;
    // Create socket
    ctx->fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->fd < 0) {
        return -1;
    }
    printf("Received address = %d\n", server_addr.sin_addr.s_addr);
    // Prepare server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8883);
    //server_addr.sin_addr.s_addr = server_ip.u_addr.ip4.addr;

    // Connect to the server
    ret = lwip_connect(ctx->fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        lwip_close(ctx->fd);
        return -1;
    }

    return 0;  // Success
}


int lwip_net_recv(void *ctx, unsigned char *buf, size_t len) {
    int ret = lwip_recv(((mbedtls_net_context *)ctx)->fd, buf, len, 0);
    if (ret < 0) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;  // Number of bytes read
}

int lwip_net_send(void *ctx, const unsigned char *buf, size_t len) {
    int ret = lwip_send(((mbedtls_net_context *)ctx)->fd, buf, len, 0);
    if (ret < 0) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;  // Number of bytes sent
}


void azure_mqtt_connect(mqtt_client_t *client)
{
    // Initialize TLS (mbedTLS) structures
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mqtt_tls_init(&ssl, &conf, &cacert);

//    err_t err = dns_gethostbyname("PoCIoTHubSoftnautics.azure-devices.net", &mqtt_broker_ip, NULL, NULL);  // Resolve IoT Hub DNS
//    if (err == ERR_OK) {
//    	printf("dns_gethostbyname Success\n");
//    }
//    HAL_Delay(10000);

	ipaddr_aton(MQTT_BROKER_IP, &mqtt_broker_ip); // Convert IP address string to LwIP IP format

    mbedtls_net_context server_fd;
    struct sockaddr_in server_addr = {0};
    server_addr.sin_addr.s_addr = mqtt_broker_ip.u_addr.ip4.addr;
    err_t err = lwip_net_connect(&server_fd, server_addr);
    //mbedtls_net_connect(net, IOT_HUB_HOSTNAME, "8883", MBEDTLS_NET_PROTO_TCP);
    if (err == ERR_OK) {
            printf("lwip_net_connect\n");
        }
    // Set up the SSL connection on the socket
    mbedtls_ssl_set_bio(&ssl, &server_fd, lwip_net_send, lwip_net_recv, NULL);

//     Perform the SSL/TLS handshake
    if (mbedtls_ssl_handshake(&ssl) != 0) {
        printf("TLS handshake failed\n");
        return;
    }

    printf("Connected to Azure IoT Hub over TLS\n");

	client = mqtt_client_new(); // Allocate memory for the MQTT client
	if (client == NULL) {
		printf("Failed to create MQTT client!\n");
		return;
	}

    // Now you can proceed to use the LWIP MQTT client with the secure connection (using mbedTLS)
    struct mqtt_connect_client_info_t mqtt_info = {
        .client_id = "SampleDevice",
        .client_user = "PoCIoTHubSoftnautics.azure-devices.net/SampleDevice/?api-version=2020-09-30",
        .client_pass = "SharedAccessSignature sr=PoCIoTHubSoftnautics.azure-devices.net%2Fdevices%2FSampleDevice&sig=TfF6Pvl4moh5rNqpTSgXsM8SZKrOWTIHx9CBD5mVh9s%3D&se=1727368524",  // SAS token for authentication
		.keep_alive = 240,                   // Keep-alive interval in seconds
		.will_topic = NULL,                 // Will topic (optional)
		.will_msg = NULL,                   // Will message (optional)
		.will_qos = 0,
		.will_retain = 0
    };

    //mqtt_connect(client, &mqtt_broker_ip, 8883, mqtt_connection_cb, NULL, &mqtt_info);
	err_t ret  = mqtt_client_connect(client, &mqtt_broker_ip, MQTT_BROKER_PORT, mqtt_connection_cb, 0, &mqtt_info);
	if (ret != 0) {
		printf("Failed to connect!\n");
		return -1;
	}
	HAL_Delay(10000);
}


int mqtt_app_connection()
{
	azure_mqtt_connect(mqtt_client);

}
#endif


#if 1

#define MQTT_BROKER_IP "172.17.0.157" // Replace with your broker's IP or domain
#define MQTT_BROKER_PORT 3003          // Typically 1883 for non-TLS MQTT




void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status) {
	if (status == MQTT_CONNECT_ACCEPTED) {
		printf("MQTT connected successfully!\n");
	} else {
		printf("MQTT connection failed with status: %d\n", status);
	}
}


void mqtt_publish_cb(void *arg, err_t err) {
	if (err == ERR_OK) {
		printf("MQTT message published successfully!\n");
	} else {
		printf("Failed to publish message, error: %d\n", err);
	}
}


void mqtt_incoming_publish_cb(void *arg, const char *topic, u32_t tot_len) {
	printf("Incoming message received: topic='%s', length=%d\n", topic, tot_len);
}

void mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags) {
	printf("Message payload: %.*s\n", len, (const char*)data);
}

void publish_message(char* json_string) {
	const char *topic = "STM32/DeviceData";
	err_t ret = mqtt_publish(mqtt_client, topic, json_string, strlen(json_string), 0, 0, mqtt_publish_cb, NULL);
	if (ret != 0) {
		printf("Failed to Publish!\n");
		return;
	}
}


int mqtt_app_connection() {
	// STM32 initialization code (HAL, LwIP, etc.)
	mqtt_client = mqtt_client_new(); // Allocate memory for the MQTT client
	if (mqtt_client == NULL) {
		printf("Failed to create MQTT client!\n");
		return -1;
	}

	struct mqtt_connect_client_info_t mqtt_client_info = {
			.client_id = "SampleDevice",   // Replace with your client ID
			.client_user = "PoCIoTHubSoftnautics.azure-devices.net/SampleDevice/?api-version=2020-09-30",                // Username (if required by broker)
			.client_pass = "SharedAccessSignature sr=PoCIoTHubSoftnautics.azure-devices.net%2Fdevices%2FSampleDevice&sig=pEhucnVpchgpmFoVnZEQ2pUcI3xgKyQB9ImbproQGa4%3D&se=1726944417",                // Password (if required by broker)
			.keep_alive = 240,                   // Keep-alive interval in seconds
			.will_topic = NULL,                 // Will topic (optional)
			.will_msg = NULL,                   // Will message (optional)
			.will_qos = 1,
			.will_retain = 0
	};

    err_t err = dns_gethostbyname("PoCIoTHubSoftnautics.azure-devices.net", &mqtt_broker_ip, NULL, NULL);  // Resolve IoT Hub DNS
    if (err == ERR_OK) {
    	printf("dns_gethostbyname Success\n");
    }


	ipaddr_aton(MQTT_BROKER_IP, &mqtt_broker_ip); // Convert IP address string to LwIP IP format
	err_t ret  = mqtt_client_connect(mqtt_client, &mqtt_broker_ip, MQTT_BROKER_PORT, mqtt_connection_cb, 0, &mqtt_client_info);
	if (ret != 0) {
		printf("Failed to connect!\n");
		return -1;
	}
	HAL_Delay(10000);
	// Initialize MQTT client and connect to broker
	//connect_to_mqtt_broker();

	// Subscribe to a topic
	//subscribe_to_topic();

	// Publish a message
	//publish_message(json_string);

	return 0;
}

#endif



















#if 0
/*
 * mqtt_AppConnection.c
 *
 *  Created on: Sep 21, 2024
 *      Author: Ganesh Thorat
 */
#include "cy_mqtt_api.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "FreeRTOS.h"
#include "task.h"
//#include "semphr.h"

/* MQTT Client configurations */
#define MQTT_BROKER_ADDRESS   "PoCIoTHubSoftnautics.azure-devices.net"  /* Broker URL or IP address */
#define MQTT_BROKER_PORT      8883                  /* Secure MQTT over TLS */
#define MQTT_CLIENT_ID        "SampleDevice"
#define MQTT_KEEP_ALIVE_SEC   60
#define MQTT_USERNAME         "PoCIoTHubSoftnautics.azure-devices.net/SampleDevice/?api-version=2020-09-30"            /* Optional, if needed */
#define MQTT_PASSWORD         "SharedAccessSignature sr=PoCIoTHubSoftnautics.azure-devices.net%2Fdevices%2FSampleDevice&sig=pEhucnVpchgpmFoVnZEQ2pUcI3xgKyQB9ImbproQGa4%3D&se=1726944417"            /* Optional, if needed */

/* Topics for publishing and subscribing */
#define MQTT_PUBLISH_TOPIC    "devices/SampleDevice/messages/events/"
#define MQTT_SUBSCRIBE_TOPIC  "stm32/commands"

/* Message parameters */
#define MQTT_PUBLISH_QOS      1  /* Quality of Service level 0, 1, or 2 */
#define MQTT_SUBSCRIBE_QOS    1

/* Task Stack Size and Priority */
#define MQTT_TASK_STACK_SIZE  1024
#define MQTT_TASK_PRIORITY    5

/* Declare MQTT client handle */
cy_mqtt_t mqtt_client;

/* Mutex to protect access to MQTT Client */
//SemaphoreHandle_t mqtt_mutex;


//void mqtt_event_callback(cy_mqtt_event_t *event)
//{
//    switch (event->event_type)
//    {
//        case CY_MQTT_EVENT_CONNECT:
//            printf("Connected to MQTT broker.\n");
//            break;
//
//        case CY_MQTT_EVENT_DISCONNECT:
//            printf("Disconnected from MQTT broker.\n");
//            break;
//
//        case CY_MQTT_EVENT_PUBLISH:
//            printf("Message published.\n");
//            break;
//
//        case CY_MQTT_EVENT_SUBSCRIBE:
//            printf("Subscribed to topic.\n");
//            break;
//
//        default:
//            break;
//    }
//}

//void mqtt_publish(cy_mqtt_client_t *client)
//{
//    const char *message = "Hello, MQTT!";
//    cy_mqtt_publish(client, MQTT_TOPIC, message, strlen(message), QOS, false);
//}

int mqtt_app_connection(void)
{
	cy_rslt_t result;
	cy_mqtt_connect_info_t connect_info;
	cy_mqtt_publish_info_t publish_info;

	// Initialize MQTT client

	/* Configure the connection info structure */
	memset(&connect_info, 0, sizeof(connect_info));
	connect_info.client_id = MQTT_CLIENT_ID;
	connect_info.client_id_len = strlen(MQTT_CLIENT_ID);
	connect_info.keep_alive_sec = MQTT_KEEP_ALIVE_SEC+240;
	connect_info.username = MQTT_USERNAME;
	connect_info.username_len = strlen(MQTT_USERNAME);
	connect_info.password = MQTT_PASSWORD;
	connect_info.password_len = strlen(MQTT_PASSWORD);


	result = cy_mqtt_init();
	if (result != CY_RSLT_SUCCESS)
	{
		printf("MQTT initialization failed.\n");
		return -1;
	}

	// Connect to the Wi-Fi
	//cy_wcm_connect_ap(&ap_credentials); // Define your AP credentials

	// Connect to MQTT broker
	result = cy_mqtt_connect(mqtt_client, &connect_info);
	if (result != CY_RSLT_SUCCESS)
	{
		printf("MQTT connection failed.\n");
		return -1;
	}

	// Subscribe to a topic
	//    result = cy_mqtt_subscribe(client, MQTT_TOPIC, QOS);
	//    if (result != CY_RSLT_SUCCESS)
	//    {
	//        printf("MQTT subscribe failed.\n");
	//        return -1;
	//    }
	char json_string[256] = {0};
	//current_state = STATE_IDLE;
	generate_heartbeat_package_data(json_string);
	/* Publish data */
	publish_info.qos = MQTT_PUBLISH_QOS;
	publish_info.topic = MQTT_PUBLISH_TOPIC;
	publish_info.payload = json_string;
	publish_info.payload_len = strlen(publish_info.payload);
	// Publish a message
	cy_mqtt_publish(mqtt_client, &publish_info);
	if (result != CY_RSLT_SUCCESS)
	{
		printf("Publish failed!\n");
	}
	else
	{
		printf("Data published successfully!\n");
	}
	// Main loop
	while (1)
	{

		// Handle MQTT events and maintain the connection
		//cy_mqtt_process(mqtt_client);
		// Optional: Add delay or wait for other events
	}

	// Clean up
	cy_mqtt_disconnect(mqtt_client);
	cy_mqtt_deinit();
	return 0;
}


#endif
