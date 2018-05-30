/**
 * @file subscribe_publish_cpp_sample.cpp
 * @brief simple MQTT publish and subscribe on the same topic in C++
 *
 * This example takes the parameters from the aws_iot_config.h file and establishes a connection to the AWS IoT MQTT Platform.
 * It subscribes and publishes to the same topic - "sdkTest/sub"
 *
 * If all the certs are correct, you should see the messages received by the application in a loop.
 *
 * The application takes in the certificate path, host name , port and the number of times the publish should happen.
 *
 */
#include "mbed.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

#include "easy-connect.h"
#include "mbed-trace/mbed_trace.h"

//#include "WNC14A2AInterface.h"

/**
 * @brief Default cert location
 */
//char certDirectory[PATH_MAX + 1];
//char rootCA[PATH_MAX + 1];
//char clientCRT[PATH_MAX + 1];
//char clientKey[PATH_MAX + 1];
//char CurrentWD[PATH_MAX + 1];
char cPayload[100];

//Thread aws_subscribe_publish(osPriorityNormal, 16*1024, NULL);
Thread aws_subscribe_publish(osPriorityNormal, 8*1024, NULL);
void   aws_subscribe_publish_task(void);

void trace_printer(const char* str) {
    printf("%s\r\n",str);
}

/**
 * @brief This parameter will avoid infinite loop of publish and exit the program after certain number of publishes
 */
uint32_t publishCount = 0;

void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen, IoT_Publish_Message_Params *params, void *pData) 
{
    IOT_UNUSED(pData);
    IOT_UNUSED(pClient);
    IOT_INFO("Subscribe callback");
    IOT_INFO("%.*s\t%.*s", topicNameLen, topicName, (int) params->payloadLen, (char *) params->payload);
}

void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) 
{
    IOT_WARN("MQTT Disconnect");
    IoT_Error_t rc = FAILURE;

    if(NULL == pClient) 
        return;

    IOT_UNUSED(data);

    if(aws_iot_is_autoreconnect_enabled(pClient)) {
        IOT_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
        } 
    else{
        IOT_WARN("Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(pClient);
        if(NETWORK_RECONNECTED == rc) {
            IOT_WARN("Manual Reconnect Successful");
            } 
        else{
            IOT_WARN("Manual Reconnect Failed - %d", rc);
            }
        }
}

int main() 
{
    mbed_trace_init();
    mbed_trace_print_function_set(trace_printer);

    printf("AWS %s Example.\n",__FILE__);
    IOT_INFO("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    aws_subscribe_publish.start(aws_subscribe_publish_task);
    aws_subscribe_publish.join();
    printf(" - - - - - - - ALL DONE - - - - - - - \n");
}

void aws_subscribe_publish_task()
{
    bool        infinitePublishFlag = true;
    IoT_Error_t rc = FAILURE;


    int32_t i = 0;

    AWS_IoT_Client client;
    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

    IoT_Publish_Message_Params paramsQOS0;
    IoT_Publish_Message_Params paramsQOS1;

//    memset(rootCA, 0x00, sizeof(rootCA));
//    memset(clientCRT, 0x00, sizeof(clientCRT));
//    memset(clientKey, 0x00, sizeof(clientKey));
//    memset(CurrentWD, 0x00, sizeof(CurrentWD));
    memset(cPayload, 0x00, sizeof(cPayload));
//    memset(certDirectory, 0x00, sizeof(certDirectory));

//    snprintf(rootCA, sizeof(rootCA), "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_ROOT_CA_FILENAME);
//    snprintf(clientCRT, sizeof(clientCRT), "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_CERTIFICATE_FILENAME);
//    snprintf(clientKey, sizeof(clientKey), "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_PRIVATE_KEY_FILENAME);

//    IOT_DEBUG("rootCA %s", rootCA);
//    IOT_DEBUG("clientCRT %s", clientCRT);
//    IOT_DEBUG("clientKey %s", clientKey);

    mqttInitParams.enableAutoReconnect = false; // We enable this later below
    mqttInitParams.pHostURL = AWS_IOT_MQTT_HOST;
    mqttInitParams.port = AWS_IOT_MQTT_PORT;
    mqttInitParams.pRootCALocation = AWS_IOT_ROOT_CA_FILENAME;
    mqttInitParams.pDeviceCertLocation = AWS_IOT_CERTIFICATE_FILENAME;
    mqttInitParams.pDevicePrivateKeyLocation = AWS_IOT_PRIVATE_KEY_FILENAME;
    mqttInitParams.mqttCommandTimeout_ms = 20000;
    mqttInitParams.tlsHandshakeTimeout_ms = 5000;
    mqttInitParams.isSSLHostnameVerify = true;
    mqttInitParams.disconnectHandler = disconnectCallbackHandler;
    mqttInitParams.disconnectHandlerData = NULL;
    rc = aws_iot_mqtt_init(&client, &mqttInitParams);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
        return;
        }

    connectParams.keepAliveIntervalInSec = 600;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    connectParams.pClientID = (char *)AWS_IOT_MQTT_CLIENT_ID;
    connectParams.clientIDLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
    connectParams.isWillMsgPresent = false;

    IOT_INFO("Connecting...");
    rc = aws_iot_mqtt_connect(&client, &connectParams);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
        return;
        }

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
    rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Unable to set Auto Reconnect to true - %d", rc);
        return;
        }

    IOT_INFO("Subscribing...");
    rc = aws_iot_mqtt_subscribe(&client, "sdkTest/sub", 11, QOS0, iot_subscribe_callback_handler, NULL);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Error subscribing : %d ", rc);
        return;
        }

    sprintf(cPayload, "%s : %ld ", "hello from SDK", i);

    paramsQOS0.qos = QOS0;
    paramsQOS0.payload = (void *) cPayload;
    paramsQOS0.isRetained = 0;

    paramsQOS1.qos = QOS1;
    paramsQOS1.payload = (void *) cPayload;
    paramsQOS1.isRetained = 0;

    if(publishCount != 0) {
        infinitePublishFlag = false;
        }

    while( (NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || AWS_SUCCESS == rc) && (publishCount > 0 || infinitePublishFlag)) {
        sprintf(cPayload, "%s : %ld ", "hello from SDK QOS0", i++);
        paramsQOS0.payloadLen = strlen(cPayload);
        rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS0);
        if(publishCount > 0) 
            publishCount--;

        sprintf(cPayload, "%s : %ld ", "hello from SDK QOS1", i++);
        paramsQOS1.payloadLen = strlen(cPayload);
        rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS1);
        if (rc == MQTT_REQUEST_TIMEOUT_ERROR) {
            IOT_WARN("QOS1 publish ack not received.\n");
            rc = AWS_SUCCESS;
            }
        if(publishCount > 0) 
            publishCount--;

        IOT_INFO("-->sleep");
        wait(5);
        }

    if(AWS_SUCCESS != rc) {
        IOT_ERROR("An error occurred in the loop.\n");
        } 
    else{
        IOT_INFO("Publish done\n");
        }
    printf("... AWS_SUBSCRIBE_PUBLISH EXAMPLE DONE!\n");
}
