/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/**
 * @file shadow_sample.c
 * @brief A simple connected window example demonstrating the use of Thing Shadow
 */

#include "mbed.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_shadow_interface.h"
#include "awscerts.h"

/*!
 * The goal of this sample application is to demonstrate the capabilities of shadow.
 * This device(say Connected Window) will open the window of a room based on temperature
 * It can report to the Shadow the following parameters:
 *  1. temperature of the room (double)
 *  2. status of the window (open or close)
 * It can act on commands from the cloud. In this case it will open or close the window based on the 
 * json object "windowOpen" data[open/close]
 *
 * The two variables from a device's perspective are double temperature and bool windowOpen
 * The device needs to act on only on windowOpen variable, so we will create a primitiveJson_t object with callback
 The Json Document in the cloud will be
 {
 "reported": {
 "temperature": 0,
 "windowOpen": false
 },
 "desired": {
 "windowOpen": false
 }
 }
 */

#define ROOMTEMPERATURE_UPPERLIMIT 32.0f
#define ROOMTEMPERATURE_LOWERLIMIT 25.0f
#define STARTING_ROOMTEMPERATURE ROOMTEMPERATURE_LOWERLIMIT

#define MAX_LENGTH_OF_UPDATE_JSON_BUFFER 200

//static uint32_t port = AWS_IOT_MQTT_PORT;
//static uint8_t numPubs = 5;

static void simulateRoomTemperature(float *pRoomTemperature) {
    static float deltaChange;

    if(*pRoomTemperature >= ROOMTEMPERATURE_UPPERLIMIT) {
        deltaChange = -0.5f;
    } else if(*pRoomTemperature <= ROOMTEMPERATURE_LOWERLIMIT) {
        deltaChange = 0.5f;
    }

    *pRoomTemperature += deltaChange;
}

void ShadowUpdateStatusCallback(const char *pThingName, ShadowActions_t action, Shadow_Ack_Status_t status,
                                const char *pReceivedJsonDocument, void *pContextData) {
    IOT_UNUSED(pThingName);
    IOT_UNUSED(action);
    IOT_UNUSED(pReceivedJsonDocument);
    IOT_UNUSED(pContextData);

    if(SHADOW_ACK_TIMEOUT == status) {
        IOT_INFO("Update Timeout--");
    } else if(SHADOW_ACK_REJECTED == status) {
        IOT_INFO("Update RejectedXX");
    } else if(SHADOW_ACK_ACCEPTED == status) {
        IOT_INFO("Update Accepted !!");
    }
}

void windowActuate_Callback(const char *pJsonString, uint32_t JsonStringDataLen, jsonStruct_t *pContext) {
    IOT_UNUSED(pJsonString);
    IOT_UNUSED(JsonStringDataLen);

    if(pContext != NULL) {
        IOT_INFO("Delta - Window state changed to %d", *(bool *) (pContext->pData));
    }
}

Thread aws_shadow_sample(osPriorityNormal, 8*1024, NULL);
void   aws_shadow_sample_task(void);

int main() 
{
    printf("AWS %s Example.\n",__FILE__);
    IOT_INFO("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    aws_shadow_sample.start(aws_shadow_sample_task);
    aws_shadow_sample.join();
    printf(" - - - - - - - ALL DONE - - - - - - - \n");
}

void aws_shadow_sample_task() {
    IoT_Error_t rc = FAILURE;

    char JsonDocumentBuffer[MAX_LENGTH_OF_UPDATE_JSON_BUFFER];
    size_t sizeOfJsonDocumentBuffer = sizeof(JsonDocumentBuffer) / sizeof(JsonDocumentBuffer[0]);
    float temperature = 0.0;

    bool windowOpen = false;
    jsonStruct_t windowActuator;
    windowActuator.cb = windowActuate_Callback;
    windowActuator.pData = &windowOpen;
    windowActuator.dataLength = sizeof(bool);
    windowActuator.pKey = "windowOpen";
    windowActuator.type = SHADOW_JSON_BOOL;

    jsonStruct_t temperatureHandler;
    temperatureHandler.cb = NULL;
    temperatureHandler.pKey = "temperature";
    temperatureHandler.pData = &temperature;
    temperatureHandler.dataLength = sizeof(float);
    temperatureHandler.type = SHADOW_JSON_FLOAT;

    // initialize the mqtt client
    AWS_IoT_Client mqttClient;

    ShadowInitParameters_t sp = ShadowInitParametersDefault;
    sp.pHost = AWS_IOT_MQTT_HOST;
    sp.port = AWS_IOT_MQTT_PORT;
    sp.pClientCRT = (char*)aws_iot_certificate; //mbed change
    sp.pClientKey = (char*)aws_iot_private_key; //mbed change
    sp.pRootCA = (char*)aws_iot_rootCA;         //mbed change
    sp.enableAutoReconnect = false;
    sp.disconnectHandler = NULL;

    IOT_INFO("Shadow Init");
    rc = aws_iot_shadow_init(&mqttClient, &sp);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Shadow Connection Error");
        return;
        }

    ShadowConnectParameters_t scp = ShadowConnectParametersDefault;
    scp.pMyThingName = AWS_IOT_MY_THING_NAME;
    scp.pMqttClientId = AWS_IOT_MQTT_CLIENT_ID;
    scp.mqttClientIdLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);

    IOT_INFO("Shadow Connect");
    rc = aws_iot_shadow_connect(&mqttClient, &scp);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Shadow Connection Error");
        return;
        }

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
    rc = aws_iot_shadow_set_autoreconnect_status(&mqttClient, true);
    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Unable to set Auto Reconnect to true - %d", rc);
        return;
        }

    rc = aws_iot_shadow_register_delta(&mqttClient, &windowActuator);

    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Shadow Register Delta Error");
        }
    temperature = STARTING_ROOMTEMPERATURE;

    // loop and publish a change in temperature
    while(NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || AWS_SUCCESS == rc) {
        rc = aws_iot_shadow_yield(&mqttClient, 200);
        if(NETWORK_ATTEMPTING_RECONNECT == rc) {
            wait(1);
            continue; // If the client is attempting to reconnect we will skip the rest of the loop.
        }
        IOT_INFO("\n=======================================================================================\n");
        IOT_INFO("On Device: window state %s", windowOpen ? "true" : "false");
        simulateRoomTemperature(&temperature);

        rc = aws_iot_shadow_init_json_document(JsonDocumentBuffer, sizeOfJsonDocumentBuffer);
        if(AWS_SUCCESS == rc) {
            rc = aws_iot_shadow_add_reported(JsonDocumentBuffer, sizeOfJsonDocumentBuffer, 2, &temperatureHandler,
                                             &windowActuator);
            if(AWS_SUCCESS == rc) {
                rc = aws_iot_finalize_json_document(JsonDocumentBuffer, sizeOfJsonDocumentBuffer);
                if(AWS_SUCCESS == rc) {
                    IOT_INFO("Update Shadow: %s", JsonDocumentBuffer);
                    rc = aws_iot_shadow_update(&mqttClient, AWS_IOT_MY_THING_NAME, JsonDocumentBuffer,
                                               ShadowUpdateStatusCallback, NULL, 4, true);
                    if( rc != AWS_SUCCESS ) {
                        IOT_ERROR("An error occurred in aws_iot_finalize_json_document - %d", rc);
                        }
                    }
                else{
                    IOT_ERROR("An error occurred in aws_iot_finalize_json_document - %d", rc);
                    }
                }
            else{
                IOT_ERROR("An error occurred in aws_iot_shadow_add_reported - %d", rc);
                }
            }
        else{
            IOT_ERROR("An error occurred in aws_iot_shadow_init_json_document - %d", rc);
            }

        IOT_INFO("*****************************************************************************************\n");
        wait(1);
        }

    if(AWS_SUCCESS != rc) {
        IOT_ERROR("An error occurred in the loop %d", rc);
        }

    IOT_INFO("Disconnecting");
    rc = aws_iot_shadow_disconnect(&mqttClient);

    if(AWS_SUCCESS != rc) {
        IOT_ERROR("Disconnect error %d", rc);
        }
}
