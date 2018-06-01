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

#include "mbed.h"

#include "easy-connect.h"

#define MBEDTLS_FS_IO 1

#include <stdbool.h>
#include <string.h>
#include <timer_platform.h>
#include <network_interface.h>

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "aws_iot_error.h"
#include "aws_iot_log.h"
#include "network_interface.h"
#include "network_platform.h"

#include "awscerts.h"

/* This is the value used for ssl read timeout (in msec) */
#define IOT_SSL_READ_TIMEOUT 1

/* This defines the value of the debug buffer that gets allocated.
 * The value can be altered based on memory constraints
 */
#ifdef ENABLE_IOT_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#endif


void mbedtls_aws_init( mbedtls_net_context * );
int  mbedtls_aws_connect( mbedtls_net_context *, const char *host, uint16_t port, int proto );
int  mbedtls_aws_bind( mbedtls_net_context *, const char *bind_ip, const char *port, int proto );
int  mbedtls_aws_accept( mbedtls_net_context *bind_ctx, mbedtls_net_context *client_ctx, void *client_ip, size_t buf_size, size_t *ip_len ) ;
void mbedtls_aws_usleep( unsigned long );
int  mbedtls_aws_recv( void *, unsigned char *, size_t );
int  mbedtls_aws_recv_timeout( void *, unsigned char *, size_t , uint32_t );
int  mbedtls_aws_send( void *, const unsigned char *, size_t  );
void mbedtls_aws_free( mbedtls_net_context * );

/*
 * This is a function to do further verification if needed on the cert received
 */

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) 
{
    char buf[1024];
    ((void) data);
    FUNC_ENTRY;

    IOT_DEBUG("Verify requested for (Depth %d):", depth);
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
    IOT_DEBUG("%s", buf);

    if((*flags) == 0) {
        IOT_DEBUG("This certificate has no flags");
    } else {
        IOT_DEBUG(buf, sizeof(buf), "  ! ", *flags);
        IOT_DEBUG("%s", buf);
    }

    FUNC_EXIT_RC( 0);
}

void _iot_tls_set_connect_params(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                                 char *pDevicePrivateKeyLocation, char *pDestinationURL,
                                 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) 
{
    FUNC_ENTRY;
    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

IoT_Error_t iot_tls_init(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                         char *pDevicePrivateKeyLocation, char *pDestinationURL,
                         uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) 
{
    FUNC_ENTRY;
    _iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
                                    pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);

    pNetwork->connect = iot_tls_connect;
    pNetwork->read = iot_tls_read;
    pNetwork->write = iot_tls_write;
    pNetwork->disconnect = iot_tls_disconnect;
    pNetwork->isConnected = iot_tls_is_connected;
    pNetwork->destroy = iot_tls_destroy;

    pNetwork->tlsDataParams.flags = 0;

    FUNC_EXIT_RC( AWS_SUCCESS);
}

IoT_Error_t iot_tls_is_connected(Network *pNetwork) 
{
    FUNC_ENTRY;
    /* Use this to add implementation which can check for physical layer disconnect */
    FUNC_EXIT_RC( NETWORK_PHYSICAL_LAYER_CONNECTED);
}

IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *params) 
{
    int ret = 0;
    const char *pers = "aws_iot_tls_wrapper";
    TLSDataParams *tlsDataParams = NULL;
    char vrfy_buf[512];
    const char *alpnProtocols[] = { "x-amzn-mqtt-ca", NULL };

    FUNC_ENTRY;

    if(pNetwork == NULL) {
        FUNC_EXIT_RC(NULL_VALUE_ERROR);
    }

    if( params != NULL) {
        _iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
                                    params->pDevicePrivateKeyLocation, params->pDestinationURL,
                                    params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
        }

    tlsDataParams = &(pNetwork->tlsDataParams);


    mbedtls_entropy_init(&(tlsDataParams->entropy));
    mbedtls_ctr_drbg_init(&(tlsDataParams->ctr_drbg));
    mbedtls_x509_crt_init(&(tlsDataParams->clicert));
    mbedtls_x509_crt_init(&(tlsDataParams->cacert));
    mbedtls_ssl_init(&(tlsDataParams->ssl));
    mbedtls_ssl_config_init(&(tlsDataParams->conf));
    mbedtls_pk_init(&(tlsDataParams->pkey));

    IOT_DEBUG("\nSeed the random number generator...");
    if((ret = mbedtls_ctr_drbg_seed(&(tlsDataParams->ctr_drbg), mbedtls_entropy_func, &(tlsDataParams->entropy),
                     (const unsigned char *) pers, 
                     strlen(pers))) != 0) {
        IOT_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        FUNC_EXIT_RC(NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED);
    }

    IOT_DEBUG("Load the IoT certificate ...");
    #ifdef USING_SD_CARD
    ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->clicert), pNetwork->tlsConnectParams.pDeviceCertLocation);
    #else
    ret = mbedtls_x509_crt_parse(&(tlsDataParams->clicert), (const unsigned char*)aws_iot_certificate, 
                  strlen(aws_iot_certificate)+1);
    #endif
    if(ret != 0) {
        IOT_ERROR(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\n\n", -ret);
        FUNC_EXIT_RC(NETWORK_X509_DEVICE_CRT_PARSE_ERROR);
    }

    IOT_DEBUG("Load the private key ...");
    #ifdef USING_SD_CARD
    ret = mbedtls_pk_parse_keyfile(&(tlsDataParams->pkey), pNetwork->tlsConnectParams.pDevicePrivateKeyLocation, "");
    #else
    ret = mbedtls_pk_parse_key(&(tlsDataParams->pkey), (const unsigned char*)aws_iot_private_key, 
                  strlen(aws_iot_private_key)+1, NULL, 0 );	
    #endif	
    if(ret != 0) {
        IOT_ERROR(" failed\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\n\n", -ret);
        IOT_DEBUG(" path : %s ", pNetwork->tlsConnectParams.pDevicePrivateKeyLocation);
        FUNC_EXIT_RC(NETWORK_PK_PRIVATE_KEY_PARSE_ERROR);
    }

    IOT_DEBUG("Load the CA root certificate ...");
    #ifdef USING_SD_CARD
    ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->cacert), pNetwork->tlsConnectParams.pRootCALocation);
    #else
    ret = mbedtls_x509_crt_parse(&(tlsDataParams->cacert), (const unsigned char*)aws_iot_rootCA, 
                  sizeof(aws_iot_rootCA));
    #endif
    if(ret < 0) {
        IOT_ERROR(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
        FUNC_EXIT_RC(NETWORK_X509_ROOT_CRT_PARSE_ERROR);
    }

    IOT_DEBUG("done.\nSetting up the SSL/TLS structure...");
    if((ret = mbedtls_ssl_config_defaults(&(tlsDataParams->conf), 
                  MBEDTLS_SSL_IS_CLIENT, 
                  MBEDTLS_SSL_TRANSPORT_STREAM,
                  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        IOT_ERROR(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
        FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
    }

    mbedtls_ssl_conf_ca_chain(&(tlsDataParams->conf), &(tlsDataParams->cacert), NULL);
    mbedtls_ssl_conf_rng(&(tlsDataParams->conf), mbedtls_ctr_drbg_random, &(tlsDataParams->ctr_drbg));

    if((ret = mbedtls_ssl_setup(&(tlsDataParams->ssl), &(tlsDataParams->conf))) != 0) {
        IOT_ERROR(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
    }

    if((ret = mbedtls_ssl_set_hostname(&(tlsDataParams->ssl), pNetwork->tlsConnectParams.pDestinationURL)) != 0) {
        IOT_ERROR(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
    }
    IOT_DEBUG("Set the SSL BIO ...");
    mbedtls_ssl_set_bio(&(tlsDataParams->ssl), &(tlsDataParams->server_fd), mbedtls_aws_send, NULL,
                        mbedtls_aws_recv_timeout);
    mbedtls_ssl_conf_verify(&(tlsDataParams->conf), _iot_tls_verify_cert, NULL);
    if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) 
        mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
    else
        mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);

    if((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams->conf), &(tlsDataParams->clicert), 
                   &(tlsDataParams->pkey))) != 0) {
        IOT_ERROR(" failed\n!!! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
        }

    mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), pNetwork->tlsConnectParams.timeout_ms);

    /* Use the AWS IoT ALPN extension for MQTT if port 443 is requested. */
    if(443 == pNetwork->tlsConnectParams.DestinationPort) {
        if((ret = mbedtls_ssl_conf_alpn_protocols(&(tlsDataParams->conf), alpnProtocols)) != 0) {
            IOT_ERROR(" failed\n  ! mbedtls_ssl_conf_alpn_protocols returned -0x%x\n\n", -ret);
            FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
        }
    }

    mbedtls_aws_init(&(tlsDataParams->server_fd));
    if( (tlsDataParams->server_fd).fd == -1 ) {
        IOT_ERROR(" Network connected failed!\n");
        FUNC_EXIT_RC(NETWORK_ERR_NET_CONNECT_FAILED);
        }

    IOT_DEBUG("Connecting to %s/%d...", pNetwork->tlsConnectParams.pDestinationURL, pNetwork->tlsConnectParams.DestinationPort);
    if((ret = mbedtls_aws_connect(&(tlsDataParams->server_fd), pNetwork->tlsConnectParams.pDestinationURL, 
                        pNetwork->tlsConnectParams.DestinationPort, 
                        MBEDTLS_NET_PROTO_TCP)) != 0) {
        IOT_ERROR(" failed\n  ! mbedtls_aws_connect returned -0x%x\n\n", -ret);
        switch(ret) {
            case MBEDTLS_ERR_NET_SOCKET_FAILED:
                FUNC_EXIT_RC(NETWORK_ERR_NET_SOCKET_FAILED);
            case MBEDTLS_ERR_NET_UNKNOWN_HOST:
                FUNC_EXIT_RC(NETWORK_ERR_NET_UNKNOWN_HOST);
            case MBEDTLS_ERR_NET_CONNECT_FAILED:
            default:
                FUNC_EXIT_RC(NETWORK_ERR_NET_CONNECT_FAILED);
        };
    }

    IOT_DEBUG("\n\nPerform the SSL/TLS handshake...\n\n\n\n");

    while((ret = mbedtls_ssl_handshake(&(tlsDataParams->ssl))) != 0) {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            IOT_ERROR(" failed\n  ! mbedtls_ssl_handshake returned -0x%x (%d)\n", -ret, ret);
            if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                IOT_ERROR( "Unable to verify the server's certificate.  Either it is invalid, or you\n"
                           "didn't set ca_file or ca_path to an appropriate value.  Alternatively,\n"
                           "you may want to use auth_mode=optional for testing purposes.\n" );
                }
            FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
            }
        }

    IOT_DEBUG("[ Protocol is %s ]\n[ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(tlsDataParams->ssl)),
    mbedtls_ssl_get_ciphersuite(&(tlsDataParams->ssl)));
    if((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams->ssl))) >= 0) {
        IOT_DEBUG("[Record expansion is %d]", ret);
        } 
    else{
        IOT_DEBUG("[Record expansion is unknown (compression)]");
        }
    IOT_DEBUG("Verifying peer X.509 certificate...");

    if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
        if((tlsDataParams->flags = mbedtls_ssl_get_verify_result(&(tlsDataParams->ssl))) != 0) {
            IOT_ERROR(" FAIL\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams->flags);
            IOT_ERROR("%s\n", vrfy_buf);
            ret = SSL_CONNECTION_ERROR;
        } else {
            IOT_DEBUG("Verified OK\n");
            ret = AWS_SUCCESS;
        }
    } else {
        IOT_DEBUG("Server Verification skipped\n");
        ret = AWS_SUCCESS;
    }

#ifdef ENABLE_IOT_DEBUG
    if (mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)) != NULL) {
        unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
        IOT_DEBUG("Peer certificate information    ...\n");
        mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)));
        IOT_DEBUG("%s", buf);
    }
#endif

    mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), IOT_SSL_READ_TIMEOUT);

    FUNC_EXIT_RC((IoT_Error_t) ret);
}

IoT_Error_t iot_tls_write(Network *pNetwork, unsigned char *pMsg, size_t len, awsTimer *timer, size_t *written_len) 
{
    size_t written_so_far;
    bool isErrorFlag = false;
    int frags;
    int ret = 0;
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);

    FUNC_ENTRY;
    for(written_so_far = 0, frags = 0;
        written_so_far < len && !has_timer_expired(timer); written_so_far += ret, frags++) {
        while(!has_timer_expired(timer) &&
              (ret = mbedtls_ssl_write(&(tlsDataParams->ssl), pMsg + written_so_far, len - written_so_far)) <= 0) {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                IOT_ERROR("FAILED!\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
                /* All other negative return values indicate connection needs to be reset.
                 * Will be caught in ping request so ignored here */
                isErrorFlag = true;
                break;
            }
        }
        if(isErrorFlag) {
            break;
        }
    }

    *written_len = written_so_far;

    if(isErrorFlag) {
        FUNC_EXIT_RC(NETWORK_SSL_WRITE_ERROR);
    } else if(has_timer_expired(timer) && written_so_far != len) {
        FUNC_EXIT_RC(NETWORK_SSL_WRITE_TIMEOUT_ERROR);
    }

    FUNC_EXIT_RC(AWS_SUCCESS);
}

IoT_Error_t iot_tls_read(Network *pNetwork, unsigned char *pMsg, size_t len, awsTimer *timer, size_t *read_len) 
{
    mbedtls_ssl_context *ssl = &(pNetwork->tlsDataParams.ssl);
    size_t rxLen = 0;
    int ret=0;
    FUNC_ENTRY;

    while (len > 0) {
        // This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read

        while( ret == 0 && !has_timer_expired(timer) )
            ret = mbedtls_ssl_read(ssl, pMsg, len);

        if (ret == 0) {
            FUNC_EXIT_RC(NETWORK_SSL_NOTHING_TO_READ);
            }
        if (ret > 0) {
            rxLen += ret;
            pMsg += ret;
            len -= ret;
            } 
        else if ((ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_TIMEOUT)) {
            FUNC_EXIT_RC(NETWORK_SSL_READ_ERROR);
            }
        }

    if (len == 0) {
        *read_len = rxLen;
        FUNC_EXIT_RC(AWS_SUCCESS);
    }

    if (rxLen == 0) {
        FUNC_EXIT_RC(NETWORK_SSL_NOTHING_TO_READ);
    } else {
        FUNC_EXIT_RC(NETWORK_SSL_READ_TIMEOUT_ERROR);
    }
}

IoT_Error_t iot_tls_disconnect(Network *pNetwork) 
{
    mbedtls_ssl_context *ssl = &(pNetwork->tlsDataParams.ssl);
    int ret = 0;
    FUNC_ENTRY;
    do {
        ret = mbedtls_ssl_close_notify(ssl);
    } while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* All other negative return values indicate connection needs to be reset.
     * No further action required since this is disconnect call */

    FUNC_EXIT_RC(AWS_SUCCESS);
}

IoT_Error_t iot_tls_destroy(Network *pNetwork) 
{
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    FUNC_ENTRY;

    mbedtls_aws_free(&(tlsDataParams->server_fd));

    mbedtls_x509_crt_free(&(tlsDataParams->clicert));
    mbedtls_x509_crt_free(&(tlsDataParams->cacert));
    mbedtls_pk_free(&(tlsDataParams->pkey));
    mbedtls_ssl_free(&(tlsDataParams->ssl));
    mbedtls_ssl_config_free(&(tlsDataParams->conf));
    mbedtls_ctr_drbg_free(&(tlsDataParams->ctr_drbg));
    mbedtls_entropy_free(&(tlsDataParams->entropy));

    FUNC_EXIT_RC(AWS_SUCCESS);
}


