/*
 *  TCP/IP or UDP/IP networking functions
 *
 *  This version of net_sockets.c is setup to use ARM easy-connect for network connectivity
 *
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
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


NetworkInterface *network = NULL;
TCPSocket        mbedtls_socket;
bool             network_connected = false;

/*
 * Initialize a context
 */
void mbedtls_aws_init( mbedtls_net_context *ctx )
{
    FUNC_ENTRY;

    if( network != NULL )
        network->disconnect();       //disconnect from the current network

    network_connected = false;
    network = easy_connect(true);
    if (!network) {
        IOT_DEBUG("Network Connection Failed!");
        return;
        }
    IOT_DEBUG("Modem SW Revision: %s", FIRMWARE_REV(network));
    network_connected = true;
    ctx->fd = 1;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 * return 0 if success, otherwise error is returned
 */
int mbedtls_aws_connect( mbedtls_net_context *ctx, const char *host, uint16_t port, int proto )
{
    FUNC_ENTRY;
    if( !network_connected ) {
        IOT_DEBUG("No network connection");
        FUNC_EXIT_RC(NETWORK_ERR_NET_CONNECT_FAILED);
        }

    int ret = mbedtls_socket.open(network) || mbedtls_socket.connect(host,port);
    if( ret != 0 ){
        IOT_DEBUG("Socket Open Failed - %d",ret);
        }

    FUNC_EXIT_RC(ret);
}

/*
 * Create a listening socket on bind_ip:port
 */
int mbedtls_aws_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto )
{
    FUNC_EXIT_RC(MBEDTLS_ERR_NET_BIND_FAILED);
}

/*
 * Accept a connection from a remote client
 */
int mbedtls_aws_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
    FUNC_ENTRY;
    FUNC_EXIT_RC(MBEDTLS_ERR_NET_ACCEPT_FAILED );
}

/*
 * Set the socket blocking or non-blocking
 */
int mbedtls_aws_set_block( mbedtls_net_context *ctx )
{
        mbedtls_socket.set_blocking(true);
        return 0;
}

int mbedtls_aws_set_nonblock( mbedtls_net_context *ctx )
{
    mbedtls_socket.set_blocking(false);
    return 0;
}

/*
 * Portable usleep helper
 */
void mbedtls_aws_usleep( unsigned long usec )
{
    FUNC_ENTRY;
    Timer t;
    t.start();
    while( t.read_us() < (int)usec )
        /* wait here */ ;
}

/*
 * Read at most 'len' characters
 */
int mbedtls_aws_recv( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    FUNC_ENTRY;
    if( fd < 0 )
        FUNC_EXIT_RC(MBEDTLS_ERR_NET_INVALID_CONTEXT );

    ret = (int) mbedtls_socket.recv( buf, len );

    if( ret == NSAPI_ERROR_WOULD_BLOCK )
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    FUNC_EXIT_RC(ret );
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_aws_recv_timeout( void *ctx, unsigned char *buf, size_t len, uint32_t timeout )
{
    int   ret, ttime;
    Timer t;
    FUNC_ENTRY;

    t.start();
    do {
        ret = mbedtls_aws_recv( ctx, buf, len );
        ttime = t.read_ms();
       }
    while( ttime < (int)timeout && ret < 0 );

    if( ret < 0 && ttime >= (int)timeout )
        ret = MBEDTLS_ERR_SSL_TIMEOUT;
    FUNC_EXIT_RC(ret);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_aws_send( void *ctx, const unsigned char *buf, size_t len )
{
    int ret = NSAPI_ERROR_WOULD_BLOCK;
    Timer t;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    FUNC_ENTRY;

    if( fd < 0 )
        FUNC_EXIT_RC(NETWORK_PHYSICAL_LAYER_DISCONNECTED);

    t.start();
    while( ret == NSAPI_ERROR_WOULD_BLOCK && t.read_ms() < 100)
        ret = mbedtls_socket.send(buf, len);

    if( ret < 0 )
        ret = MBEDTLS_ERR_NET_SEND_FAILED;

    FUNC_EXIT_RC( ret );
}

/*
 * Gracefully close the connection
 */
void mbedtls_aws_free( mbedtls_net_context *ctx )
{
    FUNC_ENTRY;
    if( !network_connected || ctx->fd < 0 ) {
        FUNC_EXIT;
        }

    mbedtls_socket.close();
    network->disconnect();       //disconnect from the current network
    ctx->fd = -1;
    FUNC_EXIT;
}

