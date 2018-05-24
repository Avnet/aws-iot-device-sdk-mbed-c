/*******************************************************************************
 * Copyright (c) 2014 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *******************************************************************************/

/**
 * @file timer_interface.h
 * @brief awsTimer interface definition for MQTT client.
 *
 * Defines an interface to timers that can be used by other system
 * components.  MQTT client requires timers to handle timeouts and
 * MQTT keep alive.
 * Starting point for porting the SDK to the timer hardware layer of a new platform.
 */

#ifndef __TIMER_INTERFACE_H_
#define __TIMER_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The platform specific timer header that defines the awsTimer struct
 */
#include "timer_platform.h"

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief awsTimer Type
 *
 * Forward declaration of a timer struct.  The definition of this struct is
 * platform dependent.  When porting to a new platform add this definition
 * in "timer_<platform>.h" and include that file above.
 *
 */
typedef struct awsTimer  awsTimer;

/**
 * @brief Check if a timer is expired
 *
 * Call this function passing in a timer to check if that timer has expired.
 *
 * @param awsTimer - pointer to the timer to be checked for expiration
 * @return bool - true = timer expired, false = timer not expired
 */
bool has_timer_expired(awsTimer *);

/**
 * @brief Create a timer (milliseconds)
 *
 * Sets the timer to expire in a specified number of milliseconds.
 *
 * @param awsTimer - pointer to the timer to be set to expire in milliseconds
 * @param uint32_t - set the timer to expire in this number of milliseconds
 */
void countdown_ms(awsTimer *, uint32_t);

/**
 * @brief Create a timer (seconds)
 *
 * Sets the timer to expire in a specified number of seconds.
 *
 * @param awsTimer - pointer to the timer to be set to expire in seconds
 * @param uint32_t - set the timer to expire in this number of seconds
 */
void countdown_sec(awsTimer *, uint32_t);

/**
 * @brief Check the time remaining on a given timer
 *
 * Checks the input timer and returns the number of milliseconds remaining on the timer.
 *
 * @param awsTimer - pointer to the timer to be set to checked
 * @return int - milliseconds left on the countdown timer
 */
uint32_t left_ms(awsTimer *);

/**
 * @brief Initialize a timer
 *
 * Performs any initialization required to the timer passed in.
 *
 * @param awsTimer - pointer to the timer to be initialized
 */
void init_timer(awsTimer *);

#ifdef __cplusplus
}
#endif

#endif //__TIMER_INTERFACE_H_
