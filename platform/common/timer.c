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
 * @file timer.c
 * @brief Linux implementation of the timer interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>
#include <time.h>
 

#include "timer_platform.h"

#ifdef ONLINE_COMPILER

#define timerclear(tvp)         ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#define timercmp(tvp, uvp, cmp)                                         \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?                             \
            ((tvp)->tv_usec cmp (uvp)->tv_usec) :                       \
            ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < (time_t)0) {                       \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)


#endif //ONLINE_COMPILER

volatile uint32_t mscount = 0;

void onMillisecondTicker(void)
{
    mscount++;
}

void mbed_gettimeofday(struct timeval *now)
{
    uint32_t cnt = mscount;
    now->tv_sec = time(NULL);
    now->tv_usec= cnt - ((long)cnt/1000)*1000;
}


bool has_timer_expired(awsTimer *timer) {
    struct timeval now, res;
    mbed_gettimeofday(&now);
    timersub(&timer->end_time, &now, &res);
    return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
}

void countdown_ms(awsTimer *timer, uint32_t timeout) {
    struct timeval now;
#ifdef __cplusplus
    struct timeval interval = {timeout / 1000, static_cast<int>((timeout % 1000) * 1000)};
#else
    struct timeval interval = {timeout / 1000, (int)((timeout % 1000) * 1000)};
#endif
    mbed_gettimeofday(&now);
    timeradd(&now, &interval, &timer->end_time);
}

uint32_t left_ms(awsTimer *timer) {
    struct timeval now, res;
    uint32_t result_ms = 0;
    mbed_gettimeofday(&now);
    timersub(&timer->end_time, &now, &res);
    if(res.tv_sec >= 0) {
        result_ms = (uint32_t) (res.tv_sec * 1000 + res.tv_usec / 1000);
    }
    return result_ms;
}

void countdown_sec(awsTimer *timer, uint32_t timeout) {
    struct timeval now;
    struct timeval interval = {timeout, 0};
    mbed_gettimeofday(&now);
    timeradd(&now, &interval, &timer->end_time);
}

void init_timer(awsTimer *timer) {
    timer->end_time = (struct timeval) {0, 0};
}

#ifdef __cplusplus
}
#endif

