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

#ifndef __TIMER_PLATFORM_H__
#define __TIMER_PLATFORM_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* the_timer;
    uint32_t ms_timeout;
} awsTimer;

#ifdef __cplusplus
}
#endif

#endif 


