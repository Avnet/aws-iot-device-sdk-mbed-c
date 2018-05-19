
/**
 * @file timer.cpp
 * @brief MBed OS implementation of the timer interface.
 */

#include "mbed.h"

#include "timer_platform.h"

#define MAX_TIMERS 5

static Timer awsTimers[MAX_TIMERS];
static int   timers_used=0;


#ifdef __cplusplus
extern "C" {
#endif

void init_timer(awsTimer *timer) 
{
    timers_used = (++timers_used) % MAX_TIMERS;
    timer->ms_timeout=0;
    timer->the_timer = (void*) &awsTimers[timers_used];
    awsTimers[timers_used].stop();
    awsTimers[timers_used].reset();
}

bool has_timer_expired(awsTimer *timer) 
{
    Timer* t = (Timer*)timer->the_timer;

    return (t->read_ms() > (int)timer->ms_timeout)? true : false;
}

void countdown_ms(awsTimer *timer, uint32_t timeout) 
{
    Timer* t = (Timer*)timer->the_timer;
    timer->ms_timeout = timeout;
    t->reset();
    t->start();
}

void countdown_sec(awsTimer *timer, uint32_t timeout) 
{
    countdown_ms(timer,timeout*1000);
}

uint32_t left_ms(awsTimer *timer) 
{
    Timer* t   = (Timer*)timer->the_timer;
    uint32_t x = (timer->ms_timeout - t->read_ms());
    return (x>0)? x:0;
}


#ifdef __cplusplus
}
#endif

