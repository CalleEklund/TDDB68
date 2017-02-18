#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/list.h"
#include "threads/synch.h"

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

/*Struct to be placed in the tick list to map the time of sleep(in ticks) of each thread*/
struct p_sleep_time 
{
  int64_t sleep_ticks;
  int pid;
  int64_t start;
  struct semaphore sema;
  struct list_elem elem;
  };
void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

void timer_print_stats (void);

bool time_left_sleep(const struct list_elem* new_e, const struct list_elem* cmp_e, void* aux);

#endif /* devices/timer.h */
