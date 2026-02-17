#ifndef SHM_RATE_LIMITER_HPP
#define SHM_RATE_LIMITER_HPP

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <time.h>

struct RateLimitEntry
{
    uint32_t ip_addr;
    time_t last_reset;
    int count;
};

const int MAX_CLIENTS = 1024;
const int LIMIT_PERIOD = 60;
const int LIMIT_REQUESTS = 10;

struct SharedMemoryState
{
    pthread_mutex_t mutex;
    int active_connections;
    RateLimitEntry entries[MAX_CLIENTS];

    void init()
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);

        pthread_mutex_init(&mutex, &attr);
        pthread_mutexattr_destroy(&attr);

        active_connections = 0;

        for (int i = 0; i < MAX_CLIENTS; ++i)
        {
            entries[i].ip_addr = 0;
            entries[i].count = 0;
            entries[i].last_reset = 0;
        }
    }
};

class ShmRateLimiter
{
private:
    SharedMemoryState *state;
    size_t shm_size;

    void lock_mutex()
    {
        int ret = pthread_mutex_lock(&state->mutex);
        if (ret == EOWNERDEAD)
        {
            pthread_mutex_consistent(&state->mutex);
        }
        else if (ret != 0)
        {
            perror("pthread_mutex_lock");
            exit(1);
        }
    }

    void unlock_mutex()
    {
        pthread_mutex_unlock(&state->mutex);
    }

public:
    ShmRateLimiter()
    {
        shm_size = sizeof(SharedMemoryState);
        void *addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED)
        {
            perror("mmap");
            exit(1);
        }
        state = static_cast<SharedMemoryState *>(addr);
        state->init();
    }

    bool increment_connection(int max_conn)
    {
        lock_mutex();
        bool allowed = true;
        if (state->active_connections >= max_conn)
        {
            allowed = false;
        }
        else
        {
            state->active_connections++;
        }
        unlock_mutex();
        return allowed;
    }

    void decrement_connection()
    {
        lock_mutex();
        if (state->active_connections > 0)
        {
            state->active_connections--;
        }
        unlock_mutex();
    }

    bool allow_request(uint32_t ip)
    {
        lock_mutex();

        int index = ip % MAX_CLIENTS;
        int start_index = index;

        while (state->entries[index].ip_addr != 0 && state->entries[index].ip_addr != ip)
        {
            index = (index + 1) % MAX_CLIENTS;
            if (index == start_index)
            {
                unlock_mutex();
                return false;
            }
        }

        RateLimitEntry &entry = state->entries[index];
        time_t now = time(NULL);

        if (entry.ip_addr == 0)
        {
            entry.ip_addr = ip;
            entry.last_reset = now;
            entry.count = 1;
        }
        else
        {
            if (now - entry.last_reset > LIMIT_PERIOD)
            {
                entry.last_reset = now;
                entry.count = 1;
            }
            else
            {
                entry.count++;
            }
        }

        bool allowed = entry.count <= LIMIT_REQUESTS;
        unlock_mutex();
        return allowed;
    }
};

#endif
