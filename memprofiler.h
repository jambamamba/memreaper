#pragma once


#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include <map>

struct Snapshot
{
    void* m_mem;
    size_t m_size;
    std::string m_callstack;
    char m_threadname[256];
    long m_timestampms;

    Snapshot(void* mem = nullptr, size_t size = 0/*, const std::string& callstack = ""*/, const std::string &callstack = "");
};

struct MemProfiler
{
    MemProfiler();
    ~MemProfiler(){}
    void Dump();
    void HandleMalloc(void *ptr, size_t size);
    void HandleFree(void *ptr);

    pthread_mutex_t m_mutex;
    pthread_mutexattr_t m_attr;
    std::map<void*, Snapshot> m_snapshots;
    long m_startms;
};
