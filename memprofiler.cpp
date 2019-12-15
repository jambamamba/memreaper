#include <atomic>
#include <cstdlib>
#include <cxxabi.h>
#include <dirent.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <fstream>
#include <future>
#include <iostream>
#include <libgen.h>
#include <malloc.h>
#include <map>
#include <mutex>
#include <pthread.h>
#include <regex>
#include <sstream>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>


namespace  {
//https://beesbuzz.biz/code/4399-Embedding-binary-resources-with-CMake-and-C-11
class Resource {
public:
    Resource(const char *start, const char *end): mData(start),
                                                  mSize(end - start)
    {}

    const char * const &data() const { return mData; }
    const size_t &size() const { return mSize; }

    const char *begin() const { return mData; }
    const char *end() const { return mData + mSize; }

private:
    const char *mData;
    size_t mSize;
};
}//namespace

#define LOAD_RESOURCE(x) ([]() {                                            \
        extern const char _binary_##x##_start, _binary_##x##_end;           \
        return Resource(&_binary_##x##_start, &_binary_##x##_end);          \
    })()

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
    ~MemProfiler();
    void Dump();
    void SafeDump();
    void LogMemoryUse();
    void HandleMalloc(void *ptr, size_t size);
    void HandleFree(void *ptr);
    std::string UpdateRuntime(long now);
    void StartLoggerThread();

    pthread_mutex_t m_mutex;
    pthread_mutexattr_t m_attr;
    std::multimap<void*, Snapshot> m_snapshots;
    long m_startms;
    std::future<void> m_future;
    bool m_quit = false;
    long m_allocd_pages = 0;
    //values read from /tmp/memreaper/
    std::string m_appname;
    size_t m_min_alloc_bytes = 100;//1024;
    size_t m_min_num_allocs = 10;
    long m_dump_interval_seconds = 60;
    long m_memlog_interval_seconds = 10;
    size_t m_max_points_in_graph = 2000;
    size_t m_max_pies = 20;//5;
    size_t m_max_callstacks = 40;
};

struct MemorySizes
{
   unsigned long VirtualMemSize = 0;
   unsigned long ResidentMemSize = 0;
   unsigned long SharedMemSize = 0;
};

static MemProfiler profiler;

static std::atomic<bool> recursing_malloc(false);
static std::atomic<bool> recursing_free(false);

static void *(*__MALLOC_HOOK_VOLATILE old_malloc_hook)(size_t __size,
                                                     const void *);
static void (*__MALLOC_HOOK_VOLATILE old_free_hook) (void *__ptr,
                                                   const void *);

static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

static std::string exeName()
{
    static char exe[4096] = {0};
    if(exe[0]) {
        return exe;
    }
    int ret = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if(ret ==-1) {
        return "";
    }
    char *base = basename(exe);
    memcpy(exe, base, strlen(base));
    exe[strlen(base)] = 0;
    return exe;
}
static bool isDir(const char* path)
{
    struct stat buf;
    stat(path, &buf);
    return S_ISDIR(buf.st_mode);
}
static int copyFile(const char* source, const char* destination)
{
    int input, output;
    if ((input = open(source, O_RDONLY)) == -1)
    {
        return -1;
    }
    if ((output = creat(destination, 0660)) == -1)
    {
        close(input);
        return -1;
    }

    off_t bytesCopied = 0;
    struct stat fileinfo = {0};
    fstat(input, &fileinfo);
    int result = sendfile(output, input, &bytesCopied, fileinfo.st_size);

    return result;
}

static void copyDir(const char *inputDir, const std::string &outDir)
{
    DIR *pDIR;
    struct dirent *entry;
    std::string tmpStr, tmpStrPath, outStrPath, inputDir_str = inputDir;

    if (isDir(inputDir) == false)
    {
//        std::cout << "This is not a folder \n";
        return;
    }


    if( pDIR = opendir(inputDir_str.c_str()) )
    {

        while(entry = readdir(pDIR)) // get folders and files names
        {
            tmpStr = entry->d_name;
            if( strcmp(entry->d_name, ".")  != 0 && strcmp(entry->d_name, "..") != 0 )
            {
                tmpStrPath = inputDir_str;
                tmpStrPath.append( "/" );
                tmpStrPath.append( tmpStr );

                if (isDir(tmpStrPath.c_str()))
                {
                    outStrPath = outDir;
                    outStrPath.append( "/" );
                    outStrPath.append( tmpStr );
                    mkdir(outStrPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

                    copyDir(tmpStrPath.c_str(), outStrPath);
                }
                else
                {
                    outStrPath = outDir;
                    outStrPath.append( "/" );
                    outStrPath.append( tmpStr );
                    copyFile(tmpStrPath.c_str(), outStrPath.c_str());
                }
            }
        }
        closedir(pDIR);
    }
}

static bool fileExists(const char *filename)
{
  struct stat   buffer;
  return (stat (filename, &buffer) == 0);
}

//https://stackoverflow.com/questions/52560466/c-regex-replace-whole-word
static std::string& replace_all_mute(std::string& s,
    const std::string& from, const std::string& to)
{
    if(!from.empty())
        for(std::size_t pos = 0; (pos = s.find(from, pos) + 1); pos += to.size())
            s.replace(--pos, from.size(), to);
    return s;
}

static std::string readFile(const std::string &file)
{
    if(file.size() == 0 ||
            !fileExists(file.c_str())) {
        return "";
    }
    std::ifstream stream;

    stream.open(file);
    std::stringstream buffer;
    buffer << stream.rdbuf();
    stream.close();

    return buffer.str();
}

static int readNumFromFile(const std::string &file, int defaultNum)
{
    std::string txt = readFile(file);
    return (txt.size() > 0) ?
                std::stoi(txt) :
                defaultNum;
}

static void writeFile(const std::string &file, const std::string &contents)
{
    std::ofstream stream;
    stream.open(file, std::ios::out);
    stream << contents;
    stream.close();
}

static void appendFile(const std::string &file, const std::string &contents)
{
    std::ofstream stream;
    stream.open(file, std::ios::out|std::ios::app);
    stream << contents;
    stream.close();
}

static std::string memory(const std::string &tag)
{
    std::string mem = readFile("/proc/meminfo");

    std::smatch regexMatch;
    if(!std::regex_search(mem, regexMatch, std::regex(tag + ":\\s*([0-9]*) kB")))
    {
       return "";
    }
    if(regexMatch.size() < 2)
    {
       return "";
    }
    return regexMatch[1];
}

MemorySizes statm()
{
    enum class ProcParserState : int {
       VIRTUAL_MEMORY_SZ,
       RESIDENT_MEMORY_SZ,
       SHARED_MEMORY_SZ,
       DONE
    };
    MemorySizes memsizes;

   auto pspath = std::string("/proc/").
           append(std::to_string(getpid())).
           append("/statm");
   std::string line = readFile(pspath);
   std::istringstream str(line);
   std::string token;
   int i = 0;
   while (getline(str, token, ' ')) {
       if(token.size() > 0) {
           switch(i) {
           case (int)ProcParserState::VIRTUAL_MEMORY_SZ:
               memsizes.VirtualMemSize = std::stoi(token);
               i++;
               break;
           case (int)ProcParserState::RESIDENT_MEMORY_SZ:
               memsizes.ResidentMemSize = std::stoi(token);
               i++;
               break;
           case (int)ProcParserState::SHARED_MEMORY_SZ:
               memsizes.SharedMemSize = std::stoi(token);
               i++;
               break;
           }
       }
   }
   return memsizes;
}

static std::string stackdump()
{
   const size_t max_dump_size = 50;
   void* dump[max_dump_size];
   size_t size = backtrace(dump, max_dump_size);
   char** messages = backtrace_symbols(dump, static_cast<int>(size)); // overwrite sigaction with caller's address

   // dump stack: skip first frame, since that is here
   std::ostringstream oss;
   for (size_t idx = 1; idx < size && messages != nullptr; ++idx) {
      char* mangled_name = 0, *offset_begin = 0, *offset_end = 0;
      // find parantheses and +address offset surrounding mangled name
      for (char* p = messages[idx]; *p; ++p) {
         if (*p == '(') {
            mangled_name = p;
         } else if (*p == '+') {
            offset_begin = p;
         } else if (*p == ')') {
            offset_end = p;
            break;
         }
      }

      // if the line could be processed, attempt to demangle the symbol
      if (mangled_name && offset_begin && offset_end &&
            mangled_name < offset_begin) {
         *mangled_name++ = '\0';
         *offset_begin++ = '\0';
         *offset_end++ = '\0';

         int status;
         char* real_name = abi::__cxa_demangle(mangled_name, 0, 0, &status);
         // if demangling is successful, output the demangled function name
         if (status == 0) {
            oss << "\n\tstack dump [" << idx << "]  " << messages[idx] << " : " << real_name << "+";
            oss << offset_begin << offset_end << std::endl;
         }// otherwise, output the mangled function name
         else {
            oss << "\tstack dump [" << idx << "]  " << messages[idx] << mangled_name << "+";
            oss << offset_begin << offset_end << std::endl;
         }
         free(real_name); // mallocated by abi::__cxa_demangle(...)
      } else {
         // no demangling done -- just dump the whole line
         oss << "\tstack dump [" << idx << "]  " << messages[idx] << std::endl;
      }
   } // END: for(size_t idx = 1; idx < size && messages != nullptr; ++idx)
   free(messages);
   return oss.str();
}

extern "C" {

static void *my_malloc_hook(size_t, const void *);
static void my_free_hook (void *, const void *);

static void *
my_malloc_hook (size_t size, const void *caller)
{
    pthread_mutex_lock(&profiler.m_mutex);
  void *ptr;
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */
  ptr = malloc (size);
  /* Save underlying hooks */
  old_malloc_hook = __malloc_hook;
  old_free_hook = __free_hook;

  profiler.HandleMalloc(ptr, size);

  /* Restore our own hooks */
  __malloc_hook = my_malloc_hook;
  __free_hook = my_free_hook;
  pthread_mutex_unlock(&profiler.m_mutex);
  return ptr;
}

static void
my_free_hook (void *ptr, const void *caller)
{
    pthread_mutex_lock(&profiler.m_mutex);
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */
  free (ptr);
  /* Save underlying hooks */
  old_malloc_hook = __malloc_hook;
  old_free_hook = __free_hook;

  profiler.HandleFree(ptr);

  /* Restore our own hooks */
  __malloc_hook = my_malloc_hook;
  __free_hook = my_free_hook;
  pthread_mutex_unlock(&profiler.m_mutex);
}


}//C

//=====================================================================================
Snapshot::Snapshot(void* mem, size_t size, const std::string &callstack)
    : m_mem(mem)
    , m_size(size)
    , m_callstack(callstack)
{
    pthread_getname_np( pthread_self(), m_threadname, sizeof(m_threadname)-1 );

    m_timestampms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch()).count();
}

//=====================================================================================
MemProfiler::MemProfiler()
{
    m_appname = readFile("/memreaper/appname");
    if(m_appname.size() == 0)
    {
        return;
    }
    rtrim(m_appname);
    if(strcmp(exeName().c_str(), m_appname.c_str()) != 0)
    {
        std::cout << "Not latching on to " << exeName() << ", did not match " << m_appname << "\n";
        return;
    }
    pthread_mutexattr_init(&m_attr);
    pthread_mutexattr_settype(&m_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&m_mutex, &m_attr);

    mkdir("/tmp/memreaper", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    mkdir("/memreaper", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    mkdir("/tmp/memreaper/rsc", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    mkdir("/tmp/memreaper/logs", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    std::remove("/tmp/memreaper/dump");

    m_min_alloc_bytes = readNumFromFile("/memreaper/min_alloc_bytes", m_min_alloc_bytes);
    m_min_num_allocs = readNumFromFile("/memreaper/min_num_allocs", m_min_num_allocs);
    m_dump_interval_seconds = readNumFromFile("/memreaper/dump_interval_seconds", m_dump_interval_seconds);
    m_max_pies = readNumFromFile("/memreaper/max_pies", m_max_pies);
    m_max_callstacks = readNumFromFile("/memreaper/max_callstacks", m_max_callstacks);
    m_memlog_interval_seconds = readNumFromFile("/memreaper/memlog_interval_seconds", m_memlog_interval_seconds);
    m_max_points_in_graph = readNumFromFile("/memreaper/max_points_in_graph", m_max_points_in_graph);

    m_startms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

    std::cout << "======================MemReaper======================\n"
              << " SELF: " << m_appname << "\n"
              << " PID: " << std::to_string(getpid()) << "\n"
              << " Monitoring App: " << m_appname << "\n"
              << " Only log mallocs >= " << m_min_alloc_bytes << " bytes\n"
              << " Only log mallocs that occur >= " << m_min_num_allocs << " times for each size\n"
              << " Only show " << m_max_pies << " pies\n"
              << " Only show " << m_max_callstacks << " callstacks\n"
              << " Dump backtraces for allocated memory every " << m_dump_interval_seconds << " seconds\n"
              << " Log total memory usage every " << m_memlog_interval_seconds << " seconds\n"
              << " Show last " << m_max_points_in_graph << " points in line graph\n"
              << "--->\n";

    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;

    StartLoggerThread();
}
//=====================================================================================
MemProfiler::~MemProfiler()
{
    if(!m_future.valid()) {
        return;
    }
    m_quit = true;
    SafeDump();
    std::cout << "======================~MemReaper======================\n";
}
//=====================================================================================
void MemProfiler::SafeDump()
{
    pthread_mutex_lock(&profiler.m_mutex);
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    Dump();
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    pthread_mutex_unlock(&profiler.m_mutex);
}
//=====================================================================================
void MemProfiler::StartLoggerThread()
{
    auto func = [this] {
        long lastmemlogat = 0;
        long lastdumpat = 0;
        while(!m_quit) {
            long now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
            if(fileExists( "/tmp/memreaper/dump") ||
                    (now - lastdumpat >= m_dump_interval_seconds)) {
                {
                    SafeDump();
                }
                lastdumpat = now;
            }
            if(lastmemlogat == 0 ||
                    (now - lastmemlogat >= m_memlog_interval_seconds)) {
                LogMemoryUse();
                lastmemlogat = now;
            }
            usleep(1 * 1000*1000);
        }
    };
    m_future = std::async(std::launch::async, func);
}
//=====================================================================================
void MemProfiler::HandleMalloc(void *ptr, size_t size/*, const std::string &callstack*/)
{
    if(size > m_min_alloc_bytes){
        HandleFree(ptr);
        profiler.m_snapshots.insert({ptr,
                                     Snapshot(ptr, size, stackdump())
                                    });
    }
}

//=====================================================================================
void MemProfiler::HandleFree(void *ptr)
{
    while(true) {
        auto it = profiler.m_snapshots.find(ptr);
        if(it == profiler.m_snapshots.end()){
            break;
        }
        profiler.m_snapshots.erase(it);

    }
}

//=====================================================================================
std::string MemProfiler::UpdateRuntime(long now)
{
    long milliseconds = now - m_startms;
    long hours = milliseconds/1000/60/60;
    long minutes = (milliseconds-hours*1000*60*60)/1000/60;
    long seconds = (milliseconds-hours*1000*60*60-minutes*1000*60)/1000;
    milliseconds = (milliseconds-hours*1000*60*60-minutes*1000*60-seconds*1000);
    std::string timeunit = hours > 0 ? "hours" : minutes > 0 ? "minutes" : seconds > 0 ? "seconds" : "milliseconds";
    std::string runtime = hours > 0 ? std::string( 2 - std::to_string(hours).size(), '0').append(std::to_string(hours)).append(":") : "";
    runtime += minutes > 0 ? std::string( 2 - std::to_string(minutes).size(), '0').append(std::to_string(minutes)).append(":") : (hours > 0) ? "00:" : "";
    runtime += seconds > 0 ? std::string( 2 - std::to_string(seconds).size(), '0').append(std::to_string(seconds)).append(":" ) : (hours > 0 || minutes > 0) ? "00:" : "";
    runtime += milliseconds > 0 ? std::string( 3 - std::to_string(milliseconds).size(), '0').append(std::to_string(milliseconds)) : "000";
    return std::string("Ran ").
            append(m_appname).
            append(" for ").
            append(runtime).
            append(" ").
            append(timeunit);
}

//=====================================================================================
void MemProfiler::LogMemoryUse()
{
    static size_t i = 0;
    long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
    long milliseconds = now - m_startms;
    MemorySizes memsnap = statm();
    m_allocd_pages = memsnap.ResidentMemSize/* + memsnap.VirtualMemSize + memsnap.SharedMemSize*/;
    long appmem = m_allocd_pages * getpagesize()/1024;
    std::string jsfile = std::string("/tmp/memreaper/logs/memtimeline.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".js");
    std::string csvfile = std::string("/tmp/memreaper/logs/memtimeline.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".csv");
    static long prev = m_allocd_pages;
    if(i==0)
    {
        appendFile(jsfile,
               std::string("{second:'").
               append(std::to_string(milliseconds/1000)).
               append("',memory:").
               append(std::to_string(appmem)).
               append("}")
               );
        appendFile(csvfile,
               std::string("Seconds").
               append(",").
               append("kB").
               append("\n")
               );
        i++;
    }
    else if (prev != m_allocd_pages)
    {
        appendFile(jsfile,
               std::string("\n,{second:'").
               append(std::to_string(milliseconds/1000)).
               append("',memory:").
               append(std::to_string(appmem)).
               append("}")
               );
        appendFile(csvfile,
               std::string(std::to_string(milliseconds/1000)).
               append(",").
               append(std::to_string(appmem)).
               append("\n")
               );
        i++;
    }
    prev = m_allocd_pages;
}

//=====================================================================================
void MemProfiler::Dump()
{
    std::remove("/tmp/memreaper/dump");

    std::string snapshotsdump = std::string("/tmp/memreaper/snapshots.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".txt");

    typedef std::map<size_t/*memsize*/, std::vector<const Snapshot*>> SizeMap;
    SizeMap mallocszSnapshotsMap;
    for(const auto &ptrSnapshotPair : m_snapshots)
    {
        ptrSnapshotPair.second.m_mem;
        ptrSnapshotPair.second.m_size;
        ptrSnapshotPair.second.m_callstack;
        ptrSnapshotPair.second.m_timestampms - m_startms;

        mallocszSnapshotsMap[ptrSnapshotPair.second.m_size].push_back(&ptrSnapshotPair.second);
    }

    typedef std::map<size_t/*mode*/, std::map<size_t/*memsize*/, std::vector<const Snapshot*>>> ModeMap;
    ModeMap snapshotsByMode;
    for(const auto &mallocszSnapshotsPair : mallocszSnapshotsMap)
    {
        if(mallocszSnapshotsPair.second.size() > m_min_num_allocs)
        {
            size_t mode = mallocszSnapshotsPair.second.size();
            size_t mallocsz = mallocszSnapshotsPair.first;
            snapshotsByMode[mode][mallocsz] = mallocszSnapshotsPair.second;
        }
    }

    long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
    std::string pieData;
    std::string barGraphData;
    size_t pieIdx = 0;
    std::ofstream file;
    std::string report = std::string("/tmp/memreaper/report.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".txt");
    file.open(report.c_str(), std::ios::out);
    for (auto it = snapshotsByMode.rbegin(); it != snapshotsByMode.rend(); ++it)
    {
        if(pieIdx >= m_max_pies) { break; }
        size_t mode = it->first;
        std::map<size_t/*memsize*/, std::vector<const Snapshot*>> mallocszSnapshotsMap = it->second;
        for(const auto &mallocszSnapshotsPair : mallocszSnapshotsMap)
        {
            file << "=====================================================\n";
            std::map<size_t/*milliseconds*/, const Snapshot*> snapshotsByTime;
            for(const Snapshot *snapshot : mallocszSnapshotsPair.second)
            {
                snapshotsByTime[snapshot->m_timestampms - m_startms] = snapshot;
            }

            size_t szidx = 0;
            size_t bytes = 0;
            for(const auto &timeSnapshotPair : snapshotsByTime)
            {
                const Snapshot* snapshot = timeSnapshotPair.second;
                if(szidx == 0)
                {
                    bytes = snapshot->m_size;
                    size_t kb = bytes/1024;
                    size_t mb = kb/1024;
                    file << "Allocated "
                         << (mb > 0 ? mb : kb > 0 ? kb : bytes)
                         << (mb > 0 ? " MB" : kb > 0 ? " KB" : " Bytes")
                         << " (" << snapshot->m_size << " Bytes)"
                         << " " << it->first << " times"
                         << "\n";
                    if(pieIdx > 0) { pieData += ","; }
                    pieData +=
                            std::string("{ \"piekey\": ") +
                            std::to_string(pieIdx) +
                            std::string(", \"label\": \"") +
                            std::to_string(mb > 0 ? mb : kb > 0 ? kb : bytes) +
                            std::string(mb > 0 ? " MB" : kb > 0 ? " KB" : " Bytes") +
                            "\", \"value\": " +
                            std::to_string(it->first) +
                            ", \"bytes\": " +
                            std::to_string(bytes) +
                            " }";
                    barGraphData +=
                    std::string(pieIdx==0 ? "\n" : ",\n").append("{\"data\":[");
                    pieIdx++;
                    file << "Milliseconds since start: ";
                }
                else
                {
                    bytes += snapshot->m_size;
                }
                long milliseconds = snapshot->m_timestampms - m_startms;
                std::stringstream memaddrs;
                memaddrs << std::hex << snapshot->m_mem;
                if(szidx >= snapshotsByTime.size() - m_max_callstacks){
                    barGraphData += "{ \"millisecond\": \""+std::to_string(milliseconds)+
                            "\", \"second\": \""+std::to_string(milliseconds/1000)+
                            "\", \"bytes\": \""+std::to_string(bytes)+
                            "\", \"memaddrs\": \""+memaddrs.str()+
//                            "\", \"callstack\": \"abc\""+
                            "\", \"callstack\": `"+snapshot->m_callstack+"`"+
                            " }";
                }

                file << (milliseconds);

                if(szidx == snapshotsByTime.size()-1)
                {
                    barGraphData += "]}";
                    file << "\n";
                }
                else
                {
                    if(szidx >= snapshotsByTime.size() - m_max_callstacks) {barGraphData += ",\n";}
                    file << ",";
                }
                szidx++;
            }
        }
    }
    file.close();

    Resource jquery_min_js = LOAD_RESOURCE(graph_jquery_min_js);
    Resource morris_css = LOAD_RESOURCE(graph_morris_css);
    Resource morris_min_js = LOAD_RESOURCE(graph_morris_min_js);
    Resource raphael_min_js = LOAD_RESOURCE(graph_raphael_min_js);
    Resource grim_reaper_png = LOAD_RESOURCE(graph_grim_reaper_png);
    Resource webpage_template = LOAD_RESOURCE(graph_webpage_template);

    std::string html = std::string(webpage_template.data(), webpage_template.size());
    size_t memtotal = std::stoull(memory("MemTotal"));//kb
    size_t memavail = std::stoull(memory("MemAvailable"));//kb

    replace_all_mute(html, "[/*exename*/]", std::string(m_appname).append(" [PID:").append(std::to_string(getpid())).append("]"));
    replace_all_mute(html, "[/*mem app name*/]", m_appname);
    replace_all_mute(html, "[/*mem used*/]", std::to_string((memtotal - memavail)*100/memtotal));
    replace_all_mute(html, "[/*mem free*/]", std::to_string((memavail*100)/memtotal));
    replace_all_mute(html, "[/*allocmem*/]", "");
    UpdateRuntime(now);
    replace_all_mute(html, "[/*runtime*/]", UpdateRuntime(now));

    std::string totalsData = std::string("{label:\"Used\",value:").
            append(std::to_string((memtotal - memavail)*100/memtotal)).
            append("}, {label:\"Free\",value:").
            append(std::to_string((memavail*100)/memtotal)).
            append("}");
    std::string totalsdatafile = std::string("/tmp/memreaper/logs/totalsdata.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".js");
    appendFile(totalsdatafile,
               std::string(fileExists(totalsdatafile.c_str()) ? "," : "")+
               std::string("{\"second\":")+
               std::to_string((now-m_startms)/1000)+
               std::string(",\n\"data\":[")+
               totalsData+
               std::string("]\n}\n"));
    replace_all_mute(html, "[/*totalsdata*/]", readFile(totalsdatafile));

    std::string piedatafile = std::string("/tmp/memreaper/logs/piedata.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".js");
    appendFile(piedatafile,
               std::string(fileExists(piedatafile.c_str()) ? "," : "")+
               std::string("{\"second\":")+
               std::to_string((now-m_startms)/1000)+
               std::string(",\n\"data\":[")+
               pieData+
               std::string("]\n}\n"));
    replace_all_mute(html, "[/*piedata*/]", readFile(piedatafile));

    std::string bargraphdatafile = std::string("/tmp/memreaper/logs/bargraphdata.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".js");
    appendFile(bargraphdatafile,
               std::string(fileExists(bargraphdatafile.c_str()) ? "," : "")+
               std::string("{\"second\":")+
               std::to_string((now-m_startms)/1000)+
               std::string(",\n\"data\":{")+
               barGraphData+
               std::string("}\n}\n"));
    replace_all_mute(html, "[/*bargraphdata*/]",
                     barGraphData
//                     readFile(bargraphdatafile)
                     );

    std::string jsfile = std::string("/tmp/memreaper/logs/memtimeline.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".js");
    replace_all_mute(html, "[/*memtimeline*/]", readFile(jsfile));

    if(!fileExists("/tmp/memreaper/jquery.min.js")) {writeFile("/tmp/memreaper/rsc/jquery.min.js", std::string(jquery_min_js.data(), jquery_min_js.size()));}
    if(!fileExists("/tmp/memreaper/morris.css")) {writeFile("/tmp/memreaper/rsc/morris.css", std::string(morris_css.data(), morris_css.size()));}
    if(!fileExists("/tmp/memreaper/morris.min.js")) {writeFile("/tmp/memreaper/rsc/morris.min.js", std::string(morris_min_js.data(), morris_min_js.size()));}
    if(!fileExists("/tmp/memreaper/raphael-min.js")) {writeFile("/tmp/memreaper/rsc/raphael-min.js", std::string(raphael_min_js.data(), raphael_min_js.size()));}
    if(!fileExists("/tmp/memreaper/grim-reaper.png")) {writeFile("/tmp/memreaper/rsc/grim-reaper.png", std::string(grim_reaper_png.data(), grim_reaper_png.size()));}

    std::string reporthtml = std::string("/tmp/memreaper/report.").
            append(m_appname).
            append(".").
            append(std::to_string(getpid())).
            append(".html");
    writeFile(reporthtml.c_str(), html);

    symlink(reporthtml.c_str(), "/tmp/memreaper/index.html");
}

