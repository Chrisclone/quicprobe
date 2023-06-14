/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#define QUICREACH_VERSION_ONLY 1

#include <stdio.h>
#include <string>
#include <thread>
#include <vector>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <condition_variable>
#include <msquic.hpp>
#include "quicreach.ver"
#include "domains.hpp"
#ifdef _WIN32
#define QUIC_CALL __cdecl
#else
#define QUIC_CALL
#endif

using namespace std;

const MsQuicApi* MsQuic;

// TODO - Make these public?
#define QUIC_VERSION_2          0x709a50c4U     // Second official version (host byte order)
#define QUIC_VERSION_1          0x00000001U     // First official version (host byte order)

const uint32_t SupportedVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2};
const MsQuicVersionSettings VersionSettings(SupportedVersions, 2);

struct ReachConfig {
    bool PrintStatistics {false};
    bool RequireAll {false};
    std::vector<const char*> HostNames;
    QuicAddr Address;
    uint32_t Parallel {1};
    uint16_t Port {443};
    MsQuicAlpn Alpn {"h3"};
    MsQuicSettings Settings;
    QUIC_CREDENTIAL_FLAGS CredFlags {QUIC_CREDENTIAL_FLAG_CLIENT};
    const char* OutCsvFile {nullptr};
    ReachConfig() {
        Settings.SetDisconnectTimeoutMs(1000);
        Settings.SetHandshakeIdleTimeoutMs(1000);
        Settings.SetPeerUnidiStreamCount(3);
        Settings.SetMinimumMtu(1288); /* We use a slightly larger than default MTU:
                                         1240 (QUIC) + 40 (IPv6) + 8 (UDP) */
        Settings.SetMaximumMtu(1500);
    }
} Config;

struct ReachResults {
    uint32_t TotalCount {0};
    uint32_t ReachableCount {0};
    uint32_t TooMuchCount {0};
    uint32_t MultiRttCount {0};
    uint32_t RetryCount {0};
    uint32_t IPv6Count {0};
    uint32_t Quicv2Count {0};
    // Number of currently active connections.
    uint32_t ActiveCount {0};
    // Synchronization for active count.
    mutex Mutex;
    condition_variable NotifyEvent;
    void WaitForActiveCount() {
        while (ActiveCount >= Config.Parallel) {
            unique_lock<mutex> lock(Mutex);
            NotifyEvent.wait(lock, [this]() { return ActiveCount < Config.Parallel; });
        }
    }
    void WaitForAll() {
        while (ActiveCount) {
            unique_lock<mutex> lock(Mutex);
            NotifyEvent.wait(lock, [this]() { return ActiveCount == 0; });
        }
    }
    void IncActive() {
        lock_guard<mutex> lock(Mutex);
        ++ActiveCount;
    }
    void DecActive() {
        unique_lock<mutex> lock(Mutex);
        ActiveCount--;
        NotifyEvent.notify_all();
    }
} Results;

void IncStat( _Inout_ _Interlocked_operand_ uint32_t volatile &Addend) {
#if _WIN32
    InterlockedIncrement((volatile long*)&Addend);
#else
    __sync_add_and_fetch((long*)&Addend, (long)1);
#endif
}

struct ReachConnection : public MsQuicConnection {
    const char* HostName;
    bool HandshakeComplete {false};
    QUIC_STATISTICS_V2 Stats {0};
    ReachConnection(
        _In_ const MsQuicRegistration& Registration,
        _In_ const MsQuicConfiguration& Configuration,
        _In_ const char* HostName
    ) : MsQuicConnection(Registration, CleanUpAutoDelete, Callback), HostName(HostName) {
        IncStat(Results.TotalCount);
        Results.IncActive();
        if (IsValid() && Config.Address.GetFamily() != QUIC_ADDRESS_FAMILY_UNSPEC) {
            InitStatus = SetRemoteAddr(Config.Address);
        }
        if (IsValid()) {
            InitStatus = Start(Configuration, HostName, Config.Port);
        }
        if (!IsValid()) {
            Results.DecActive();
        }
    }
    static QUIC_STATUS QUIC_API Callback(
        _In_ MsQuicConnection* _Connection,
        _In_opt_ void* ,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept {
        auto Connection = (ReachConnection*)_Connection;
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Connection->OnReachable();
            Connection->Shutdown(0);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            if (!Connection->HandshakeComplete) Connection->OnUnreachable();
            Results.DecActive();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream); // Shouldn't do this
        }
        return QUIC_STATUS_SUCCESS;
    }
    bool succeeded = false;
private:
    void OnReachable() {
        succeeded = true;
        HandshakeComplete = true;
        IncStat(Results.ReachableCount);
        GetStatistics(&Stats);
        QuicAddr RemoteAddr;
        GetRemoteAddr(RemoteAddr);
        uint32_t Version, VersionLength = sizeof(Version);
        GetParam(QUIC_PARAM_CONN_QUIC_VERSION, &VersionLength, &Version);
        auto HandshakeTime = (uint32_t)(Stats.TimingHandshakeFlightEnd - Stats.TimingStart);
        auto InitialTime = (uint32_t)(Stats.TimingInitialFlightEnd - Stats.TimingStart);
        auto Amplification = (double)Stats.RecvTotalBytes / (double)Stats.SendTotalBytes;
        auto TooMuch = false, MultiRtt = false;
        auto Retry = (bool)(Stats.StatelessRetry);
        if (Stats.SendTotalPackets != 1) {
            MultiRtt = true;
            IncStat(Results.MultiRttCount);
        } else {
            TooMuch = Amplification > 3.0;
            if (TooMuch) IncStat(Results.TooMuchCount);
        }
        if (Retry) {
            IncStat(Results.RetryCount);
        }
        if (RemoteAddr.GetFamily() == QUIC_ADDRESS_FAMILY_INET6) {
            IncStat(Results.IPv6Count);
        }
        if (Version == QUIC_VERSION_2) {
            IncStat(Results.Quicv2Count);
        }
        if (Config.PrintStatistics){
            const char HandshakeTags[3] = {
                TooMuch ? '!' : (MultiRtt ? '*' : ' '),
                Retry ? 'R' : ' ',
                '\0'};
            QUIC_ADDR_STR AddrStr;
            QuicAddrToString(&RemoteAddr.SockAddr, &AddrStr);
            unique_lock<mutex> lock(Results.Mutex);
            printf("%30s   %3u.%03u ms   %3u.%03u ms   %3u.%03u ms   %u:%u %u:%u (%2.1fx)  %4u   %4u     %s   %20s   %s\n",
                HostName,
                Stats.Rtt / 1000, Stats.Rtt % 1000,
                InitialTime / 1000, InitialTime % 1000,
                HandshakeTime / 1000, HandshakeTime % 1000,
                (uint32_t)Stats.SendTotalPackets,
                (uint32_t)Stats.RecvTotalPackets,
                (uint32_t)Stats.SendTotalBytes,
                (uint32_t)Stats.RecvTotalBytes,
                Amplification,
                Stats.HandshakeClientFlight1Bytes,
                Stats.HandshakeServerFlight1Bytes,
                Version == QUIC_VERSION_1 ? "v1" : "v2",
                AddrStr.Address,
                HandshakeTags);
        }
    }
    void OnUnreachable() {
        if (Config.PrintStatistics) {
            unique_lock<mutex> lock(Results.Mutex);
            printf("%30s\n", HostName);
        }
    }
};

bool TestReachability() {
    MsQuicRegistration Registration("quicreach");
    MsQuicConfiguration Configuration(Registration, Config.Alpn, Config.Settings, MsQuicCredentialConfig(Config.CredFlags));
    if (!Configuration.IsValid()) { printf("Configuration initializtion failed!\n"); return false; }
    Configuration.SetVersionSettings(VersionSettings);
    Configuration.SetVersionNegotiationExtEnabled();

    if (Config.PrintStatistics)
        printf("%30s          RTT       TIME_I       TIME_H              SEND:RECV    C1     S1    VER                     IP\n", "SERVER");

    for (auto HostName : Config.HostNames) {
        new ReachConnection(Registration, Configuration, HostName);
        Results.WaitForActiveCount();
    }

    Results.WaitForAll();

    if (Config.PrintStatistics) {
        if (Results.ReachableCount > 1) {
            printf("\n");
            printf("%4u domain(s) attempted\n", (uint32_t)Config.HostNames.size());
            printf("%4u domain(s) reachable\n", Results.ReachableCount);
            if (Results.MultiRttCount)
                printf("%4u domain(s) required multiple round trips (*)\n", Results.MultiRttCount);
            if (Results.TooMuchCount)
                printf("%4u domain(s) exceeded amplification limits (!)\n", Results.TooMuchCount);
            if (Results.RetryCount)
                printf("%4u domain(s) sent RETRY packets (R)\n", Results.RetryCount);
            if (Results.IPv6Count)
                printf("%4u domain(s) used IPv6\n", Results.IPv6Count);
            if (Results.Quicv2Count)
                printf("%4u domain(s) used QUIC v2\n", Results.Quicv2Count);
        }
    }

    return Config.RequireAll ? ((size_t)Results.ReachableCount == Config.HostNames.size()) : (Results.ReachableCount != 0);
}

enum QuicProbeState {PROBE_DOWN, PROBE_UP, PROBE_PAUSED, PROBE_STOPPED, PROBE_NONEXISTANT};
enum ClientState    {CLIENT_DOWN, CLIENT_HEALTHY, CLIENT_UNHEALTHY, CLIENT_UNKNOWN, CLIENT_PROBE_NONEXISTANT};

struct AsyncQuicProbe {
    private:
        const MsQuicApi* api         = nullptr;
        QuicProbeState   state       = PROBE_NONEXISTANT;
        ClientState      clientState = CLIENT_UNKNOWN;
        const char*      targetUrl;
        thread*          worker;
        bool             paused;
        bool             stopped;
    public:
        mutex            Mutex;
        AsyncQuicProbe(const char* url, const MsQuicApi* api){
            targetUrl = _strdup(url);
            this->api = api;
            beginProbe();
        }

        ~AsyncQuicProbe(){
            delete[] targetUrl;
        }

        static void    threadFunc(AsyncQuicProbe* parent); //looping quic query function that runs inside thread
        void           beginProbe();
        void           pauseProbe();
        void           stopProbe();
        QuicProbeState getProbeState();    
        ClientState    getClientState();
};

bool reachableURL(_In_ const char* url){ //blocking function, TODO FIX LEAKY MEMORY   
    struct Container {
        ReachConnection* n;
    };

    Container c;

    auto fun = [url, &c](){
        MsQuicRegistration registration(url);
        MsQuicConfiguration Configuration(registration, Config.Alpn, Config.Settings, MsQuicCredentialConfig(Config.CredFlags));
        
        c.n = new ReachConnection(registration, Configuration, url);
    };
    thread t(fun);
    t.join();
    bool succeed = c.n->succeeded;

    return succeed;
}

mutex printMutex;
mutex numMutex;
int thread_count = 0;
int thread_max = std::thread::hardware_concurrency() * 2;
void AsyncQuicProbe::threadFunc(AsyncQuicProbe* parent){
    parent->Mutex.lock();
    const char* url = parent->targetUrl;

    while(!parent->stopped){
        parent->Mutex.unlock();
        this_thread::sleep_for(1s);

        parent->Mutex.lock();
        while(!parent->paused && !parent->stopped) {
            parent->Mutex.unlock();

            while(thread_count >= thread_max){
                this_thread::sleep_for(.1s);
                }

            numMutex.lock();
            thread_count++;
            numMutex.unlock();
            bool reach = reachableURL(url);
            numMutex.lock();
            thread_count--;
            numMutex.unlock();

            parent->Mutex.lock();
            printMutex.lock();
            cout << "Thread count: " << thread_count << endl;
            if (reach){
                cout << url << " " << "is up" << endl;
                parent->clientState = CLIENT_HEALTHY;
            } else {
                cout << url << " " << "is down" << endl;
                parent->clientState = CLIENT_DOWN;
            }
            printMutex.unlock();
            parent->Mutex.unlock();
            this_thread::sleep_for(15s);
            parent->Mutex.lock();
        }
    }
}

void AsyncQuicProbe::beginProbe(){
    Mutex.lock();
    paused       = false;
    stopped      = false;
    this->worker = new thread(threadFunc, this);
    Mutex.unlock();
}

void AsyncQuicProbe::pauseProbe(){
    Mutex.lock();
    paused = true;
    Mutex.unlock();
}

void AsyncQuicProbe::stopProbe(){
    Mutex.lock();
    stopped = true;
    worker->detach();
    state = PROBE_STOPPED;
    clientState = CLIENT_UNKNOWN;
    Mutex.unlock();
}

QuicProbeState AsyncQuicProbe::getProbeState(){//you have to lock and unlock the mutex for this function to read properly
    return state;
}

ClientState AsyncQuicProbe::getClientState(){//you have to lock and unlock the mutex for this function to read properly
    return clientState;
}


class QuicProbeManager {
    private:
        unordered_map<char*, AsyncQuicProbe*> probes;
        MsQuicApi api;
    public:
        QuicProbeState                       getProbeState(char* url);
        unordered_map<char*, QuicProbeState> getProbeStates();
        ClientState                          getClientState(char* url);
        unordered_map<char*, ClientState>    getClientStates();
        bool                                 allocateProbe(const char* url);
        bool                                 dealocateProbe(char* url);

};

QuicProbeState QuicProbeManager::getProbeState(char* url){
    if (probes.find(url) != probes.end()){
        probes[url]->Mutex.lock();
        auto state = probes[url]->getProbeState();
        probes[url]->Mutex.unlock();

        return state;
    }

    return PROBE_NONEXISTANT;
};

unordered_map<char*, QuicProbeState>QuicProbeManager::getProbeStates(){ //TODO change this to a map
    unordered_map<char*, QuicProbeState> states;
    for (auto i = probes.begin(); i != probes.end(); ++i){
        try {
            auto state = this->getProbeState(i->first);
            states[i->first] = state;
        } catch (...) {
            states[i->first] = PROBE_DOWN;
        }
    }
    return states;
}

ClientState QuicProbeManager::getClientState(char* url){
    if (probes.find(url) != probes.end()){
        probes[url]->Mutex.lock();
        auto state = probes[url]->getClientState();
        probes[url]->Mutex.unlock();

        return state;
    }

    return CLIENT_PROBE_NONEXISTANT;
}

bool QuicProbeManager::allocateProbe(const char* url){
    auto copy = _strdup(url);
    if (probes.find(copy) != probes.end()){
        delete[] copy;
        return false;
    }

    probes[copy] = new AsyncQuicProbe(url, MsQuic);
    return true;
}

bool QuicProbeManager::dealocateProbe(char* url){
    if (probes.find(url) == probes.end()){
        return false;
    }
    delete probes[url];
    probes.erase(url);
    return true;
}

unordered_map<char*, ClientState>QuicProbeManager::getClientStates(){ //TODO change this to a map
    unordered_map<char*, ClientState> states;
    for (auto i = probes.begin(); i != probes.end(); ++i){
        try {
            auto state = this->getClientState(i->first);
            states[i->first] = state;
        } catch (...) {
            states[i->first] = CLIENT_UNKNOWN;
        }
    }
    return states;
}

int QUIC_CALL main() {
    MsQuic = new (std::nothrow) MsQuicApi();
    /*
    string input = "";
    vector<AsyncQuicProbe*> probes;
    while(input != "end"){
        cin >> input;
        probes.push_back(new AsyncQuicProbe(input.c_str(), MsQuic));
    }  
    */
    QuicProbeManager manager;
    for (int i = 0; i < 1000; i++){
        new AsyncQuicProbe(TopDomains[i], MsQuic);
        //manager.allocateProbe(TopDomains[i]);
    }

    string s;
    cin >> s;
    delete MsQuic;
    
    return 0;
}
