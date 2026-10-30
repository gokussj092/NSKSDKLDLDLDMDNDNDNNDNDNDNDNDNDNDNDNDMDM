#include "../android/app/src/main/cpp/spdecode_session.h"
#include <cassert>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
int main() {
    using Cache=spdecode::SessionCache;
    using namespace std::chrono;
    Cache cache;
    const auto now=Cache::Clock::now();
    assert(cache.get(now).empty());
    assert(cache.requiresActionIntegrity());
    cache.store("header.payload",120,false,now);
    assert(cache.get(now+seconds(89))=="header.payload");
    assert(!cache.requiresActionIntegrity());
    cache.clearIfMatches("unrelated.token");
    assert(cache.get(now)=="header.payload");
    cache.clearIfMatches("header.payload");
    assert(cache.get(now).empty());
    assert(cache.requiresActionIntegrity());
    cache.store("new.value",60,true,now);
    assert(cache.get(now+seconds(29))=="new.value");
    assert(cache.get(now+seconds(30)).empty());
    cache.store("short.lived",1,false,now);
    assert(cache.get(now).empty());
    for(const auto& invalid:{"abc","a..b","a.b.c","a.!"}) {
        bool rejected=false;
        try{cache.store(invalid,120,true,now);}
        catch(const std::invalid_argument&){rejected=true;}
        assert(rejected);
    }
    for(auto ttl:{0,301}) {
        bool rejected=false;
        try{cache.store("a.b",ttl,true,now);}
        catch(const std::invalid_argument&){rejected=true;}
        assert(rejected);
    }
    cache.store("first.token",120,true);
    std::vector<std::thread> workers;
    for(int i=0;i<8;++i)workers.emplace_back([&cache,i](){
        for(int j=0;j<100;++j){
            if(i%2==0)cache.clearIfMatches("stale.token");
            else (void)cache.get();
        }
    });
    for(auto& worker:workers)worker.join();
    assert(cache.get()=="first.token");
    cache.clear();
    assert(cache.get().empty());
    std::cout<<"PASS native session TTL, invalidation and concurrency\n";
}
