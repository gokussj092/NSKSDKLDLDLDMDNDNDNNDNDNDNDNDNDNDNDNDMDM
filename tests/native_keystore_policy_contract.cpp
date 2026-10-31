#include "../android/app/src/main/cpp/spdecode_keystore_policy.h"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
int main(){
    using namespace spdecode;
    assert(managedKeystoreAlias("spdecode.transport.v2"));
    assert(managedKeystoreAlias("spdecode.transport.v3.1793370000000.AAAAAAAA"));
    assert(!managedKeystoreAlias("irrelevant"));
    const auto aliases=managedKeystoreAliases({"irrelevant","spdecode.transport.v2",
        "spdecode.transport.v3.1793370000000.AAAAAAAA",
        "spdecode.transport.v3.1793370000001.BBBBBBBB"});
    assert(aliases.size()==3);
    assert(preferredKeystoreAlias(aliases)=="spdecode.transport.v3.1793370000001.BBBBBBBB");
    assert(preferredKeystoreAlias({"spdecode.transport.v2"})=="spdecode.transport.v2");
    assert(preferredKeystoreAlias({}).empty());
    assert(shouldPurgeKeystoreAlias("spdecode.transport.v3.1000000000000.AAAAAAAA","",
                                   1000000600001LL));
    assert(!shouldPurgeKeystoreAlias("spdecode.transport.v3.1000000000000.AAAAAAAA","",
                                    1000000600000LL));
    assert(!shouldPurgeKeystoreAlias("spdecode.transport.v3.1000000000000.AAAAAAAA",
                                     "spdecode.transport.v3.1000000000000.AAAAAAAA",1000000900000LL));
    assert(shouldPurgeKeystoreAlias("spdecode.transport.v3.corrupt.AAAAAAAA","",1000000900000LL));
    assert(validEnrollmentChallenge(std::string(43,'A'),"tee"));
    assert(validEnrollmentChallenge(std::string(43,'A'),"strongbox"));
    assert(!validEnrollmentChallenge(std::string(42,'A'),"tee"));
    assert(!validEnrollmentChallenge(std::string(43,'A'),"none"));
    assert(validKeyClaim(std::string(120,'B')));
    assert(!validKeyClaim(std::string(119,'B')));
    std::cout<<"PASS native Keystore alias and enrollment policies\n";
}
