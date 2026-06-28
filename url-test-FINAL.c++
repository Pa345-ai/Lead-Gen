// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "url.h"

#include <kj/table.h>
#include <kj/test.h>

#include <regex>

namespace workerd::jsg::test {
namespace {

KJ_TEST("Basics") {
  Url theUrl = nullptr;
  KJ_IF_SOME(url, Url::tryParse("http://example.org:81"_kj)) {
    KJ_ASSERT(url.getOrigin() == "http://example.org:81"_kj);
    KJ_ASSERT(url.getHref() == "http://example.org:81/"_kj);
    KJ_ASSERT(url.getProtocol() == "http:"_kj);
    KJ_ASSERT(url.getHostname() == "example.org"_kj);
    KJ_ASSERT(url.getHost() == "example.org:81"_kj);
    KJ_ASSERT(url.getPort() == "81"_kj);
    KJ_ASSERT(url.getPathname() == "/"_kj);
    KJ_ASSERT(url.getSchemeType() == Url::SchemeType::HTTP);
    KJ_ASSERT(url.getHostType() == Url::HostType::DEFAULT);
    KJ_ASSERT(url.getUsername() == ""_kj);
    KJ_ASSERT(url.getPassword() == ""_kj);
    KJ_ASSERT(url.getHash() == ""_kj);
    KJ_ASSERT(url.getSearch() == ""_kj);

    theUrl = url.clone();
    KJ_ASSERT(theUrl == url);
    theUrl = kj::mv(url);

    auto res = KJ_ASSERT_NONNULL(theUrl.resolve("abc"_kj));
    KJ_ASSERT(res.getHref() == "http://example.org:81/abc"_kj);

    // jsg::Urls support KJ_STRINGIFY
    KJ_ASSERT(kj::str(res) == "http://example.org:81/abc");

    // jsg::Urls are suitable to be used as keys in a hashset, hashmap
    kj::HashSet<Url> urls;
    urls.insert(res.clone());
    KJ_ASSERT(urls.contains(res));

    kj::HashMap<Url, int> urlmap;
    urlmap.insert(res.clone(), 1);
    KJ_ASSERT(KJ_ASSERT_NONNULL(urlmap.find(res)) == 1);
  } else {
    KJ_FAIL_ASSERT("url could not be parsed");
  }

  KJ_ASSERT(Url::idnToAscii("täst.de"_kj) == "xn--tst-qla.de"_kj);
  KJ_ASSERT(Url::idnToUnicode("xn--tst-qla.de"_kj) == "täst.de"_kj);
}

}  // namespace
}  // namespace workerd::jsg::test

KJ_TEST("Finding #1: Direct OOB Trigger via normalizePathEncoding") {
  // This test is declared in url.c++ as testFinding1DirectOOB()
  // It calls normalizePathEncoding() with raw strings ending in %2
  // which bypasses ada's normalization layer
  
  // If ada parser was "fixing" the input, this test will crash with ASAN
  // because we're calling the function directly without ada processing
  
  // Declare external function from url.c++
  extern void testFinding1DirectOOB();
  
  // Call it - if OOB exists and is real, ASAN fires here
  testFinding1DirectOOB();
  
  // If we reach here, either:
  // A) OOB doesn't exist (false positive)
  // B) The vulnerable code path isn't reached
  // C) ASAN didn't detect it (unlikely with --config=asan)
}
