//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/PublicRsaKeySharedMain.h"

#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

namespace td {

std::shared_ptr<PublicRsaKeySharedMain> PublicRsaKeySharedMain::create(bool is_test) {
  auto add_pem = [](vector<RsaKey> &keys, CSlice pem) {
    auto rsa = mtproto::RSA::from_pem_public_key(pem).move_as_ok();
    auto fingerprint = rsa.get_fingerprint();
    keys.push_back(RsaKey{std::move(rsa), fingerprint});
  };

  if (is_test) {
    static auto test_public_rsa_key = [&] {
      vector<RsaKey> keys;
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\n"
              "yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\n"
              "plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\n"
              "j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\n"
              "aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\n"
              "j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return test_public_rsa_key;
  } else {
    static auto main_public_rsa_key = [&] {
      vector<RsaKey> keys;
      // BeHappy server RSA public key
      add_pem(keys,
              "-----BEGIN RSA PUBLIC KEY-----\n"
              "MIIBCgKCAQEAvqCL9IFBWxiDU3dFAdFv4vP50Wzv2eXNgH8d7j/ZdzZIMMGbdNgq\n"
              "+jKXStI6yrnkx6IGq1z9ymGmErbocJ5RLwUh+VqJhKZ683hVsHhPka2/s7So/YRV\n"
              "NbMjJj4L15CSFdGNPsQNpFCQrGfI71eGh8q2lNuW2cbe+AafWFhqtmfKglJJdwiM\n"
              "sl+5/FAN2Ks0s5CWNhRNsZmo00eLb4cBxOIh4LVxjlrXgiBQ+b0OKIymqa9/0Hvv\n"
              "veTrPO6qPkNcMjumx79l3AZtasg821gBHafzTh+acLYJyqtEAlCtAQGYGhcl7wSo\n"
              "VJyRJX7reja7fCNc4jpAs79VAF8TNCAWSwIDAQAB\n"
              "-----END RSA PUBLIC KEY-----");
      return std::make_shared<PublicRsaKeySharedMain>(std::move(keys));
    }();
    return main_public_rsa_key;
  }
}

Result<mtproto::PublicRsaKeyInterface::RsaKey> PublicRsaKeySharedMain::get_rsa_key(const vector<int64> &fingerprints) {
  for (auto fingerprint : fingerprints) {
    for (const auto &key : keys_) {
      if (key.fingerprint == fingerprint) {
        return RsaKey{key.rsa.clone(), fingerprint};
      }
    }
  }
  return Status::Error(PSLICE() << "Unknown Main fingerprints " << fingerprints);
}

void PublicRsaKeySharedMain::drop_keys() {
  // nothing to do
}

}  // namespace td
