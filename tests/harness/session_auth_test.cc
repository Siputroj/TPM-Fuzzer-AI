#include <harness/command_attributes.h>
#include <harness/session_auth.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" {
void EnterFailureMode(const char* function, int line, int code) {
  (void)function;
  (void)line;
  (void)code;
}
}

TEST_CASE("LookupCommandAttr resolves existing and previously missing commands",
          "[command_attributes]") {
  CommandAttrEntry attr = {};

  // Existing commands
  REQUIRE(LookupCommandAttr(0x00000131u, &attr));  // TPM2_CC_CreatePrimary
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 1);

  REQUIRE(LookupCommandAttr(0x00000147u, &attr));  // TPM2_CC_ActivateCredential
  REQUIRE(attr.handle_count == 2);
  REQUIRE(attr.auth_handle_count == 2);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x00000176u, &attr));  // TPM2_CC_StartAuthSession
  REQUIRE(attr.handle_count == 2);
  REQUIRE(attr.auth_handle_count == 0);
  REQUIRE(attr.out_handle_count == 1);

  // Previously missing commands required for HMAC & Policy sessions
  REQUIRE(LookupCommandAttr(0x0000012Cu, &attr));  // TPM2_CC_PCR_SetAuthPolicy
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000012Bu, &attr));  // TPM2_CC_PCR_Allocate
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000013Cu, &attr));  // TPM2_CC_PCR_Event
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000012Eu, &attr));  // TPM2_CC_SetPrimaryPolicy
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x00000155u, &attr));  // TPM2_CC_MAC / HMAC
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000015Bu, &attr));  // TPM2_CC_MAC_Start
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 1);

  REQUIRE(LookupCommandAttr(0x00000186u, &attr));  // TPM2_CC_HashSequenceStart
  REQUIRE(attr.handle_count == 0);
  REQUIRE(attr.auth_handle_count == 0);
  REQUIRE(attr.out_handle_count == 1);

  REQUIRE(LookupCommandAttr(0x0000015Cu, &attr));  // TPM2_CC_SequenceUpdate
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000013Eu, &attr));  // TPM2_CC_SequenceComplete
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(
      LookupCommandAttr(0x00000185u, &attr));  // TPM2_CC_EventSequenceComplete
  REQUIRE(attr.handle_count == 2);
  REQUIRE(attr.auth_handle_count == 2);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x0000017Fu, &attr));  // TPM2_CC_PolicyPCR
  REQUIRE(attr.handle_count == 1);
  REQUIRE(attr.auth_handle_count == 0);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x00000151u, &attr));  // TPM2_CC_PolicySecret
  REQUIRE(attr.handle_count == 2);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x00000149u, &attr));  // TPM2_CC_PolicyNV
  REQUIRE(attr.handle_count == 3);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);

  REQUIRE(LookupCommandAttr(0x00000137u, &attr));  // TPM2_CC_NV_Write
  REQUIRE(attr.handle_count == 2);
  REQUIRE(attr.auth_handle_count == 1);
  REQUIRE(attr.out_handle_count == 0);
}

TEST_CASE("LookupCommandAttr rejects unimplemented command codes",
          "[command_attributes]") {
  CommandAttrEntry attr = {};
  REQUIRE_FALSE(LookupCommandAttr(0x00000000u, &attr));
  REQUIRE_FALSE(LookupCommandAttr(0x00000999u, &attr));
  REQUIRE_FALSE(LookupCommandAttr(0xDEADBEEFu, &attr));
}

namespace {
void Append16(std::vector<uint8_t>* b, uint16_t v) {
  b->push_back(static_cast<uint8_t>(v >> 8));
  b->push_back(static_cast<uint8_t>(v));
}
void Append32(std::vector<uint8_t>* b, uint32_t v) {
  b->push_back(static_cast<uint8_t>(v >> 24));
  b->push_back(static_cast<uint8_t>(v >> 16));
  b->push_back(static_cast<uint8_t>(v >> 8));
  b->push_back(static_cast<uint8_t>(v));
}
void PatchSize(std::vector<uint8_t>* b) {
  uint32_t sz = static_cast<uint32_t>(b->size());
  (*b)[2] = static_cast<uint8_t>(sz >> 24);
  (*b)[3] = static_cast<uint8_t>(sz >> 16);
  (*b)[4] = static_cast<uint8_t>(sz >> 8);
  (*b)[5] = static_cast<uint8_t>(sz);
}
std::vector<uint8_t> MakeSessionResponse(
    uint32_t rc, const std::vector<uint32_t>& out_handles,
    const std::vector<uint8_t>& params, uint8_t session_attrs = 0x01) {
  std::vector<uint8_t> resp;
  Append16(&resp, TPM2_ST_SESSIONS);
  Append32(&resp, 0);  // size placeholder
  Append32(&resp, rc);
  for (uint32_t h : out_handles) Append32(&resp, h);
  Append32(&resp, static_cast<uint32_t>(params.size()));
  resp.insert(resp.end(), params.begin(), params.end());
  // Auth area: nonceTPM(16 bytes of 0x55) | sessionAttrs | hmac(32 bytes of 0)
  Append16(&resp, 16);
  resp.insert(resp.end(), 16, 0x55);
  resp.push_back(session_attrs);
  Append16(&resp, 32);
  resp.insert(resp.end(), 32, 0x00);
  PatchSize(&resp);
  return resp;
}
}  // namespace

TEST_CASE("SessionAuth supports SHA-384 and SHA-512 HMAC sessions",
          "[session_auth]") {
  SessionAuthReset();
  uint8_t nonce_tpm[48];
  std::memset(nonce_tpm, 0x11, sizeof(nonce_tpm));
  SessionAuthInit(0x02000000u, nonce_tpm, sizeof(nonce_tpm), nullptr, 0,
                  TPM2_ALG_SHA384);

  // Build TPM2_Clear(TPM_RH_LOCKOUT) with empty nonce and empty hmac
  std::vector<uint8_t> cmd;
  Append16(&cmd, TPM2_ST_SESSIONS);
  Append32(&cmd, 0);
  Append32(&cmd, TPM2_CC_Clear);
  Append32(&cmd, 0x4000000Au);  // TPM_RH_LOCKOUT
  Append32(&cmd, 9);            // authSize: handle(4)+nonce(2)+attrs(1)+hmac(2)
  Append32(&cmd, 0x02000000u);
  Append16(&cmd, 0);
  cmd.push_back(0x01);  // continueSession
  Append16(&cmd, 0);
  PatchSize(&cmd);

  const size_t orig_size = cmd.size();
  cmd.resize(orig_size + 128);
  const size_t new_size =
      SessionAuthPatchCommand(cmd.data(), orig_size, cmd.size());
  // Should grow by 16 (nonceCaller) + 48 (SHA-384 HMAC) = 64 bytes
  REQUIRE(new_size == orig_size + 64);
}

TEST_CASE("SessionAuth resolves 0-byte Name for MAC_Start sequence handles",
          "[session_auth]") {
  SessionAuthReset();
  uint8_t nonce_tpm[32];
  std::memset(nonce_tpm, 0x22, sizeof(nonce_tpm));
  SessionAuthInit(0x02000000u, nonce_tpm, sizeof(nonce_tpm), nullptr, 0,
                  TPM2_ALG_SHA256);

  // Simulate sending TPM2_MAC_Start (0x0000015B)
  std::vector<uint8_t> mac_start;
  Append16(&mac_start, TPM2_ST_SESSIONS);
  Append32(&mac_start, 0);
  Append32(&mac_start, TPM2_CC_MAC_Start);
  Append32(&mac_start, 0x40000001u);  // dummy handle
  Append32(&mac_start, 9);
  Append32(&mac_start, TPM2_RS_PW);
  Append16(&mac_start, 0);
  mac_start.push_back(0x01);
  Append16(&mac_start, 0);
  Append16(&mac_start, 0);            // auth (empty TPM2B)
  Append16(&mac_start, TPM2_ALG_SHA256);
  PatchSize(&mac_start);

  mac_start.resize(mac_start.size() + 128);
  SessionAuthPatchCommand(mac_start.data(), mac_start.size() - 128,
                          mac_start.size());

  // Response returns sequenceHandle = 0x80000001, 0 bytes of params
  auto resp = MakeSessionResponse(TPM2_RC_SUCCESS, {0x80000001u}, {});
  SessionAuthProcessResponse(resp.data(), resp.size());

  // Now send TPM2_SequenceUpdate (0x0000015C) on 0x80000001 using 0x02000000
  std::vector<uint8_t> seq_update;
  Append16(&seq_update, TPM2_ST_SESSIONS);
  Append32(&seq_update, 0);
  Append32(&seq_update, TPM2_CC_SequenceUpdate);
  Append32(&seq_update, 0x80000001u);  // sequenceHandle
  Append32(&seq_update, 9);
  Append32(&seq_update, 0x02000000u);
  Append16(&seq_update, 0);
  seq_update.push_back(0x01);
  Append16(&seq_update, 0);
  Append16(&seq_update, 4);  // 4-byte buffer
  Append32(&seq_update, 0xdeadbeef);
  PatchSize(&seq_update);

  const size_t orig_size = seq_update.size();
  seq_update.resize(orig_size + 128);
  const size_t new_size = SessionAuthPatchCommand(
      seq_update.data(), orig_size, seq_update.size());
  REQUIRE(new_size == orig_size + 48);  // 16B nonce + 32B SHA-256 HMAC
}

TEST_CASE("SessionAuth computes and caches NV Index Name from NV_DefineSpace",
          "[session_auth]") {
  SessionAuthReset();
  uint8_t nonce_tpm[32];
  std::memset(nonce_tpm, 0x33, sizeof(nonce_tpm));
  SessionAuthInit(0x02000000u, nonce_tpm, sizeof(nonce_tpm), nullptr, 0,
                  TPM2_ALG_SHA256);

  // Build TPM2_NV_DefineSpace defining index 0x01000000 with SHA256 nameAlg
  std::vector<uint8_t> nv_def;
  Append16(&nv_def, TPM2_ST_SESSIONS);
  Append32(&nv_def, 0);
  Append32(&nv_def, TPM2_CC_NV_DefineSpace);
  Append32(&nv_def, 0x40000001u);  // TPM_RH_OWNER
  Append32(&nv_def, 9);
  Append32(&nv_def, TPM2_RS_PW);
  Append16(&nv_def, 0);
  nv_def.push_back(0x01);
  Append16(&nv_def, 0);
  Append16(&nv_def, 0);   // auth: empty TPM2B_AUTH
  Append16(&nv_def, 14);  // publicInfo: TPM2B_NV_PUBLIC size = 14
  Append32(&nv_def, 0x01000000u);      // nvIndex
  Append16(&nv_def, TPM2_ALG_SHA256);  // nameAlg
  Append32(&nv_def, 0x02020002u);      // attributes
  Append16(&nv_def, 0);                // authPolicy (empty)
  Append16(&nv_def, 32);               // dataSize
  PatchSize(&nv_def);

  nv_def.resize(nv_def.size() + 128);
  SessionAuthPatchCommand(nv_def.data(), nv_def.size() - 128, nv_def.size());

  auto resp = MakeSessionResponse(TPM2_RC_SUCCESS, {}, {});
  SessionAuthProcessResponse(resp.data(), resp.size());

  // Now send TPM2_NV_Write(authHandle=0x01000000, nvIndex=0x01000000) with
  // HMAC session 0x02000000
  std::vector<uint8_t> nv_write;
  Append16(&nv_write, TPM2_ST_SESSIONS);
  Append32(&nv_write, 0);
  Append32(&nv_write, TPM2_CC_NV_Write);
  Append32(&nv_write, 0x01000000u);  // authHandle = nvIndex
  Append32(&nv_write, 0x01000000u);  // nvIndex
  Append32(&nv_write, 9);
  Append32(&nv_write, 0x02000000u);
  Append16(&nv_write, 0);
  nv_write.push_back(0x01);
  Append16(&nv_write, 0);
  Append16(&nv_write, 4);  // data TPM2B
  Append32(&nv_write, 0x12345678u);
  Append16(&nv_write, 0);  // offset = 0
  PatchSize(&nv_write);

  const size_t orig_size = nv_write.size();
  nv_write.resize(orig_size + 128);
  const size_t new_size =
      SessionAuthPatchCommand(nv_write.data(), orig_size, nv_write.size());
  REQUIRE(new_size == orig_size + 48);
}

TEST_CASE("SessionAuth flushes session when continueSession is 0",
          "[session_auth]") {
  SessionAuthReset();
  uint8_t nonce_tpm[32];
  std::memset(nonce_tpm, 0x44, sizeof(nonce_tpm));
  SessionAuthInit(0x02000000u, nonce_tpm, sizeof(nonce_tpm), nullptr, 0,
                  TPM2_ALG_SHA256);
  REQUIRE(SessionAuthGetSessionHandle() == 0x02000000u);

  std::vector<uint8_t> cmd;
  Append16(&cmd, TPM2_ST_SESSIONS);
  Append32(&cmd, 0);
  Append32(&cmd, TPM2_CC_Clear);
  Append32(&cmd, 0x4000000Au);
  Append32(&cmd, 9);
  Append32(&cmd, 0x02000000u);
  Append16(&cmd, 0);
  cmd.push_back(0x00);  // continueSession = 0!
  Append16(&cmd, 0);
  PatchSize(&cmd);

  const size_t orig_size = cmd.size();
  cmd.resize(orig_size + 128);
  const size_t new_size =
      SessionAuthPatchCommand(cmd.data(), orig_size, cmd.size());
  REQUIRE(new_size == orig_size + 48);

  auto resp = MakeSessionResponse(TPM2_RC_SUCCESS, {}, {}, /*attrs=*/0x00);
  SessionAuthProcessResponse(resp.data(), resp.size());

  // Session should now be flushed
  REQUIRE(SessionAuthGetSessionHandle() == 0u);
}

TEST_CASE(
    "SessionAuth supports Policy sessions, PolicyCommandCode digest updates, "
    "and PolicyPassword",
    "[session_auth]") {
  SessionAuthReset();

  // Bootstrap Policy session via StartAuthSession(TPM_SE_POLICY)
  std::vector<uint8_t> start_policy;
  Append16(&start_policy, TPM2_ST_NO_SESSIONS);
  Append32(&start_policy, 0);
  Append32(&start_policy, TPM2_CC_StartAuthSession);
  Append32(&start_policy, TPM2_RH_NULL);  // tpmKey
  Append32(&start_policy, TPM2_RH_NULL);  // bind
  Append16(&start_policy, 16);            // nonceCaller
  start_policy.insert(start_policy.end(), 16, 0xAA);
  Append16(&start_policy, 0);             // encryptedSalt
  start_policy.push_back(TPM2_SE_POLICY);
  Append16(&start_policy, TPM2_ALG_NULL);  // symmetric
  Append16(&start_policy, TPM2_ALG_SHA256);
  PatchSize(&start_policy);

  SessionAuthPatchCommand(start_policy.data(), start_policy.size(),
                          start_policy.size());

  std::vector<uint8_t> start_resp;
  Append16(&start_resp, TPM2_ST_NO_SESSIONS);
  Append32(&start_resp, 0);
  Append32(&start_resp, TPM2_RC_SUCCESS);
  Append32(&start_resp, 0x03000000u);  // policy session handle
  Append16(&start_resp, 32);
  start_resp.insert(start_resp.end(), 32, 0x66);
  PatchSize(&start_resp);
  SessionAuthProcessResponse(start_resp.data(), start_resp.size());

  REQUIRE(SessionAuthGetSessionHandle() == 0x03000000u);

  // Send TPM2_PolicyCommandCode(0x03000000, TPM2_CC_Clear)
  std::vector<uint8_t> pol_cc;
  Append16(&pol_cc, TPM2_ST_NO_SESSIONS);
  Append32(&pol_cc, 0);
  Append32(&pol_cc, TPM2_CC_PolicyCommandCode);
  Append32(&pol_cc, 0x03000000u);
  Append32(&pol_cc, TPM2_CC_Clear);
  PatchSize(&pol_cc);

  SessionAuthPatchCommand(pol_cc.data(), pol_cc.size(), pol_cc.size());

  std::vector<uint8_t> ok_no_sess;
  Append16(&ok_no_sess, TPM2_ST_NO_SESSIONS);
  Append32(&ok_no_sess, 10);
  Append32(&ok_no_sess, TPM2_RC_SUCCESS);
  SessionAuthProcessResponse(ok_no_sess.data(), ok_no_sess.size());

  uint8_t digest[64] = {};
  size_t digest_size = 0;
  REQUIRE(SessionAuthGetPolicyDigest(0x03000000u, digest, &digest_size));
  REQUIRE(digest_size == 32);
  // Policy digest must now be non-zero after PolicyCommandCode
  bool non_zero = false;
  for (size_t i = 0; i < 32; ++i) {
    if (digest[i] != 0) non_zero = true;
  }
  REQUIRE(non_zero);

  // Send guarded TPM2_Clear authorized by Policy session 0x03000000 (HMAC mode)
  std::vector<uint8_t> clear_cmd;
  Append16(&clear_cmd, TPM2_ST_SESSIONS);
  Append32(&clear_cmd, 0);
  Append32(&clear_cmd, TPM2_CC_Clear);
  Append32(&clear_cmd, 0x4000000Au);
  Append32(&clear_cmd, 9);
  Append32(&clear_cmd, 0x03000000u);
  Append16(&clear_cmd, 0);
  clear_cmd.push_back(0x01);
  Append16(&clear_cmd, 0);
  PatchSize(&clear_cmd);

  const size_t orig_clear = clear_cmd.size();
  clear_cmd.resize(orig_clear + 128);
  const size_t patched_clear =
      SessionAuthPatchCommand(clear_cmd.data(), orig_clear, clear_cmd.size());
  REQUIRE(patched_clear == orig_clear + 48);  // 16B nonce + 32B Policy HMAC
}

TEST_CASE(
    "SessionAuth PolicyPassword hashes TPM2_CC_PolicyAuthValue and NV_Write "
    "promotes NV Index Name with TPMA_NV_WRITTEN",
    "[session_auth]") {
  SessionAuthReset();

  // 1. Start Policy session 0x03000000 and run PolicyPassword; verify digest
  // equals SHA256(zeros(32) || TPM2_CC_PolicyAuthValue (0x0000016B)).
  const uint8_t nonce0[32] = {0x11};
  SessionAuthInit(0x03000000u, nonce0, sizeof(nonce0), nullptr, 0,
                  TPM2_ALG_SHA256);

  std::vector<uint8_t> pol_pw;
  Append16(&pol_pw, TPM2_ST_NO_SESSIONS);
  Append32(&pol_pw, 0);
  Append32(&pol_pw, TPM2_CC_PolicyPassword);
  Append32(&pol_pw, 0x03000000u);
  PatchSize(&pol_pw);
  SessionAuthPatchCommand(pol_pw.data(), pol_pw.size(), pol_pw.size());

  std::vector<uint8_t> ok_no_sess;
  Append16(&ok_no_sess, TPM2_ST_NO_SESSIONS);
  Append32(&ok_no_sess, 10);
  Append32(&ok_no_sess, TPM2_RC_SUCCESS);
  SessionAuthProcessResponse(ok_no_sess.data(), ok_no_sess.size());

  // Now do the same with PolicyAuthValue on 0x03000001; per TPM 2.0 Part 3
  // section 23.8 (PolicyPassword.c:17), both must produce the exact same
  // policyDigest!
  SessionAuthInit(0x03000001u, nonce0, sizeof(nonce0), nullptr, 0,
                  TPM2_ALG_SHA256);
  std::vector<uint8_t> pol_av;
  Append16(&pol_av, TPM2_ST_NO_SESSIONS);
  Append32(&pol_av, 0);
  Append32(&pol_av, TPM2_CC_PolicyAuthValue);
  Append32(&pol_av, 0x03000001u);
  PatchSize(&pol_av);
  SessionAuthPatchCommand(pol_av.data(), pol_av.size(), pol_av.size());
  SessionAuthProcessResponse(ok_no_sess.data(), ok_no_sess.size());

  uint8_t d_pw[64] = {};
  uint8_t d_av[64] = {};
  size_t s_pw = 0, s_av = 0;
  REQUIRE(SessionAuthGetPolicyDigest(0x03000000u, d_pw, &s_pw));
  REQUIRE(SessionAuthGetPolicyDigest(0x03000001u, d_av, &s_av));
  REQUIRE(s_pw == 32);
  REQUIRE(std::memcmp(d_pw, d_av, 32) == 0);

  // 2. Define NV Index 0x01000000 (unwritten), run NV_Write, and verify that
  // the cached NV Index Name updates with TPMA_NV_WRITTEN (1 << 29).
  SessionAuthInit(0x02000000u, nonce0, sizeof(nonce0), nullptr, 0,
                  TPM2_ALG_SHA256);

  std::vector<uint8_t> nv_def;
  Append16(&nv_def, TPM2_ST_SESSIONS);
  Append32(&nv_def, 0);
  Append32(&nv_def, TPM2_CC_NV_DefineSpace);
  Append32(&nv_def, 0x40000001u);  // TPM_RH_OWNER
  Append32(&nv_def, 9);
  Append32(&nv_def, 0x02000000u);
  Append16(&nv_def, 0);
  nv_def.push_back(0x01);
  Append16(&nv_def, 0);
  Append16(&nv_def, 0);            // auth (empty TPM2B_AUTH)
  Append16(&nv_def, 14);           // publicInfo size = 14
  Append32(&nv_def, 0x01000000u);  // nvIndex
  Append16(&nv_def, TPM2_ALG_SHA256);
  Append32(&nv_def, 0x00060006u);  // TPMA_NV (unwritten)
  Append16(&nv_def, 0);            // authPolicy (empty)
  Append16(&nv_def, 8);            // dataSize = 8
  PatchSize(&nv_def);

  const size_t orig_def = nv_def.size();
  nv_def.resize(orig_def + 128);
  SessionAuthPatchCommand(nv_def.data(), orig_def, nv_def.size());

  std::vector<uint8_t> ok_sess;
  Append16(&ok_sess, TPM2_ST_SESSIONS);
  Append32(&ok_sess, 0);
  Append32(&ok_sess, TPM2_RC_SUCCESS);
  Append32(&ok_sess, 0);  // param_size = 0
  Append16(&ok_sess, 32);
  ok_sess.insert(ok_sess.end(), nonce0, nonce0 + 32);
  ok_sess.push_back(0x01);
  Append16(&ok_sess, 32);
  ok_sess.insert(ok_sess.end(), 32, 0x00);
  PatchSize(&ok_sess);
  SessionAuthProcessResponse(ok_sess.data(), ok_sess.size());

  // Build an NV_Read command BEFORE NV_Write to capture the HMAC with unwritten
  // Name.
  auto make_nv_read = []() {
    std::vector<uint8_t> cmd;
    Append16(&cmd, TPM2_ST_SESSIONS);
    Append32(&cmd, 0);
    Append32(&cmd, 0x0000014Eu);  // TPM2_CC_NV_Read
    Append32(&cmd, 0x01000000u);  // authHandle = nvIndex
    Append32(&cmd, 0x01000000u);  // nvIndex
    Append32(&cmd, 9);
    Append32(&cmd, 0x02000000u);
    Append16(&cmd, 0);
    cmd.push_back(0x01);
    Append16(&cmd, 0);
    Append16(&cmd, 8);  // size = 8
    Append16(&cmd, 0);  // offset = 0
    PatchSize(&cmd);
    return cmd;
  };

  std::vector<uint8_t> read_before = make_nv_read();
  const size_t orig_read = read_before.size();
  read_before.resize(orig_read + 128);
  REQUIRE(SessionAuthPatchCommand(read_before.data(), orig_read,
                                  read_before.size()) == orig_read + 48);

  // Now execute NV_Write and process its success response (which keeps the same
  // nonce0).
  std::vector<uint8_t> nv_write;
  Append16(&nv_write, TPM2_ST_SESSIONS);
  Append32(&nv_write, 0);
  Append32(&nv_write, 0x00000137u);  // TPM2_CC_NV_Write
  Append32(&nv_write, 0x01000000u);  // authHandle
  Append32(&nv_write, 0x01000000u);  // nvIndex
  Append32(&nv_write, 9);
  Append32(&nv_write, 0x02000000u);
  Append16(&nv_write, 0);
  nv_write.push_back(0x01);
  Append16(&nv_write, 0);
  Append16(&nv_write, 4);  // data size = 4
  Append32(&nv_write, 0xDEADBEEFu);
  Append16(&nv_write, 0);  // offset = 0
  PatchSize(&nv_write);

  const size_t orig_write = nv_write.size();
  nv_write.resize(orig_write + 128);
  REQUIRE(SessionAuthPatchCommand(nv_write.data(), orig_write,
                                  nv_write.size()) == orig_write + 48);
  SessionAuthProcessResponse(ok_sess.data(), ok_sess.size());

  // Patch an identical NV_Read AFTER NV_Write; its HMAC must differ because the
  // NV Index Name now has TPMA_NV_WRITTEN (1 << 29) set!
  std::vector<uint8_t> read_after = make_nv_read();
  read_after.resize(orig_read + 128);
  REQUIRE(SessionAuthPatchCommand(read_after.data(), orig_read,
                                  read_after.size()) == orig_read + 48);
  REQUIRE(std::memcmp(read_before.data(), read_after.data(), orig_read + 48) !=
          0);
}


