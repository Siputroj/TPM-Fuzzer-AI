#include "harness/session_auth.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdint>
#include <cstring>

#include "harness/command_attributes.h"

namespace {

// Fixed nonceCaller used for every session-authorized command. The TPM accepts
// any 16+ byte nonce; we keep this constant so the HMAC is reproducible across
// runs given the same fuzzed parameters.
constexpr uint8_t kNonceCallerFill = 0xAA;
constexpr size_t kNonceCallerSize = 16;

// Maximum number of transient/persistent/NV handles whose Names we track.
constexpr int kMaxNames = 32;
// algId(2) + SHA-512 digest(64) = 66; round up to 68.
constexpr size_t kMaxNameSize = 68;

// Maximum number of concurrent active sessions tracked by the harness.
constexpr int kMaxSessions = 4;

// ── byte and algorithm utilities ───────────────────────────────────────────

inline uint16_t Read16(const uint8_t* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t Read32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void Write16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

inline void Write32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

const EVP_MD* EvpMdForAlg(uint16_t alg) {
  switch (alg) {
    case TPM2_ALG_SHA1:
      return EVP_sha1();
    case TPM2_ALG_SHA256:
      return EVP_sha256();
    case TPM2_ALG_SHA384:
      return EVP_sha384();
    case TPM2_ALG_SHA512:
      return EVP_sha512();
    default:
      return nullptr;
  }
}

size_t DigestSizeFor(uint16_t alg) {
  switch (alg) {
    case TPM2_ALG_SHA1:
      return 20;
    case TPM2_ALG_SHA256:
      return 32;
    case TPM2_ALG_SHA384:
      return 48;
    case TPM2_ALG_SHA512:
      return 64;
    default:
      return 0;
  }
}

// ── crypto primitives ──────────────────────────────────────────────────────

bool ComputeDigest(uint16_t alg, const uint8_t* data, size_t len,
                   uint8_t out[SESSION_AUTH_MAX_DIGEST], size_t* out_len) {
  const EVP_MD* md = EvpMdForAlg(alg);
  if (!md) return false;
  unsigned int sz = 0;
  if (EVP_Digest(data, len, out, &sz, md, nullptr) != 1) return false;
  if (out_len) *out_len = sz;
  return true;
}

bool ComputeHmacDigest(uint16_t alg, const uint8_t* key, size_t key_len,
                       const uint8_t* msg, size_t msg_len,
                       uint8_t out[SESSION_AUTH_MAX_DIGEST],
                       size_t* out_len) {
  const EVP_MD* md = EvpMdForAlg(alg);
  if (!md) return false;
  unsigned int sz = 0;
  if (!HMAC(md, key, static_cast<int>(key_len), msg, msg_len, out, &sz)) {
    return false;
  }
  if (out_len) *out_len = sz;
  return true;
}

// ── data structures and session state ─────────────────────────────────────

struct NameEntry {
  uint32_t handle;
  uint8_t name[kMaxNameSize];
  size_t name_size;
  uint8_t written_name[kMaxNameSize];
  size_t written_name_size;
};

// Tracks handle→Name mappings for transient, persistent, and NV Index objects.
// Supports 0-byte Names for sequence objects (MAC_Start / HashSequenceStart)
// and promotes NV Index Names when TPMA_NV_WRITTEN (1 << 29) is set.
struct NameTable {
  NameEntry entries[kMaxNames];
  int count;

  void Add(uint32_t handle, const uint8_t* name, size_t name_size,
           const uint8_t* written_name = nullptr,
           size_t written_name_size = 0) {
    if (name_size > kMaxNameSize) name_size = kMaxNameSize;
    if (written_name_size > kMaxNameSize) written_name_size = kMaxNameSize;
    for (int i = 0; i < count; ++i) {
      if (entries[i].handle == handle) {
        if (name && name_size > 0) {
          std::memcpy(entries[i].name, name, name_size);
        }
        entries[i].name_size = name_size;
        if (written_name && written_name_size > 0) {
          std::memcpy(entries[i].written_name, written_name, written_name_size);
        }
        entries[i].written_name_size = written_name_size;
        return;
      }
    }
    if (count < kMaxNames) {
      NameEntry& e = entries[count++];
      e.handle = handle;
      if (name && name_size > 0) {
        std::memcpy(e.name, name, name_size);
      }
      e.name_size = name_size;
      if (written_name && written_name_size > 0) {
        std::memcpy(e.written_name, written_name, written_name_size);
      }
      e.written_name_size = written_name_size;
    }
  }

  void PromoteNvToWritten(uint32_t handle) {
    for (int i = 0; i < count; ++i) {
      if (entries[i].handle == handle && entries[i].written_name_size > 0) {
        std::memcpy(entries[i].name, entries[i].written_name,
                    entries[i].written_name_size);
        entries[i].name_size = entries[i].written_name_size;
        return;
      }
    }
  }

  bool Lookup(uint32_t handle, uint8_t* name_out, size_t name_cap,
              size_t* name_size_out) const {
    for (int i = 0; i < count; ++i) {
      if (entries[i].handle == handle) {
        const size_t ns = entries[i].name_size;
        if (ns > name_cap) return false;
        if (ns > 0) {
          std::memcpy(name_out, entries[i].name, ns);
        }
        *name_size_out = ns;
        return true;
      }
    }
    return false;
  }
};

struct SessionSlot {
  bool active;
  uint32_t handle;
  uint8_t session_type;
  uint16_t hash_alg;
  size_t digest_size;
  uint8_t nonce_tpm[SESSION_AUTH_MAX_DIGEST];
  size_t nonce_tpm_size;
  uint8_t session_key[SESSION_AUTH_MAX_DIGEST];
  size_t session_key_size;
  uint8_t policy_digest[SESSION_AUTH_MAX_DIGEST];
  bool is_password_needed;
};

struct AuthEngineState {
  SessionSlot slots[kMaxSessions];
  uint32_t most_recent_handle;
  uint32_t last_command_code;
  uint32_t last_session_handle;
  uint8_t last_session_attrs;
  bool last_command_used_session;
  NameTable names;

  // Reactive StartAuthSession bookkeeping.
  bool pending_start_auth_session;
  bool start_auth_session_compatible;
  uint8_t start_auth_session_type;
  uint16_t start_auth_session_auth_hash;

  // Pending NV_DefineSpace Name bookkeeping.
  bool pending_nv_define;
  uint32_t pending_nv_index;
  uint8_t pending_nv_name[kMaxNameSize];
  size_t pending_nv_name_size;
  uint8_t pending_nv_written_name[kMaxNameSize];
  size_t pending_nv_written_name_size;

  // Pending NV_Write / NV_Extend / NV_SetBits / NV_Increment Name promotion.
  bool pending_nv_write;
  uint32_t pending_nv_write_index;

  // Pending Policy command bookkeeping.
  bool pending_policy_cmd;
  uint32_t pending_policy_session;
  uint32_t pending_policy_cc_arg;
  uint8_t pending_policy_locality;

  SessionSlot* FindSlot(uint32_t handle) {
    for (int i = 0; i < kMaxSessions; ++i) {
      if (slots[i].active && slots[i].handle == handle) {
        return &slots[i];
      }
    }
    return nullptr;
  }

  SessionSlot* AllocateSlot(uint32_t handle) {
    if (SessionSlot* existing = FindSlot(handle)) {
      return existing;
    }
    for (int i = 0; i < kMaxSessions; ++i) {
      if (!slots[i].active) {
        return &slots[i];
      }
    }
    // Evict slot 0 if all slots are full.
    return &slots[0];
  }
};

AuthEngineState g_state = {};

// ── handle Name resolution ─────────────────────────────────────────────────

size_t SkipTPM2B(const uint8_t* buf, size_t off, size_t end) {
  if (off + 2 > end) return 0;
  const uint16_t sz = Read16(buf + off);
  const size_t new_off = off + 2u + sz;
  return (new_off <= end) ? new_off : 0u;
}

bool HandleName(uint32_t handle, uint8_t* name_out, size_t name_cap,
                size_t* name_size_out) {
  const uint8_t handle_type = static_cast<uint8_t>(handle >> 24);

  // Transient (0x80), Persistent (0x81), and NV Index (0x01): look up in Name
  // table. Note that sequence objects (0x80xxxxxx) have a valid 0-byte Name.
  if (handle_type == 0x80 || handle_type == 0x81 || handle_type == 0x01) {
    return g_state.names.Lookup(handle, name_out, name_cap, name_size_out);
  }

  // Permanent (0x40), PCR (0x00), and HMAC/Policy session (0x02/0x03) handles:
  // Name is the 4-byte big-endian handle value.
  if (handle_type == 0x40 || handle_type == 0x00 || handle_type == 0x02 ||
      handle_type == 0x03) {
    if (name_cap < 4) return false;
    Write32(name_out, handle);
    *name_size_out = 4;
    return true;
  }

  return false;
}

// ── Name extraction from responses ────────────────────────────────────────

void ExtractCreatePrimaryName(const uint8_t* buf, size_t params_start,
                              size_t params_end, uint32_t out_handle) {
  size_t p = params_start;
  p = SkipTPM2B(buf, p, params_end);  // outPublic
  if (p == 0) return;
  p = SkipTPM2B(buf, p, params_end);  // creationData
  if (p == 0) return;
  p = SkipTPM2B(buf, p, params_end);  // creationHash
  if (p == 0) return;
  if (p + 6 > params_end) return;
  p += 6;
  p = SkipTPM2B(buf, p, params_end);  // ticket digest
  if (p == 0) return;
  if (p + 2 > params_end) return;
  const uint16_t name_size = Read16(buf + p);
  if (p + 2u + name_size > params_end) return;
  g_state.names.Add(out_handle, buf + p + 2, name_size);
}

void ExtractLoadName(const uint8_t* buf, size_t params_start, size_t params_end,
                     uint32_t out_handle) {
  if (params_start + 2 > params_end) return;
  const uint16_t name_size = Read16(buf + params_start);
  if (params_start + 2u + name_size > params_end) return;
  g_state.names.Add(out_handle, buf + params_start + 2, name_size);
}

void ExtractCreateLoadedName(const uint8_t* buf, size_t params_start,
                             size_t params_end, uint32_t out_handle) {
  size_t p = params_start;
  p = SkipTPM2B(buf, p, params_end);  // outPrivate
  if (p == 0) return;
  p = SkipTPM2B(buf, p, params_end);  // outPublic
  if (p == 0) return;
  if (p + 2 > params_end) return;
  const uint16_t name_size = Read16(buf + p);
  if (p + 2u + name_size > params_end) return;
  g_state.names.Add(out_handle, buf + p + 2, name_size);
}

// Sequence objects created by MAC_Start or HashSequenceStart have
// object->nameAlg == TPM_ALG_NULL, so EntityGetName() returns an empty (0-byte)
// Name.
void ExtractSequenceName(const uint8_t* /*buf*/, size_t /*params_start*/,
                         size_t /*params_end*/, uint32_t out_handle) {
  g_state.names.Add(out_handle, nullptr, 0);
}

typedef void (*NameExtractorFn)(const uint8_t* buf, size_t params_start,
                                size_t params_end, uint32_t out_handle);

struct NameExtractorEntry {
  uint32_t command_code;
  NameExtractorFn fn;
};

const NameExtractorEntry kNameExtractors[] = {
    {TPM2_CC_CreatePrimary, ExtractCreatePrimaryName},
    {TPM2_CC_Load, ExtractLoadName},
    {TPM2_CC_LoadExternal, ExtractLoadName},
    {TPM2_CC_CreateLoaded, ExtractCreateLoadedName},
    {TPM2_CC_MAC_Start, ExtractSequenceName},
    {TPM2_CC_HashSequenceStart, ExtractSequenceName},
};

void PopulateNameFromResponse(uint32_t command_code, const uint8_t* buf,
                              size_t params_off, size_t params_end,
                              uint32_t out_handle) {
  for (size_t i = 0; i < sizeof(kNameExtractors) / sizeof(kNameExtractors[0]);
       ++i) {
    if (kNameExtractors[i].command_code == command_code) {
      kNameExtractors[i].fn(buf, params_off, params_end, out_handle);
      return;
    }
  }
}

// ── StartAuthSession, NV_DefineSpace, and Policy wire capture ─────────────

void CaptureStartAuthSessionCommand(const uint8_t* buf, size_t size) {
  g_state.pending_start_auth_session = true;
  g_state.start_auth_session_compatible = false;
  if (size < 27) return;

  size_t p = 10;
  const uint32_t tpm_key = Read32(buf + p);
  p += 4;
  const uint32_t bind = Read32(buf + p);
  p += 4;
  p = SkipTPM2B(buf, p, size);  // nonceCaller
  if (p == 0) return;
  const size_t encrypted_salt_off = p;
  p = SkipTPM2B(buf, p, size);  // encryptedSalt
  if (p == 0) return;
  if (p + 1 > size) return;
  const uint8_t session_type = buf[p];

  const uint16_t auth_hash = Read16(buf + size - 2);
  const uint16_t encrypted_salt_size = Read16(buf + encrypted_salt_off);

  const bool valid_type = (session_type == TPM2_SE_HMAC ||
                           session_type == TPM2_SE_POLICY ||
                           session_type == TPM2_SE_TRIAL);

  g_state.start_auth_session_type = session_type;
  g_state.start_auth_session_auth_hash = auth_hash;
  g_state.start_auth_session_compatible =
      tpm_key == TPM2_RH_NULL && bind == TPM2_RH_NULL &&
      encrypted_salt_size == 0 && valid_type && DigestSizeFor(auth_hash) != 0;
}

// Pre-computes the NV Index Name = nameAlg(2B) || Hash(TPMS_NV_PUBLIC) from a
// TPM2_NV_DefineSpace command parameter area. If the command succeeds,
// SessionAuthProcessResponse commits it to the NameTable.
void CaptureNVDefineSpaceCommand(const uint8_t* buf, size_t cp_off,
                                 size_t command_size) {
  g_state.pending_nv_define = false;
  if (cp_off >= command_size) return;

  // cpBuffer layout: auth(TPM2B_AUTH) | publicInfo(TPM2B_NV_PUBLIC)
  size_t p = SkipTPM2B(buf, cp_off, command_size);
  if (p == 0 || p + 2 > command_size) return;

  const uint16_t nv_pub_size = Read16(buf + p);
  p += 2;
  if (nv_pub_size < 14 || p + nv_pub_size > command_size) return;

  // TPMS_NV_PUBLIC starts with nvIndex(4B) | nameAlg(2B)
  const uint32_t nv_index = Read32(buf + p);
  const uint16_t name_alg = Read16(buf + p + 4);

  uint8_t digest[SESSION_AUTH_MAX_DIGEST];
  size_t digest_len = 0;
  if (!ComputeDigest(name_alg, buf + p, nv_pub_size, digest, &digest_len)) {
    return;
  }
  if (2 + digest_len > sizeof(g_state.pending_nv_name)) return;

  Write16(g_state.pending_nv_name, name_alg);
  std::memcpy(g_state.pending_nv_name + 2, digest, digest_len);
  g_state.pending_nv_name_size = 2 + digest_len;

  // Also pre-compute the NV Index Name with TPMA_NV_WRITTEN (1 << 29, i.e.
  // bit 5 of byte 6 in big-endian TPMS_NV_PUBLIC) set, which the TPM applies on
  // the first successful NV_Write / NV_Extend / NV_SetBits / NV_Increment.
  g_state.pending_nv_written_name_size = 0;
  if (nv_pub_size <= 256) {
    uint8_t pub_written[256];
    std::memcpy(pub_written, buf + p, nv_pub_size);
    pub_written[6] |= 0x20u;
    uint8_t w_digest[SESSION_AUTH_MAX_DIGEST];
    size_t w_digest_len = 0;
    if (ComputeDigest(name_alg, pub_written, nv_pub_size, w_digest,
                      &w_digest_len)) {
      Write16(g_state.pending_nv_written_name, name_alg);
      std::memcpy(g_state.pending_nv_written_name + 2, w_digest, w_digest_len);
      g_state.pending_nv_written_name_size = 2 + w_digest_len;
    }
  }

  g_state.pending_nv_index = nv_index;
  g_state.pending_nv_define = true;
}

void CapturePolicyCommand(uint32_t command_code, const uint8_t* buf,
                          size_t size) {
  g_state.pending_policy_cmd = false;
  if (size < 14) return;

  // All tracked 1-handle Policy commands have policySession at byte 10.
  const uint32_t policy_session = Read32(buf + 10);
  if (!g_state.FindSlot(policy_session)) return;

  size_t cp_off = 14;
  if (Read16(buf) == TPM2_ST_SESSIONS) {
    if (18 > size) return;
    const uint32_t auth_sz = Read32(buf + 14);
    if (18u + auth_sz > size) return;
    cp_off = 18u + auth_sz;
  }

  switch (command_code) {
    case TPM2_CC_PolicyCommandCode:
      if (cp_off + 4 > size) return;
      g_state.pending_policy_cc_arg = Read32(buf + cp_off);
      g_state.pending_policy_session = policy_session;
      g_state.pending_policy_cmd = true;
      break;
    case TPM2_CC_PolicyLocality:
      if (cp_off + 1 > size) return;
      g_state.pending_policy_locality = buf[cp_off];
      g_state.pending_policy_session = policy_session;
      g_state.pending_policy_cmd = true;
      break;
    case TPM2_CC_PolicyPassword:
    case TPM2_CC_PolicyAuthValue:
    case TPM2_CC_PolicyRestart:
    case TPM2_CC_PolicyGetDigest:
      g_state.pending_policy_session = policy_session;
      g_state.pending_policy_cmd = true;
      break;
    default:
      break;
  }
}

void ApplyPolicyResponseUpdate(uint32_t command_code, const uint8_t* resp_buf,
                               size_t resp_size) {
  SessionSlot* slot = g_state.FindSlot(g_state.pending_policy_session);
  if (!slot) return;

  uint8_t msg[SESSION_AUTH_MAX_DIGEST + 16];
  size_t mlen = 0;

  switch (command_code) {
    case TPM2_CC_PolicyRestart:
      std::memset(slot->policy_digest, 0, sizeof(slot->policy_digest));
      slot->is_password_needed = false;
      break;

    case TPM2_CC_PolicyCommandCode:
      std::memcpy(msg, slot->policy_digest, slot->digest_size);
      mlen = slot->digest_size;
      Write32(msg + mlen, TPM2_CC_PolicyCommandCode);
      mlen += 4;
      Write32(msg + mlen, g_state.pending_policy_cc_arg);
      mlen += 4;
      ComputeDigest(slot->hash_alg, msg, mlen, slot->policy_digest, nullptr);
      break;

    case TPM2_CC_PolicyAuthValue:
      std::memcpy(msg, slot->policy_digest, slot->digest_size);
      mlen = slot->digest_size;
      Write32(msg + mlen, TPM2_CC_PolicyAuthValue);
      mlen += 4;
      ComputeDigest(slot->hash_alg, msg, mlen, slot->policy_digest, nullptr);
      slot->is_password_needed = false;
      break;

    case TPM2_CC_PolicyPassword:
      // Per TPM 2.0 Part 3 §23.8 (PolicyPassword.c:17), TPM2_PolicyPassword
      // hashes TPM_CC_PolicyAuthValue (0x0000016B) into policyDigest so that
      // PolicyPassword and PolicyAuthValue satisfy the same authPolicy digest.
      std::memcpy(msg, slot->policy_digest, slot->digest_size);
      mlen = slot->digest_size;
      Write32(msg + mlen, TPM2_CC_PolicyAuthValue);
      mlen += 4;
      ComputeDigest(slot->hash_alg, msg, mlen, slot->policy_digest, nullptr);
      slot->is_password_needed = true;
      break;

    case TPM2_CC_PolicyLocality:
      std::memcpy(msg, slot->policy_digest, slot->digest_size);
      mlen = slot->digest_size;
      Write32(msg + mlen, TPM2_CC_PolicyLocality);
      mlen += 4;
      msg[mlen++] = g_state.pending_policy_locality;
      ComputeDigest(slot->hash_alg, msg, mlen, slot->policy_digest, nullptr);
      break;

    case TPM2_CC_PolicyGetDigest: {
      // Response params layout: policyDigest (TPM2B_DIGEST) at offset 10
      // (or offset 14 if TPM_ST_SESSIONS).
      size_t off = (Read16(resp_buf) == TPM2_ST_SESSIONS) ? 14u : 10u;
      if (off + 2 <= resp_size) {
        const uint16_t dsz = Read16(resp_buf + off);
        if (dsz <= SESSION_AUTH_MAX_DIGEST && off + 2u + dsz <= resp_size) {
          std::memcpy(slot->policy_digest, resp_buf + off + 2, dsz);
        }
      }
      break;
    }

    default:
      break;
  }
}

// ── command patching pipeline ──────────────────────────────────────────────

bool FindAuthArea(const uint8_t* buf, size_t command_size,
                  const CommandAttrEntry& attr, size_t* auth_size_off_out,
                  size_t* auth_off_out, uint32_t* auth_size_out) {
  const size_t handles_off = 10;
  const size_t auth_size_off = handles_off + 4u * attr.handle_count;
  if (auth_size_off + 4 > command_size) return false;

  const uint32_t auth_size = Read32(buf + auth_size_off);
  const size_t auth_off = auth_size_off + 4;
  if (auth_off + auth_size > command_size) return false;

  *auth_size_off_out = auth_size_off;
  *auth_off_out = auth_off;
  *auth_size_out = auth_size;
  return true;
}

bool ComputeCpHash(uint16_t hash_alg, const uint8_t* buf, uint32_t command_code,
                   uint8_t handle_count, size_t cp_off, size_t cp_size,
                   uint8_t cp_hash_out[SESSION_AUTH_MAX_DIGEST],
                   size_t* cp_hash_size_out) {
  constexpr size_t kHandlesOff = 10;
  const EVP_MD* md = EvpMdForAlg(hash_alg);
  if (!md) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;

  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  uint8_t cc_be[4];
  Write32(cc_be, command_code);
  EVP_DigestUpdate(ctx, cc_be, 4);

  for (uint8_t i = 0; i < handle_count; ++i) {
    const uint32_t h = Read32(buf + kHandlesOff + 4u * i);
    uint8_t name[kMaxNameSize];
    size_t name_size = 0;
    if (!HandleName(h, name, sizeof(name), &name_size)) {
      EVP_MD_CTX_free(ctx);
      return false;
    }
    if (name_size > 0) {
      EVP_DigestUpdate(ctx, name, name_size);
    }
  }
  if (cp_size > 0) {
    EVP_DigestUpdate(ctx, buf + cp_off, cp_size);
  }

  unsigned int out_len = 0;
  EVP_DigestFinal_ex(ctx, cp_hash_out, &out_len);
  EVP_MD_CTX_free(ctx);
  *cp_hash_size_out = out_len;
  return true;
}

bool ComputeSessionHmac(const SessionSlot& slot, const uint8_t* cp_hash,
                        size_t cp_hash_size, const uint8_t* nonce_caller,
                        size_t nonce_caller_size, uint8_t session_attrs,
                        uint8_t hmac_out[SESSION_AUTH_MAX_DIGEST],
                        size_t* hmac_size_out) {
  uint8_t hmac_msg[SESSION_AUTH_MAX_DIGEST + kNonceCallerSize +
                   SESSION_AUTH_MAX_DIGEST + 1];
  size_t mlen = 0;
  std::memcpy(hmac_msg + mlen, cp_hash, cp_hash_size);
  mlen += cp_hash_size;
  std::memcpy(hmac_msg + mlen, nonce_caller, nonce_caller_size);
  mlen += nonce_caller_size;
  std::memcpy(hmac_msg + mlen, slot.nonce_tpm, slot.nonce_tpm_size);
  mlen += slot.nonce_tpm_size;
  hmac_msg[mlen++] = session_attrs;

  return ComputeHmacDigest(slot.hash_alg, slot.session_key,
                           slot.session_key_size, hmac_msg, mlen, hmac_out,
                           hmac_size_out);
}

size_t PatchAuthArea(uint8_t* buf, size_t buf_capacity, size_t command_size,
                     size_t nonce_off, uint16_t orig_nonce_size,
                     uint16_t orig_hmac_size, uint8_t session_attrs,
                     size_t auth_size_off, uint32_t auth_size,
                     const uint8_t* nonce_caller, size_t nonce_caller_size,
                     const uint8_t* hmac_out, size_t hmac_size) {
  const size_t cp_off = auth_size_off + 4u + auth_size;
  const size_t cp_size = command_size - cp_off;

  const size_t new_nonce_field = 2 + nonce_caller_size;
  const size_t new_hmac_field = 2 + hmac_size;
  const size_t old_nonce_field = 2 + orig_nonce_size;
  const size_t old_hmac_field = 2 + orig_hmac_size;
  const std::int64_t delta =
      static_cast<std::int64_t>(new_nonce_field + new_hmac_field) -
      static_cast<std::int64_t>(old_nonce_field + old_hmac_field);
  const size_t new_command_size =
      static_cast<size_t>(static_cast<std::int64_t>(command_size) + delta);
  if (new_command_size > buf_capacity) return command_size;

  const size_t new_cp_off =
      static_cast<size_t>(static_cast<std::int64_t>(cp_off) + delta);
  if (cp_size && new_cp_off != cp_off) {
    std::memmove(buf + new_cp_off, buf + cp_off, cp_size);
  }

  size_t w = nonce_off;
  Write16(buf + w, static_cast<uint16_t>(nonce_caller_size));
  w += 2;
  if (nonce_caller_size > 0) {
    std::memcpy(buf + w, nonce_caller, nonce_caller_size);
    w += nonce_caller_size;
  }
  buf[w++] = session_attrs;
  Write16(buf + w, static_cast<uint16_t>(hmac_size));
  w += 2;
  if (hmac_size > 0) {
    std::memcpy(buf + w, hmac_out, hmac_size);
    w += hmac_size;
  }
  while (w < new_cp_off) buf[w++] = 0;

  const uint32_t new_auth_size =
      static_cast<uint32_t>(static_cast<std::int64_t>(auth_size) + delta);
  Write32(buf + auth_size_off, new_auth_size);
  Write32(buf + 2, static_cast<uint32_t>(new_command_size));

  return new_command_size;
}

}  // namespace

extern "C" {

void SessionAuthInit(uint32_t session_handle, const uint8_t* nonce_tpm,
                     size_t nonce_tpm_size, const uint8_t* session_key,
                     size_t session_key_size, uint16_t auth_hash_alg) {
  const size_t dsz = DigestSizeFor(auth_hash_alg);
  SessionSlot* slot = g_state.AllocateSlot(session_handle);
  std::memset(slot, 0, sizeof(*slot));
  slot->active = (dsz != 0);
  slot->handle = session_handle;
  slot->session_type = (static_cast<uint8_t>(session_handle >> 24) == 0x03)
                           ? TPM2_SE_POLICY
                           : TPM2_SE_HMAC;
  slot->hash_alg = auth_hash_alg;
  slot->digest_size = dsz;

  if (nonce_tpm_size > sizeof(slot->nonce_tpm)) {
    nonce_tpm_size = sizeof(slot->nonce_tpm);
  }
  if (nonce_tpm && nonce_tpm_size) {
    std::memcpy(slot->nonce_tpm, nonce_tpm, nonce_tpm_size);
  }
  slot->nonce_tpm_size = nonce_tpm_size;

  if (session_key_size > sizeof(slot->session_key)) {
    session_key_size = sizeof(slot->session_key);
  }
  if (session_key && session_key_size) {
    std::memcpy(slot->session_key, session_key, session_key_size);
  }
  slot->session_key_size = session_key_size;

  if (slot->active) {
    g_state.most_recent_handle = session_handle;
  }
}

void SessionAuthReset(void) { std::memset(&g_state, 0, sizeof(g_state)); }

uint32_t SessionAuthGetSessionHandle(void) {
  if (g_state.most_recent_handle != 0) {
    if (SessionSlot* s = g_state.FindSlot(g_state.most_recent_handle)) {
      return s->handle;
    }
  }
  for (int i = 0; i < kMaxSessions; ++i) {
    if (g_state.slots[i].active) {
      return g_state.slots[i].handle;
    }
  }
  return 0u;
}

bool SessionAuthGetPolicyDigest(uint32_t session_handle, uint8_t* digest_out,
                                size_t* size_out) {
  SessionSlot* slot = g_state.FindSlot(session_handle);
  if (!slot || slot->digest_size == 0) return false;
  if (digest_out) {
    std::memcpy(digest_out, slot->policy_digest, slot->digest_size);
  }
  if (size_out) {
    *size_out = slot->digest_size;
  }
  return true;
}

size_t SessionAuthPatchCommand(uint8_t* buf, size_t command_size,
                               size_t buf_capacity) {
  g_state.last_command_used_session = false;
  g_state.pending_nv_define = false;
  g_state.pending_nv_write = false;
  g_state.pending_policy_cmd = false;

  if (!buf || command_size < 10 || command_size > buf_capacity) {
    return command_size;
  }

  const uint16_t tag = Read16(buf + 0);
  const uint32_t header_size = Read32(buf + 2);
  if (header_size != command_size) {
    return command_size;
  }
  const uint32_t command_code = Read32(buf + 6);
  g_state.last_command_code = command_code;

  if (command_code == TPM2_CC_StartAuthSession) {
    CaptureStartAuthSessionCommand(buf, command_size);
    return command_size;
  }

  CapturePolicyCommand(command_code, buf, command_size);

  if (tag != TPM2_ST_SESSIONS) {
    return command_size;
  }

  CommandAttrEntry attr;
  if (!LookupCommandAttr(command_code, &attr)) {
    return command_size;
  }

  size_t auth_size_off, auth_off;
  uint32_t auth_size;
  if (!FindAuthArea(buf, command_size, attr, &auth_size_off, &auth_off,
                    &auth_size)) {
    return command_size;
  }

  const size_t cp_off = auth_off + auth_size;
  const size_t cp_size = command_size - cp_off;

  if (command_code == TPM2_CC_NV_DefineSpace) {
    CaptureNVDefineSpaceCommand(buf, cp_off, command_size);
  } else if ((command_code == TPM2_CC_NV_Write ||
              command_code == TPM2_CC_NV_Extend ||
              command_code == TPM2_CC_NV_SetBits ||
              command_code == TPM2_CC_NV_Increment) &&
             command_size >= 18) {
    g_state.pending_nv_write = true;
    g_state.pending_nv_write_index = Read32(buf + 14);
  }

  size_t p = auth_off;
  if (p + 4 > auth_off + auth_size) return command_size;
  const uint32_t session_handle = Read32(buf + p);
  p += 4;

  SessionSlot* slot = g_state.FindSlot(session_handle);
  if (!slot || slot->digest_size == 0) {
    return command_size;
  }

  if (p + 2 > auth_off + auth_size) return command_size;
  const uint16_t orig_nonce_size = Read16(buf + p);
  const size_t nonce_off = p;
  p += 2 + orig_nonce_size;
  if (p + 1 > auth_off + auth_size) return command_size;
  const uint8_t session_attrs = buf[p];
  p += 1;
  if (p + 2 > auth_off + auth_size) return command_size;
  const uint16_t orig_hmac_size = Read16(buf + p);
  p += 2 + orig_hmac_size;
  if (p != auth_off + auth_size) return command_size;

  g_state.last_session_handle = session_handle;
  g_state.last_session_attrs = session_attrs;
  g_state.last_command_used_session = true;

  // If a Policy session used TPM2_PolicyPassword, CheckPWAuthSession in
  // SessionProcess.c:1515 verifies the cleartext password (empty "") instead of
  // an HMAC, while still rolling nonces when nonceCaller is present.
  if (slot->session_type == TPM2_SE_POLICY && slot->is_password_needed) {
    uint8_t nonce_caller[kNonceCallerSize];
    std::memset(nonce_caller, kNonceCallerFill, sizeof(nonce_caller));
    return PatchAuthArea(buf, buf_capacity, command_size, nonce_off,
                         orig_nonce_size, orig_hmac_size, session_attrs,
                         auth_size_off, auth_size, nonce_caller,
                         sizeof(nonce_caller), nullptr, 0);
  }

  uint8_t cp_hash[SESSION_AUTH_MAX_DIGEST];
  size_t cp_hash_size = 0;
  if (!ComputeCpHash(slot->hash_alg, buf, command_code, attr.handle_count,
                     cp_off, cp_size, cp_hash, &cp_hash_size)) {
    return command_size;
  }

  uint8_t nonce_caller[kNonceCallerSize];
  std::memset(nonce_caller, kNonceCallerFill, sizeof(nonce_caller));

  uint8_t hmac_out[SESSION_AUTH_MAX_DIGEST];
  size_t hmac_size = 0;
  if (!ComputeSessionHmac(*slot, cp_hash, cp_hash_size, nonce_caller,
                          sizeof(nonce_caller), session_attrs, hmac_out,
                          &hmac_size)) {
    return command_size;
  }

  return PatchAuthArea(buf, buf_capacity, command_size, nonce_off,
                       orig_nonce_size, orig_hmac_size, session_attrs,
                       auth_size_off, auth_size, nonce_caller,
                       sizeof(nonce_caller), hmac_out, hmac_size);
}

void SessionAuthProcessResponse(const uint8_t* buf, size_t size) {
  if (!buf || size < 10) return;

  const uint16_t tag = Read16(buf + 0);
  const uint32_t hdr_size = Read32(buf + 2);
  const uint32_t rc = Read32(buf + 6);
  if (hdr_size != size) return;

  // 1. Reactive StartAuthSession bootstrap.
  if (g_state.pending_start_auth_session) {
    const bool compatible = g_state.start_auth_session_compatible;
    const uint8_t session_type = g_state.start_auth_session_type;
    const uint16_t auth_hash = g_state.start_auth_session_auth_hash;
    g_state.pending_start_auth_session = false;
    g_state.start_auth_session_compatible = false;
    if (tag != TPM2_ST_NO_SESSIONS || rc != TPM2_RC_SUCCESS) return;
    if (!compatible || size < 16) return;
    const uint32_t handle = Read32(buf + 10);
    const uint16_t nonce_size = Read16(buf + 14);
    if (16u + nonce_size > size) return;
    SessionAuthInit(handle, buf + 16, nonce_size, /*session_key=*/nullptr,
                    /*session_key_size=*/0, auth_hash);
    if (SessionSlot* slot = g_state.FindSlot(handle)) {
      slot->session_type = session_type;
    }
    return;
  }

  // 2. Commit pending Policy digest updates on success.
  if (g_state.pending_policy_cmd) {
    g_state.pending_policy_cmd = false;
    if (rc == TPM2_RC_SUCCESS) {
      ApplyPolicyResponseUpdate(g_state.last_command_code, buf, size);
    }
  }

  // 3. Commit pending NV_DefineSpace Name on success.
  if (g_state.pending_nv_define) {
    g_state.pending_nv_define = false;
    if (rc == TPM2_RC_SUCCESS) {
      g_state.names.Add(g_state.pending_nv_index, g_state.pending_nv_name,
                        g_state.pending_nv_name_size,
                        g_state.pending_nv_written_name,
                        g_state.pending_nv_written_name_size);
    }
  }

  // 4. Promote NV Index Name with TPMA_NV_WRITTEN after successful write.
  if (g_state.pending_nv_write) {
    g_state.pending_nv_write = false;
    if (rc == TPM2_RC_SUCCESS) {
      g_state.names.PromoteNvToWritten(g_state.pending_nv_write_index);
    }
  }

  if (rc != TPM2_RC_SUCCESS) return;

  CommandAttrEntry attr;
  if (!LookupCommandAttr(g_state.last_command_code, &attr)) return;

  // Handle commands that return an output handle even without TPM_ST_SESSIONS
  // (such as TPM2_HashSequenceStart or TPM2_LoadExternal).
  if (tag == TPM2_ST_NO_SESSIONS) {
    if (attr.out_handle_count > 0 && size >= 14) {
      const uint32_t out_handle = Read32(buf + 10);
      PopulateNameFromResponse(g_state.last_command_code, buf, 14, size,
                               out_handle);
    }
    return;
  }

  if (tag != TPM2_ST_SESSIONS) return;

  const size_t params_size_off = 10u + 4u * attr.out_handle_count;
  if (params_size_off + 4 > size) return;

  const uint32_t param_size = Read32(buf + params_size_off);
  const size_t params_off = params_size_off + 4u;
  if (params_off + param_size > size) return;
  const size_t auth_area_off = params_off + param_size;

  if (auth_area_off + 2 > size) return;
  const uint16_t nonce_size = Read16(buf + auth_area_off);
  if (auth_area_off + 2u + nonce_size + 1u > size) return;
  const uint8_t resp_session_attrs = buf[auth_area_off + 2u + nonce_size];

  if (g_state.last_command_used_session) {
    if (SessionSlot* slot = g_state.FindSlot(g_state.last_session_handle)) {
      const bool continue_session =
          ((g_state.last_session_attrs & 0x01u) != 0) &&
          ((resp_session_attrs & 0x01u) != 0);
      if (!continue_session) {
        // SessionProcess.c:2277 calls SessionFlush() when continueSession is 0.
        slot->active = false;
        if (g_state.most_recent_handle == slot->handle) {
          g_state.most_recent_handle = 0;
        }
      } else {
        if (nonce_size > 0 && nonce_size <= sizeof(slot->nonce_tpm)) {
          std::memcpy(slot->nonce_tpm, buf + auth_area_off + 2, nonce_size);
          slot->nonce_tpm_size = nonce_size;
        }
        // SessionProcess.c:2104 resets policy session data whenever a policy
        // session rolls its nonce on a command with continueSession == 1.
        if (slot->session_type == TPM2_SE_POLICY) {
          std::memset(slot->policy_digest, 0, sizeof(slot->policy_digest));
          slot->is_password_needed = false;
        }
      }
    }
  }

  if (attr.out_handle_count == 0) return;
  const uint32_t out_handle = Read32(buf + 10);
  PopulateNameFromResponse(g_state.last_command_code, buf, params_off,
                           params_off + param_size, out_handle);
}

}  // extern "C"
