#ifndef FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_
#define FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_

#include <stddef.h>
#include <stdint.h>

#if __has_include(<tss2/tss2_tpm2_types.h>)
#include <tss2/tss2_tpm2_types.h>
#endif

// Standard TPM 2.0 constants used by the session auth layer (guarded so they
// coexist with <tss2/tss2_tpm2_types.h> when present).
#ifndef TPM2_ALG_SHA1
#define TPM2_ALG_SHA1 0x0004u
#endif
#ifndef TPM2_ALG_SHA256
#define TPM2_ALG_SHA256 0x000Bu
#endif
#ifndef TPM2_ALG_SHA384
#define TPM2_ALG_SHA384 0x000Cu
#endif
#ifndef TPM2_ALG_SHA512
#define TPM2_ALG_SHA512 0x000Du
#endif
#ifndef TPM2_ALG_NULL
#define TPM2_ALG_NULL 0x0010u
#endif

#ifndef TPM2_ST_NO_SESSIONS
#define TPM2_ST_NO_SESSIONS 0x8001u
#endif
#ifndef TPM2_ST_SESSIONS
#define TPM2_ST_SESSIONS 0x8002u
#endif

#ifndef TPM2_RC_SUCCESS
#define TPM2_RC_SUCCESS 0x00000000u
#endif

#ifndef TPM2_RH_NULL
#define TPM2_RH_NULL 0x40000007u
#endif
#ifndef TPM2_RS_PW
#define TPM2_RS_PW 0x40000009u
#endif

#ifndef TPM2_SE_HMAC
#define TPM2_SE_HMAC 0x00u
#endif
#ifndef TPM2_SE_POLICY
#define TPM2_SE_POLICY 0x01u
#endif
#ifndef TPM2_SE_TRIAL
#define TPM2_SE_TRIAL 0x03u
#endif

#ifndef TPM2_CC_Clear
#define TPM2_CC_Clear 0x00000126u
#endif
#ifndef TPM2_CC_NV_DefineSpace
#define TPM2_CC_NV_DefineSpace 0x0000012Au
#endif
#ifndef TPM2_CC_PCR_Allocate
#define TPM2_CC_PCR_Allocate 0x0000012Bu
#endif
#ifndef TPM2_CC_PCR_SetAuthPolicy
#define TPM2_CC_PCR_SetAuthPolicy 0x0000012Cu
#endif
#ifndef TPM2_CC_SetPrimaryPolicy
#define TPM2_CC_SetPrimaryPolicy 0x0000012Eu
#endif
#ifndef TPM2_CC_CreatePrimary
#define TPM2_CC_CreatePrimary 0x00000131u
#endif
#ifndef TPM2_CC_NV_Increment
#define TPM2_CC_NV_Increment 0x00000134u
#endif
#ifndef TPM2_CC_NV_SetBits
#define TPM2_CC_NV_SetBits 0x00000135u
#endif
#ifndef TPM2_CC_NV_Extend
#define TPM2_CC_NV_Extend 0x00000136u
#endif
#ifndef TPM2_CC_NV_Write
#define TPM2_CC_NV_Write 0x00000137u
#endif
#ifndef TPM2_CC_NV_WriteLock
#define TPM2_CC_NV_WriteLock 0x00000138u
#endif
#ifndef TPM2_CC_PCR_Event
#define TPM2_CC_PCR_Event 0x0000013Cu
#endif
#ifndef TPM2_CC_SequenceComplete
#define TPM2_CC_SequenceComplete 0x0000013Eu
#endif
#ifndef TPM2_CC_ActivateCredential
#define TPM2_CC_ActivateCredential 0x00000147u
#endif
#ifndef TPM2_CC_PolicyNV
#define TPM2_CC_PolicyNV 0x00000149u
#endif
#ifndef TPM2_CC_NV_Read
#define TPM2_CC_NV_Read 0x0000014Eu
#endif
#ifndef TPM2_CC_NV_ReadLock
#define TPM2_CC_NV_ReadLock 0x0000014Fu
#endif
#ifndef TPM2_CC_PolicySecret
#define TPM2_CC_PolicySecret 0x00000151u
#endif
#ifndef TPM2_CC_Create
#define TPM2_CC_Create 0x00000153u
#endif
#ifndef TPM2_CC_MAC
#define TPM2_CC_MAC 0x00000155u
#endif
#ifndef TPM2_CC_HMAC
#define TPM2_CC_HMAC 0x00000155u
#endif
#ifndef TPM2_CC_Load
#define TPM2_CC_Load 0x00000157u
#endif
#ifndef TPM2_CC_Quote
#define TPM2_CC_Quote 0x00000158u
#endif
#ifndef TPM2_CC_RSA_Decrypt
#define TPM2_CC_RSA_Decrypt 0x00000159u
#endif
#ifndef TPM2_CC_MAC_Start
#define TPM2_CC_MAC_Start 0x0000015Bu
#endif
#ifndef TPM2_CC_HMAC_Start
#define TPM2_CC_HMAC_Start 0x0000015Bu
#endif
#ifndef TPM2_CC_SequenceUpdate
#define TPM2_CC_SequenceUpdate 0x0000015Cu
#endif
#ifndef TPM2_CC_Sign
#define TPM2_CC_Sign 0x0000015Du
#endif
#ifndef TPM2_CC_Unseal
#define TPM2_CC_Unseal 0x0000015Eu
#endif
#ifndef TPM2_CC_ContextLoad
#define TPM2_CC_ContextLoad 0x00000161u
#endif
#ifndef TPM2_CC_ContextSave
#define TPM2_CC_ContextSave 0x00000162u
#endif
#ifndef TPM2_CC_FlushContext
#define TPM2_CC_FlushContext 0x00000165u
#endif
#ifndef TPM2_CC_LoadExternal
#define TPM2_CC_LoadExternal 0x00000167u
#endif
#ifndef TPM2_CC_MakeCredential
#define TPM2_CC_MakeCredential 0x00000168u
#endif
#ifndef TPM2_CC_PolicyAuthValue
#define TPM2_CC_PolicyAuthValue 0x0000016Bu
#endif
#ifndef TPM2_CC_PolicyCommandCode
#define TPM2_CC_PolicyCommandCode 0x0000016Cu
#endif
#ifndef TPM2_CC_PolicyCpHash
#define TPM2_CC_PolicyCpHash 0x0000016Eu
#endif
#ifndef TPM2_CC_PolicyLocality
#define TPM2_CC_PolicyLocality 0x0000016Fu
#endif
#ifndef TPM2_CC_PolicyNameHash
#define TPM2_CC_PolicyNameHash 0x00000170u
#endif
#ifndef TPM2_CC_PolicyOR
#define TPM2_CC_PolicyOR 0x00000171u
#endif
#ifndef TPM2_CC_ReadPublic
#define TPM2_CC_ReadPublic 0x00000173u
#endif
#ifndef TPM2_CC_StartAuthSession
#define TPM2_CC_StartAuthSession 0x00000176u
#endif
#ifndef TPM2_CC_VerifySignature
#define TPM2_CC_VerifySignature 0x00000177u
#endif
#ifndef TPM2_CC_GetCapability
#define TPM2_CC_GetCapability 0x0000017Au
#endif
#ifndef TPM2_CC_GetRandom
#define TPM2_CC_GetRandom 0x0000017Bu
#endif
#ifndef TPM2_CC_PolicyPCR
#define TPM2_CC_PolicyPCR 0x0000017Fu
#endif
#ifndef TPM2_CC_PolicyRestart
#define TPM2_CC_PolicyRestart 0x00000180u
#endif
#ifndef TPM2_CC_PCR_Extend
#define TPM2_CC_PCR_Extend 0x00000182u
#endif
#ifndef TPM2_CC_EventSequenceComplete
#define TPM2_CC_EventSequenceComplete 0x00000185u
#endif
#ifndef TPM2_CC_HashSequenceStart
#define TPM2_CC_HashSequenceStart 0x00000186u
#endif
#ifndef TPM2_CC_PolicyGetDigest
#define TPM2_CC_PolicyGetDigest 0x00000189u
#endif
#ifndef TPM2_CC_PolicyPassword
#define TPM2_CC_PolicyPassword 0x0000018Cu
#endif
#ifndef TPM2_CC_PolicyNvWritten
#define TPM2_CC_PolicyNvWritten 0x0000018Fu
#endif
#ifndef TPM2_CC_CreateLoaded
#define TPM2_CC_CreateLoaded 0x00000191u
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Exported by vendor/TPM/TPMCmd/tpm/src/support/CommandCodeAttributes.c
uint16_t CommandCodeToCommandIndex(uint32_t commandCode);
int CommandCapGetOneCC(uint32_t commandCode, uint32_t* commandAttributes);
uint32_t CommandAuthRole(uint16_t commandIndex, uint32_t handleIndex);

#ifdef __cplusplus
}
#endif

struct CommandAttrEntry {
  uint32_t command_code;
  uint8_t handle_count;       // total handles in the handle area (0..3)
  uint8_t auth_handle_count;  // subset of handles requiring authorization
  uint8_t out_handle_count;   // handles returned in the response handle area
};

// Dynamically resolves per-command handle and authorization counts for all
// 119+ implemented TPM 2.0 commands by querying CommandCodeAttributes.c in
// Tpm_CoreLib (backed by vendor/TPM/.../private/CommandAttributeData.h).
inline bool LookupCommandAttr(uint32_t command_code, CommandAttrEntry* out) {
  constexpr uint16_t kUnimplementedCommandIndex = 0xFFFFu;
  const uint16_t cmd_idx = CommandCodeToCommandIndex(command_code);
  if (cmd_idx == kUnimplementedCommandIndex) {
    return false;
  }

  uint32_t tpma_cc = 0;
  if (!CommandCapGetOneCC(command_code, &tpma_cc)) {
    return false;
  }

  // TPMA_CC bit layout (TPM 2.0 Part 2 Table "Definition of TPMA_CC Bits"):
  //   bits [27:25] (cHandles): number of handles in the command handle area
  //   bit  [28]    (rHandle):  1 if there is a handle in the response area
  const uint8_t handle_count = static_cast<uint8_t>((tpma_cc >> 25) & 0x7u);
  const uint8_t out_handle_count = static_cast<uint8_t>((tpma_cc >> 28) & 0x1u);

  uint8_t auth_handle_count = 0;
  for (uint8_t i = 0; i < handle_count && i < 2u; ++i) {
    if (CommandAuthRole(cmd_idx, i) != 0u) {
      ++auth_handle_count;
    }
  }

  if (out) {
    out->command_code = command_code;
    out->handle_count = handle_count;
    out->auth_handle_count = auth_handle_count;
    out->out_handle_count = out_handle_count;
  }
  return true;
}

#endif  // FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_
