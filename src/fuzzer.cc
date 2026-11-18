/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code.
 */

#include <arpa/inet.h>
#include <parser/byte_parser.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include <harness/session_auth.h>
#include <harness/tpm_wrapper.h>
}

// Called for each fuzzing input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  std::vector<std::vector<uint8_t>> commands;
  if (!parseCommands(Data, Size, commands)) {
    return 1;
  }

  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();
  SessionAuthReset();

  for (auto& cmd : commands) {
    size_t cmd_size = cmd.size();
    if (cmd.size() < cmd_size + 128) {
      cmd.resize(cmd_size + 128);
    }
    cmd_size = SessionAuthPatchCommand(cmd.data(), cmd_size, cmd.size());

    struct InBuffer request;
    request.buffer = cmd.data();
    request.buffer_size = cmd_size;

    char OutputBuffer[kMaxBuffers];
    struct OutBuffer response;
    response.buffer = (uint8_t*)OutputBuffer;
    response.buffer_size = kMaxBuffers;

    TPMSendCommand(kDefaultLocality, request, &response);
    SessionAuthProcessResponse(response.buffer, response.buffer_size);
  }

  SendTPM2ShutdownCommand();

  TPMShutdown();

  return 0;
}
