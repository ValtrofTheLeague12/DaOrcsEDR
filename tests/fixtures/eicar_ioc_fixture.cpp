// Inert defensive fixture for exercising IOC and signature extraction.
//
// This program intentionally has no networking, persistence, process creation,
// credential access, obfuscation, or exploit behavior. It only emits test
// strings. The EICAR marker below is the standard antivirus test signature.

#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr const char* kEicar =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const std::vector<std::string> kTestIndicators{
    "https://c2.example.invalid/gate.php",
    "https://update.example.invalid/payload.bin",
    "http://malware-c2.example.invalid/collect",
    "c2.example.invalid",
    "malware-c2.example.invalid",
    "defanged-domain[.]example[.]invalid",
    "operator@security.example.invalid",
    "198.51.100.42",
    "203.0.113.77",
    "192.0.2.146",
    "C2 infrastructure test marker",
    "suspicious test domain marker",
    "malware family test marker: emotet",
    "ransomware behavior test marker: wannacry",
    "ATT&CK test marker: T1071.001",
    "MBC test marker: MBC-001",
    "CVE test marker: CVE-2024-0001",
    "This is an inert IOC extraction fixture, not malware.",
};

} // namespace

int main() {
    std::cout << "STATIC_ANALYZER_EICAR_IOC_FIXTURE\n";
    std::cout << "This executable is inert and performs no network activity.\n\n";
    std::cout << "[EICAR]\n" << kEicar << "\n\n";
    std::cout << "[INDICATORS]\n";
    for (const std::string& indicator : kTestIndicators) {
        std::cout << indicator << '\n';
    }
    std::cout << "\n[END FIXTURE]\n";
    return 0;
}
