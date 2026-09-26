#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace {

std::mt19937 rng{std::random_device{}()};

std::string random_hex(std::size_t length) {
    static const char hex[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) out.push_back(hex[dist(rng)]);
    return out;
}

std::string random_ip() {
    std::uniform_int_distribution<int> octet(1, 254);
    return std::to_string(octet(rng)) + "." +
           std::to_string(octet(rng)) + "." +
           std::to_string(octet(rng)) + "." +
           std::to_string(octet(rng));
}

std::string random_domain() {
    static const std::vector<std::string> tlds = {
        "com", "net", "org", "xyz", "top", "su", "ru", "io",
    };
    static const std::vector<std::string> words = {
        "evil", "c2", "panel", "gate", "update", "cdn",
        "mail", "secure", "login", "attach", "botnet",
    };
    std::uniform_int_distribution<std::size_t> pick_w(0, words.size() - 1);
    std::uniform_int_distribution<std::size_t> pick_t(0, tlds.size() - 1);
    return words[pick_w(rng)] + "-" + words[pick_w(rng)] + "." + tlds[pick_t(rng)];
}

std::string random_url() {
    static const std::vector<std::string> paths = {
        "/gate.php", "/beacon", "/upd.php", "/payload.bin",
        "/stage2.exe", "/loader", "/upload.asp", "/config.json",
    };
    static const std::vector<std::string> schemes = {"http://", "https://"};
    std::uniform_int_distribution<std::size_t> pw(0, paths.size() - 1);
    std::uniform_int_distribution<std::size_t> ps(0, schemes.size() - 1);
    return schemes[ps(rng)] + random_domain() + paths[pw(rng)];
}

std::string random_email() {
    static const std::vector<std::string> users = {
        "attacker", "admin", "invoice", "support", "researcher",
        "no-reply", "billing", "helpdesk",
    };
    std::uniform_int_distribution<std::size_t> pu(0, users.size() - 1);
    return users[pu(rng)] + "@" + random_domain();
}

std::string random_family_line() {
    static const std::vector<std::string> families = {
        "emotet", "smokeloader", "gandcrab", "qbot",
        "wannacry", "trickbot", "mirai", "locky",
        "dridex", "ursnif", "qakbot", "cerber",
    };
    static const std::vector<std::string> contexts = {
        "loader variant", "C2 gate", "ransomware affiliate",
        "infostealer exfil", "dropper family", "botnet DGA",
        "banking trojan", "ransomware builder",
    };
    std::uniform_int_distribution<std::size_t> pf(0, families.size() - 1);
    std::uniform_int_distribution<std::size_t> pc(0, contexts.size() - 1);
    return "Sample flagged as " + families[pf(rng)] + " (" + contexts[pc(rng)] + ")";
}

std::string random_ioc_line() {
    std::uniform_int_distribution<int> kind(0, 6);
    switch (kind(rng)) {
        case 0: return random_url();
        case 1: return random_ip();
        case 2: return random_domain();
        case 3: return random_email();
        case 4: return random_hex(32);
        case 5: return random_hex(64);
        case 6: return "#" + random_domain();
    }
    return "";
}

void print_banner(const char* title) {
    std::cout << "\n=== " << title << " ===\n";
}

} // namespace

int main(int argc, char** argv) {
    int count = 50;

    if (argc > 1) {
        try {
            count = std::stoi(argv[1]);
            if (count < 0) count = 0;
            if (count > 1'000'000) count = 1'000'000;
        } catch (const std::exception&) {
            std::cerr << "Usage: " << argv[0] << " [count]\n";
            std::cerr << "  count: number of IOCs to generate (default 50)\n";
            return 1;
        }
    }

    std::cout << "[*] IOC generator — standalone, no dependencies\n";
    std::cout << "[*] Generating " << count << " random IOCs\n";

    print_banner("RANDOM IOCs");
    for (int i = 0; i < count; ++i) {
        std::cout << random_ioc_line() << "\n";
    }

    print_banner("RANDOM FAMILY MATCHES");
    for (int i = 0; i < 10; ++i) {
        std::cout << random_family_line() << "\n";
    }

    print_banner("VALIDATION OF KNOWN IOCs");

    std::vector<std::string> known = {
        "http://malware-c2.example.com/gate.php",
        "https://evil-host.top/payload.bin",
        "45.33.32.156",
        "10.0.0.1",
        "8.8.8.8",
        "evil-c2.xyz",
        "attacker@evil-c2.xyz",
        "44d88612fea8a8f36de82e1278abb02f",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    for (const auto& s : known) {
        std::cout << "  [known] " << s << "\n";
    }

    print_banner("NOISE (SHOULD NOT MATCH)");
    std::vector<std::string> noise = {
        "This program cannot be run in DOS mode.",
        "KERNEL32.dll",
        "GetProcAddress",
        "some random text",
        "12345",
        "not-a-domain",
    };
    for (const auto& s : noise) {
        std::cout << "  [noise] " << s << "\n";
    }

    std::cout << "\n[*] Done. Pipe this output to the real extractor to test it.\n";
    return 0;
}