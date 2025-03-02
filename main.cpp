#include <cstring>
#include <fstream>
#include <iostream>

#include "asnr.hpp"

asnr::Bytes read_file(const std::string &path) {
    auto file = std::ifstream(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Can not open file " + path);
    return asnr::Bytes(std::istreambuf_iterator<char>(file), {});
}

int main(int argc, char *argv[]) {
    if ((argc < 2) || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        std::cout << "Arguments should be paths to files with BER encoded ASN.1" << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        const auto path = argv[i];
        const auto bytes = read_file(path);
        const auto result = asnr::parse(bytes);
        if (argc > 2)
            std::cout << path << std::endl;
        for (const auto &r : result)
            std::cout << r.json(argc == 2 ? "" : "\t") << std::endl;
    }

    return 0;
}
