#pragma once

#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace asnr {
    using Bytes = std::vector<uint8_t>;
    using Str = std::string;
    template <typename T>
    using Vec = std::vector<T>;
    template <class... Types>
    using Var = std::variant<Types...>;

    class Tlv;
    Vec<Tlv> parse(const Bytes &bytes);

    struct Tag {
        enum Class { UNIVERSAL = 0b00,
                     APPLICATION = 0b01,
                     CONTEXT_SPECIFIC = 0b10,
                     PRIVATE = 0b11 };
        Class cl;
        bool is_constructed;
        size_t number;

        Str class_name() const {
            switch (cl) {
                case Class::UNIVERSAL:
                    return "UNIVERSAL";
                case Class::APPLICATION:
                    return "APPLICATION";
                case Class::CONTEXT_SPECIFIC:
                    return "CONTEXT_SPECIFIC";
                case Class::PRIVATE:
                    return "PRIVATE";
                default:
                    return "";
            };
        }
    };

    class Tlv {
    public:
        class ParseError : public std::exception {
        public:
            ParseError(const Str &message) : message(message) {}
            const char *what() { return message.c_str(); }

        private:
            Str message;
        };

        Tlv(const Bytes &data, size_t &offset) {
            const auto tag_fb = at(data, offset++);
            tag.cl = (Tag::Class)(tag_fb >> 6);
            tag.is_constructed = (tag_fb & 0b00100000) >> 5;
            tag.number = tag_fb & 0b00011111;
            if (tag.number == 0b00011111) {
                tag.number = 0;
                uint8_t tag_number_cb;
                do {
                    tag_number_cb = at(data, offset++);
                    tag.number = (tag.number << 7) | (tag_number_cb & 0b01111111);
                } while (tag_number_cb & 0b10000000);
            }

            length = at(data, offset);
            if ((length & 0x80) == 0)
                offset++;
            else {
                uint8_t length_length = at(data, offset++) & 0x7F;
                length = 0;
                for (uint8_t i = 0; i < length_length; i++)
                    length = (length << 8) | at(data, offset++);
            }

            if (offset + length > data.size())
                throw ParseError("Invalid length " + std::to_string(length) + " which with offset " + std::to_string(offset) + " is greater then data size " + std::to_string(data.size()));
            inner = Bytes(data.begin() + offset, data.begin() + offset + length);
            if (tag.is_constructed)
                inner = parse(std::get<Bytes>(inner));
            offset += length;
        }

        Tag get_tag() const { return tag; }
        size_t get_length() const { return length; }
        const Var<Bytes, Vec<Tlv>> &get_inner() const { return inner; }

        const Tlv &at(const size_t i) const {
            if (std::holds_alternative<Bytes>(inner))
                throw std::out_of_range("Attempt to access inner TLV in TLV wich holds none of them");
            const auto &v = std::get<Vec<Tlv>>(inner);
            if (i >= v.size())
                throw std::out_of_range("Attempt to access inner TLV at index " + std::to_string(i) + " in TLV wich holds only " + std::to_string(v.size()) + " of them");
            return v[i];
        }

        Str json(const std::string &indent = "") const {
            std::stringstream ss;
            ss << indent
               << "{\"tag\": {\"class\": \"" << tag.class_name() << "\""
               << ", \"is_constructed\": " << (tag.is_constructed ? "true" : "false")
               << ", \"number: \"0x" << hex(tag.number) << "\"}"
               << ", \"length\": " << length
               << ", \"inner\": ";
            if (std::holds_alternative<Bytes>(inner))
                ss << "\"0x" << hex(std::get<Bytes>(inner)) << "\"";
            else {
                ss << "[" << std::endl;
                const auto &inner_vec = std::get<Vec<Tlv>>(inner);
                for (size_t i = 0; i < inner_vec.size(); i++) {
                    ss << inner_vec[i].json(indent + "\t");
                    if (i + 1 != inner_vec.size())
                        ss << "," << std::endl;
                }
                ss << "]";
            }
            ss << "}";
            return ss.str();
        }

    private:
        Tag tag;
        size_t length;
        Var<Bytes, Vec<Tlv>> inner;

    private:
        uint8_t at(const Bytes &bytes, const size_t i) {
            if (i >= bytes.size())
                throw ParseError(Str("Index ") + std::to_string(i) + " greater then or equal container size " + std::to_string(bytes.size()));
            return bytes[i];
        }

        Str
        hex(const uint8_t b) const {
            static char alphabet[] = "0123456789ABCDEF";
            return Str{alphabet[b / 16], alphabet[b % 16]};
        }

        Str hex(const Bytes &bytes) const {
            Str result;
            result.reserve(2 * bytes.size());
            for (const auto &i : bytes)
                result += hex(i);
            return result;
        }
    };

    inline Vec<Tlv> parse(const Bytes &bytes) {
        Vec<Tlv> result;
        size_t offset = 0;
        while (offset != bytes.size())
            result.push_back(Tlv(bytes, offset));
        return result;
    }
} // namespace asnr
