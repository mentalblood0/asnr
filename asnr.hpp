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

    class BaseError : public std::exception {
    public:
        BaseError(const Str &message) : message(message) {}
        const char *what() const noexcept override { return message.c_str(); }

    private:
        Str message;
    };

    class DecodeError : public BaseError {
    public:
        DecodeError(const Str &message) : BaseError(message) {}
    };

    class EncodeError : public BaseError {
    public:
        EncodeError(const Str &message) : BaseError(message) {}
    };

    static uint8_t at(const Bytes &bytes, const size_t i) {
        if (i >= bytes.size())
            throw DecodeError(Str("at: index ") + std::to_string(i) + " >= container size " + std::to_string(bytes.size()));
        return bytes[i];
    }

    static void set(Bytes &bytes, const size_t i, const uint8_t b) {
        if (i >= bytes.size())
            throw EncodeError(Str("set one: index ") + std::to_string(i) + " >= container size " + std::to_string(bytes.size()));
        bytes[i] = b;
    }

    static void set(Bytes &bytes, const size_t i, const Bytes &b) {
        if (i + b.size() - 1 >= bytes.size())
            throw EncodeError(Str("set many: index ") + std::to_string(i) + " + " + std::to_string(b.size()) + " - 1 is greater then or equal container size " + std::to_string(bytes.size()));
        memcpy(bytes.data() + i, b.data(), b.size());
    }

    static Str hex(const uint8_t b) {
        static char alphabet[] = "0123456789ABCDEF";
        return Str{alphabet[b / 16], alphabet[b % 16]};
    }

    static Str hex(const Bytes &bytes) {
        Str result;
        result.reserve(2 * bytes.size());
        for (const auto &i : bytes)
            result += hex(i);
        return result;
    }

    class Tag {
    public:
        enum Class { UNIVERSAL = 0b00,
                     APPLICATION = 0b01,
                     CONTEXT_SPECIFIC = 0b10,
                     PRIVATE = 0b11 };

        void set_cl(const Class cl) {
            if (int(cl) < 0 || int(cl) > 3)
                throw DecodeError("Tag class must be from {0, 1, 2, 3}, but got " + std::to_string(cl));
            this->cl = cl;
        }

        void set_number(const size_t number) {
            this->number = number;
        }

        Tag(const Class cl, const bool is_constructed, const size_t number) : is_constructed(is_constructed) {
            set_cl(cl);
            set_number(number);
        }

        Tag(const Bytes &data, size_t &offset) {
            const auto tag_fb = at(data, offset++);
            set_cl(Tag::Class(tag_fb >> 6));
            is_constructed = (tag_fb & 0b00100000) >> 5;
            size_t _number = tag_fb & 0b00011111;
            if (_number == 0b00011111) {
                _number = 0;
                uint8_t tag_number_cb;
                do {
                    tag_number_cb = at(data, offset++);
                    _number = (_number << 7) | (tag_number_cb & 0b01111111);
                } while (tag_number_cb & 0b10000000);
            }
            set_number(_number);
        }

        Class get_cl() const { return cl; }
        bool get_is_constructed() const { return is_constructed; }
        size_t get_number() const { return number; }

        Str get_cl_str() const {
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

        void write_json(std::stringstream &output) const {
            output << "{\"class\": \"" << get_cl_str() << "\""
                   << ", \"is_constructed\": " << (is_constructed ? "true" : "false")
                   << ", \"number: \"0x" << hex(number) << "\"}";
        }

        Str json() const {
            std::stringstream output;
            write_json(output);
            return output.str();
        }

    private:
        Class cl;
        bool is_constructed;
        size_t number;
    };

    class Tlv;
    Vec<Tlv> parse(const Bytes &bytes);

    class Tlv {
    public:
        Tlv(const Tag::Class &tag_class, const size_t tag_number, const Bytes &inner)
            : tag(Tag(tag_class, false, tag_number)), inner(inner) {
            set_length();
            set_size();
        }

        Tlv(const Tag::Class &tag_class, const size_t tag_number, const Vec<Tlv> &inner)
            : tag(Tag(tag_class, true, tag_number)), inner(inner) {
            set_length();
            set_size();
        }

        Tlv(const Bytes &data, size_t &offset) : tag(Tag(data, offset)) {
            length = at(data, offset++);
            if (length & 0b10000000) {
                uint8_t length_length = length & 0b01111111;
                length = 0;
                for (uint8_t i = 0; i < length_length; i++)
                    length = (length << 8) | at(data, offset++);
            }

            if (offset + length > data.size())
                throw DecodeError("Invalid length " + std::to_string(length) + " which with offset " + std::to_string(offset) + " is greater then data size " + std::to_string(data.size()));
            inner = Bytes(data.begin() + offset, data.begin() + offset + length);
            if (tag.get_is_constructed())
                inner = parse(std::get<Bytes>(inner));
            offset += length;

            set_size();

            if (!offset && (encoded() != data))
                throw DecodeError("Given data != encoded decoded data");
        }

        void write_encoded(Bytes &output, size_t &offset) const {
            uint8_t tag_fb = (tag.get_cl() << 6) | (tag.get_is_constructed() << 5);
            if (tag.get_number() <= 30) {
                tag_fb |= tag.get_number();
                set(output, offset++, tag_fb);
            } else {
                tag_fb |= 0b00011111;
                set(output, offset++, tag_fb);

                auto remaining = tag.get_number();
                while (remaining) {
                    uint8_t cb = remaining & 0b01111111;
                    remaining >>= 7;
                    if (remaining)
                        cb |= 0b10000000;
                    set(output, offset++, cb);
                }
            }
            if (length < 128)
                set(output, offset++, length);
            else {
                auto temp = length;
                uint8_t length_length = 0;
                while (temp) {
                    temp >>= 8;
                    length_length++;
                }
                set(output, offset++, length_length | 0b10000000);
                for (int i = length_length - 1; i >= 0; i--)
                    set(output, offset++, (length >> (8 * i)) & 0xFF);
            }
            if (std::holds_alternative<Bytes>(inner)) {
                const auto &v = std::get<Bytes>(inner);
                set(output, offset, v);
                offset += v.size();
            } else
                for (const auto &tlv : std::get<Vec<Tlv>>(inner))
                    tlv.write_encoded(output, offset);
        }

        Bytes encoded() const {
            Bytes output;
            output.resize(size);
            size_t offset = 0;
            write_encoded(output, offset);
            if (output.size() != offset)
                throw EncodeError("Encoding result size " + std::to_string(output.size()) + " != result offset " + std::to_string(offset));
            return output;
        }

        Tag get_tag() const { return tag; }
        size_t get_length() const { return length; }
        const Var<Bytes, Vec<Tlv>> &get_inner() const { return inner; }
        size_t get_size() const { return size; }

        const Tlv &operator[](const size_t i) const {
            if (std::holds_alternative<Bytes>(inner))
                throw std::out_of_range("Attempt to access inner TLV in TLV wich holds none of them");
            const auto &v = std::get<Vec<Tlv>>(inner);
            if (i >= v.size())
                throw std::out_of_range("Attempt to access inner TLV at index " + std::to_string(i) + " in TLV wich holds only " + std::to_string(v.size()) + " of them");
            return v[i];
        }

        void write_json(const Str &indent, std::stringstream &output) const {
            output << indent
                   << "{\"tag\": ";
            tag.write_json(output);
            output << ", \"length\": " << length
                   << ", \"inner\": ";
            if (std::holds_alternative<Bytes>(inner))
                output << "\"0x" << hex(std::get<Bytes>(inner)) << "\"";
            else {
                output << "[" << std::endl;
                const auto &inner_vec = std::get<Vec<Tlv>>(inner);
                for (size_t i = 0; i < inner_vec.size(); i++) {
                    inner_vec[i].write_json(indent + "\t", output);
                    if (i + 1 != inner_vec.size())
                        output << "," << std::endl;
                }
                output << "]";
            }
            output << "}";
        }

        Str json(const Str &indent = "") const {
            std::stringstream output;
            write_json(indent, output);
            return output.str();
        }

    private:
        Tag tag;
        size_t length;
        Var<Bytes, Vec<Tlv>> inner;

        size_t size;

        void set_length() {
            if (std::holds_alternative<Bytes>(inner))
                length = std::get<Bytes>(inner).size();
            else {
                length = 0;
                for (const auto &tlv : std::get<Vec<Tlv>>(inner))
                    length += tlv.get_length();
            }
        }

        void set_size() {
            size_t header_length = 1;
            if (tag.get_number() > 30) {
                auto temp = tag.get_number();
                uint8_t tag_number_length = 0;
                while (temp) {
                    temp >>= 7;
                    tag_number_length++;
                }
                header_length += tag_number_length;
            }
            header_length++;
            if (length >= 128) {
                auto temp = length;
                uint8_t length_length = 0;
                while (temp) {
                    temp >>= 8;
                    length_length++;
                }
                header_length += length_length;
            }
            size = header_length + length;
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
