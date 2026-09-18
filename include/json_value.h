/*
 * json_value.h - a tiny, dependency-free JSON value/builder.
 *
 * The capability report is emitted as a single JSON document in json mode, so
 * the tool needs a correct serializer without pulling in a JSON dependency.
 * Only the subset actually used is implemented, but escaping and number
 * formatting are handled carefully because incorrect escaping silently
 * corrupts the output.
 */

#ifndef SAI_CAP_JSON_VALUE_H
#define SAI_CAP_JSON_VALUE_H

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace cap {

/*
 * Escape a string for inclusion in a JSON string literal. The returned value
 * does not include the surrounding quotes.
 *
 * Handles the two mandatory escapes (quote and backslash), the short escapes,
 * and control characters below 0x20 via \u00XX. Bytes >= 0x80 are passed
 * through unchanged: the payload is assumed UTF-8, and re-encoding arbitrary
 * bytes would corrupt it further.
 */
inline std::string
json_escape(const std::string &input)
{
    std::string out;
    out.reserve(input.size() + 8);

    for (unsigned char c : input) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    char buffer[8];
                    std::snprintf(
                        buffer,
                        sizeof(buffer),
                        "\\u%04x",
                        static_cast<unsigned>(c));
                    out += buffer;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }

    return out;
}

/*
 * Minimal JSON value. Objects preserve insertion order, which keeps the
 * emitted document stable and diff-friendly across runs.
 */
class JsonValue
{
    public:
        enum class Type
        {
            Null,
            Bool,
            Int,
            Uint,
            String,
            Array,
            Object,
        };

        JsonValue() = default;

        static JsonValue make_null()
        {
            return JsonValue();
        }

        static JsonValue make_bool(bool value)
        {
            JsonValue json;
            json.m_type = Type::Bool;
            json.m_bool = value;
            return json;
        }

        static JsonValue make_int(int64_t value)
        {
            JsonValue json;
            json.m_type = Type::Int;
            json.m_int = value;
            return json;
        }

        static JsonValue make_uint(uint64_t value)
        {
            JsonValue json;
            json.m_type = Type::Uint;
            json.m_uint = value;
            return json;
        }

        static JsonValue make_string(const std::string &value)
        {
            JsonValue json;
            json.m_type = Type::String;
            json.m_string = value;
            return json;
        }

        static JsonValue make_array()
        {
            JsonValue json;
            json.m_type = Type::Array;
            return json;
        }

        static JsonValue make_object()
        {
            JsonValue json;
            json.m_type = Type::Object;
            return json;
        }

        Type type() const
        {
            return m_type;
        }

        /* Append to an array. Only valid when type() == Array. */
        void push(JsonValue value)
        {
            m_array.push_back(std::move(value));
        }

        /* Insert or overwrite an object member, preserving first-seen order. */
        void set(const std::string &key, JsonValue value)
        {
            for (auto &entry : m_object) {
                if (entry.first == key) {
                    entry.second = std::move(value);
                    return;
                }
            }
            m_object.emplace_back(key, std::move(value));
        }

        bool has(const std::string &key) const
        {
            for (const auto &entry : m_object) {
                if (entry.first == key) {
                    return true;
                }
            }
            return false;
        }

        /* Serialize with two-space indentation and a trailing newline. */
        std::string dump() const
        {
            std::string out;
            write(out, 0);
            out += "\n";
            return out;
        }

    private:
        void write(std::string &out, int indent) const
        {
            switch (m_type) {
                case Type::Null:
                    out += "null";
                    return;
                case Type::Bool:
                    out += m_bool ? "true" : "false";
                    return;
                case Type::Int:
                    out += std::to_string(m_int);
                    return;
                case Type::Uint:
                    out += std::to_string(m_uint);
                    return;
                case Type::String:
                    out += '"';
                    out += json_escape(m_string);
                    out += '"';
                    return;
                case Type::Array:
                    write_array(out, indent);
                    return;
                case Type::Object:
                    write_object(out, indent);
                    return;
            }
        }

        static void write_indent(std::string &out, int indent)
        {
            out.append(static_cast<size_t>(indent) * 2, ' ');
        }

        void write_array(std::string &out, int indent) const
        {
            if (m_array.empty()) {
                out += "[]";
                return;
            }
            out += "[\n";
            for (size_t i = 0; i < m_array.size(); ++i) {
                write_indent(out, indent + 1);
                m_array[i].write(out, indent + 1);
                if (i + 1 != m_array.size()) {
                    out += ",";
                }
                out += "\n";
            }
            write_indent(out, indent);
            out += "]";
        }

        void write_object(std::string &out, int indent) const
        {
            if (m_object.empty()) {
                out += "{}";
                return;
            }
            out += "{\n";
            for (size_t i = 0; i < m_object.size(); ++i) {
                write_indent(out, indent + 1);
                out += '"';
                out += json_escape(m_object[i].first);
                out += "\": ";
                m_object[i].second.write(out, indent + 1);
                if (i + 1 != m_object.size()) {
                    out += ",";
                }
                out += "\n";
            }
            write_indent(out, indent);
            out += "}";
        }

        Type m_type = Type::Null;
        bool m_bool = false;
        int64_t m_int = 0;
        uint64_t m_uint = 0;
        std::string m_string;
        std::vector<JsonValue> m_array;
        /* Ordered key/value pairs; the report is small enough that a linear
         * scan is simpler and faster than a map. */
        std::vector<std::pair<std::string, JsonValue>> m_object;
};

} // namespace cap

#endif /* SAI_CAP_JSON_VALUE_H */
