/*
 * Unit tests for json_value.h.
 *
 * JSON escaping is the part of machine-readable output that fails silently:
 * a wrong escape produces output that still looks plausible but does not
 * parse. These tests pin the escaping rules and the structural output.
 *
 * Build/run: make -C tests test
 */

#include "../include/json_value.h"

#include <cstdio>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void
expect_eq(const std::string &actual, const std::string &expected, const char *what)
{
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::printf(
            "FAIL %-52s expected='%s' actual='%s'\n",
            what,
            expected.c_str(),
            actual.c_str());
    } else {
        std::printf("ok   %-52s -> %s\n", what, actual.c_str());
    }
}

/* ------------------------------------------------------------------ */
/* escaping                                                            */
/* ------------------------------------------------------------------ */

void
test_json_escape()
{
    expect_eq(cap::json_escape("plain"), "plain", "plain text unchanged");
    expect_eq(cap::json_escape(""), "", "empty string");

    /* The two mandatory escapes. */
    expect_eq(cap::json_escape("a\"b"), "a\\\"b", "quote is escaped");
    expect_eq(cap::json_escape("a\\b"), "a\\\\b", "backslash is escaped");

    /* A lone trailing backslash must not swallow the closing quote. */
    expect_eq(
        cap::json_escape("trailing\\"),
        "trailing\\\\",
        "trailing backslash is escaped");

    /* Short escapes. */
    expect_eq(cap::json_escape("\n"), "\\n", "newline");
    expect_eq(cap::json_escape("\r"), "\\r", "carriage return");
    expect_eq(cap::json_escape("\t"), "\\t", "tab");
    expect_eq(cap::json_escape("\b"), "\\b", "backspace");
    expect_eq(cap::json_escape("\f"), "\\f", "form feed");

    /* Other control characters use \u00XX. */
    expect_eq(cap::json_escape("\x01"), "\\u0001", "SOH becomes \\u0001");
    expect_eq(cap::json_escape("\x1f"), "\\u001f", "unit separator");
    /* 0x20 (space) must NOT be escaped. */
    expect_eq(cap::json_escape(" "), " ", "space is not escaped");

    /* Bytes >= 0x80 pass through so UTF-8 payloads are not corrupted. */
    expect_eq(
        cap::json_escape("\xc3\xa9"),
        "\xc3\xa9",
        "UTF-8 bytes pass through");
}

/* ------------------------------------------------------------------ */
/* structure                                                           */
/* ------------------------------------------------------------------ */

void
test_json_scalars()
{
    expect_eq(cap::JsonValue::make_null().dump(), "null\n", "null");
    expect_eq(cap::JsonValue::make_bool(true).dump(), "true\n", "true");
    expect_eq(cap::JsonValue::make_bool(false).dump(), "false\n", "false");
    expect_eq(cap::JsonValue::make_int(-7).dump(), "-7\n", "negative int");
    expect_eq(
        cap::JsonValue::make_uint(18446744073709551615ULL).dump(),
        "18446744073709551615\n",
        "uint64 max is not truncated");
    expect_eq(
        cap::JsonValue::make_string("hi").dump(),
        "\"hi\"\n",
        "quoted string");
}

void
test_json_containers()
{
    expect_eq(cap::JsonValue::make_array().dump(), "[]\n", "empty array");
    expect_eq(cap::JsonValue::make_object().dump(), "{}\n", "empty object");

    auto array = cap::JsonValue::make_array();
    array.push(cap::JsonValue::make_int(1));
    array.push(cap::JsonValue::make_int(2));
    expect_eq(
        array.dump(),
        "[\n  1,\n  2\n]\n",
        "array elements are comma separated without trailing comma");

    auto object = cap::JsonValue::make_object();
    object.set("a", cap::JsonValue::make_int(1));
    object.set("b", cap::JsonValue::make_string("x"));
    expect_eq(
        object.dump(),
        "{\n  \"a\": 1,\n  \"b\": \"x\"\n}\n",
        "object members in insertion order");

    /* Overwriting a key must not duplicate it or move it. */
    object.set("a", cap::JsonValue::make_int(9));
    expect_eq(
        object.dump(),
        "{\n  \"a\": 9,\n  \"b\": \"x\"\n}\n",
        "set on an existing key overwrites in place");
    ++g_checks;
    if (!object.has("a") || object.has("missing")) {
        ++g_failures;
        std::printf("FAIL %-52s\n", "has() reports membership correctly");
    } else {
        std::printf("ok   %-52s -> true\n", "has() reports membership correctly");
    }

    /* Nesting. */
    auto nested = cap::JsonValue::make_object();
    nested.set("list", array);
    expect_eq(
        nested.dump(),
        "{\n  \"list\": [\n    1,\n    2\n  ]\n}\n",
        "nested array is indented");
}

/*
 * A string containing a quote, a backslash and a control character must
 * round-trip through the serializer without breaking the document.
 */
void
test_json_hostile_string()
{
    auto object = cap::JsonValue::make_object();
    object.set(
        "k",
        cap::JsonValue::make_string("a\"b\\c\nd\x01"));
    expect_eq(
        object.dump(),
        "{\n  \"k\": \"a\\\"b\\\\c\\nd\\u0001\"\n}\n",
        "hostile string is fully escaped");
}

} // namespace

int
main()
{
    std::printf("json_value unit tests\n");
    std::printf("--------------------\n");

    test_json_escape();
    test_json_scalars();
    test_json_containers();
    test_json_hostile_string();

    std::printf("--------------------\n");
    std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
