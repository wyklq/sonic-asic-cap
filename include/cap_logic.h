/*
 * cap_logic.h - pure, hardware-independent helpers used by sai_cap_query.
 *
 * These functions are separated from the SAI client code so they can be unit
 * tested without libsairedis, a redis server, or an ASIC. Everything here
 * depends only on the vendored SAI headers.
 */

#ifndef SAI_CAP_LOGIC_H
#define SAI_CAP_LOGIC_H

#include <sai.h>
#include <saimetadatatypes.h>

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

namespace cap {

/*
 * Normalize a SAI status code to a stable summary key.
 *
 * Vendors return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + attribute-index and similar
 * range codes. Bucketing on the raw value would split one semantic outcome
 * across thousands of keys, so the range macros are collapsed here.
 */
/*
 * Return the raw bit pattern of a SAI status.
 */
inline uint32_t
status_raw_code(sai_status_t status)
{
    return static_cast<uint32_t>(status);
}

inline std::string
status_name(sai_status_t status)
{
    switch (status) {
        case SAI_STATUS_SUCCESS:
            return "SUCCESS";
        case SAI_STATUS_FAILURE:
            return "FAILURE";
        case SAI_STATUS_NOT_SUPPORTED:
            return "NOT_SUPPORTED";
        case SAI_STATUS_NO_MEMORY:
            return "NO_MEMORY";
        case SAI_STATUS_INSUFFICIENT_RESOURCES:
            return "INSUFFICIENT_RESOURCES";
        case SAI_STATUS_INVALID_PARAMETER:
            return "INVALID_PARAMETER";
        case SAI_STATUS_ITEM_ALREADY_EXISTS:
            return "ITEM_ALREADY_EXISTS";
        case SAI_STATUS_ITEM_NOT_FOUND:
            return "ITEM_NOT_FOUND";
        case SAI_STATUS_BUFFER_OVERFLOW:
            return "BUFFER_OVERFLOW";
        case SAI_STATUS_INVALID_OBJECT_TYPE:
            return "INVALID_OBJECT_TYPE";
        case SAI_STATUS_INVALID_OBJECT_ID:
            return "INVALID_OBJECT_ID";
        case SAI_STATUS_NOT_IMPLEMENTED:
            return "NOT_IMPLEMENTED";
        case SAI_STATUS_OBJECT_IN_USE:
            return "OBJECT_IN_USE";
        case SAI_STATUS_TABLE_FULL:
            return "TABLE_FULL";
        case SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING:
            return "MANDATORY_ATTRIBUTE_MISSING";
        default:
            return "OTHER";
    }
}

/*
 * Collapse a SAI status into one stable summary key.
 *
 * This deliberately does NOT use the SAI_STATUS_IS_* macros. On non-Windows
 * builds SAI_STATUS_CODE(x) is (-x), so every failure status is a small
 * negative int and `x & ~0xFFFF` is 0xFFFF0000 for all of -1..-0xFFFF. That
 * makes SAI_STATUS_IS_INVALID_ATTRIBUTE() true for unrelated codes such as
 * SAI_STATUS_NOT_SUPPORTED or SAI_STATUS_BUFFER_OVERFLOW.
 *
 * Instead: exact-match the documented plain statuses first, then classify the
 * per-attribute range codes by the high 16 bits of the raw value. Both the
 * negative (POSIX) and positive (Windows) encodings are handled.
 *
 *   range base           negative     positive     bucket
 *   0x00010000           0xFFFF0000   0x00010000   INVALID_ATTRIBUTE
 *   0x00020000           0xFFFE0000   0x00020000   INVALID_ATTR_VALUE
 *   0x00030000           0xFFFD0000   0x00030000   ATTR_NOT_IMPLEMENTED
 *   0x00040000           0xFFFC0000   0x00040000   UNKNOWN_ATTRIBUTE
 *   0x00050000           0xFFFB0000   0x00050000   ATTR_NOT_SUPPORTED
 */
/*
 * A buffered value type carries its own element count as the first member and
 * can therefore be probed with a small buffer and grown on
 * SAI_STATUS_BUFFER_OVERFLOW.
 */
inline bool
is_buffered_value_type(sai_attr_value_type_t type)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
        case SAI_ATTR_VALUE_TYPE_INT8_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
        case SAI_ATTR_VALUE_TYPE_INT16_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        case SAI_ATTR_VALUE_TYPE_INT32_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
        case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
        case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
        case SAI_ATTR_VALUE_TYPE_MAP_LIST:
        case SAI_ATTR_VALUE_TYPE_TLV_LIST:
        case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
        case SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
        case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
        case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
        case SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
        case SAI_ATTR_VALUE_TYPE_JSON:
        case SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
        case SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
            return true;

        default:
            return false;
    }
}

/*
 * Value types the tool cannot safely ask for. A pointer value has no
 * caller-owned buffer, and the per-lane optical lists use opaque fixed-size
 * structs with no usable count preamble.
 */
inline bool
can_fetch_value_type(sai_attr_value_type_t type)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_POINTER:
        case SAI_ATTR_VALUE_TYPE_PORT_EYE_VALUES_LIST:
        case SAI_ATTR_VALUE_TYPE_PORT_ERR_STATUS_LIST:
        case SAI_ATTR_VALUE_TYPE_PORT_LANE_LATCH_STATUS_LIST:
        case SAI_ATTR_VALUE_TYPE_PORT_FREQUENCY_OFFSET_PPM_LIST:
        case SAI_ATTR_VALUE_TYPE_PORT_SNR_LIST:
        case SAI_ATTR_VALUE_TYPE_PORT_PAM4_EYE_VALUES_LIST:
        case SAI_ATTR_VALUE_TYPE_TAPS_LIST:
        case SAI_ATTR_VALUE_TYPE_PRBS_PER_LANE_RX_STATUS_LIST:
        case SAI_ATTR_VALUE_TYPE_PRBS_PER_LANE_RX_STATE_LIST:
        case SAI_ATTR_VALUE_TYPE_PRBS_PER_LANE_BIT_ERROR_RATE_LIST:
            return false;

        default:
            return true;
    }
}

/*
 * Outcome of trying to read one attribute.
 */
enum class FetchKind
{
    Ok,      /* value returned */
    Skipped, /* the tool chose not to ask (un-probeable value type) */
    Failure, /* the adapter / transport rejected the request */
};

inline std::string
classify_status(sai_status_t status)
{
    /* Plain statuses win, because their raw high word collides with the
     * INVALID_ATTRIBUTE band under the negative encoding. */
    const std::string plain = status_name(status);
    if (plain != "OTHER") {
        return plain;
    }

    switch (status_raw_code(status) & 0xFFFF0000u) {
        case 0xFFFB0000u:
        case 0x00050000u:
            return "ATTR_NOT_SUPPORTED";
        case 0xFFFC0000u:
        case 0x00040000u:
            return "UNKNOWN_ATTRIBUTE";
        case 0xFFFD0000u:
        case 0x00030000u:
            return "ATTR_NOT_IMPLEMENTED";
        case 0xFFFE0000u:
        case 0x00020000u:
            return "INVALID_ATTR_VALUE";
        case 0xFFFF0000u:
        case 0x00010000u:
            return "INVALID_ATTRIBUTE";
        default:
            break;
    }

    return "OTHER";
}

/*
 * Bucket label used by report summaries. A tool-side skip must never be
 * counted as an adapter failure, otherwise "we did not ask" silently reads as
 * "the ASIC does not support it".
 */
inline std::string
summary_bucket(FetchKind kind, sai_status_t status)
{
    switch (kind) {
        case FetchKind::Ok:
            return "ok";
        case FetchKind::Skipped:
            return "skipped_by_tool";
        case FetchKind::Failure:
            break;
    }
    return classify_status(status);
}

/*
 * Coarse classification for enum values that are absent from the locally
 * generated metadata (for example values added by a newer vendor SAI).
 */
inline std::string
classify_unknown_value(int32_t value)
{
    const uint32_t raw = static_cast<uint32_t>(value);

    if (raw >= 0x20000000u && raw < 0x30000000u) {
        return "UNKNOWN_EXTENSION_RANGE";
    }
    if (raw >= 0x10000000u && raw < 0x20000000u) {
        return "UNKNOWN_CUSTOM_RANGE";
    }
    return "UNKNOWN_VALUE";
}

inline std::string
format_stats_modes(uint32_t modes)
{
    struct ModeName
    {
        uint32_t bit;
        const char *name;
    };

    static const ModeName names[] = {
        {SAI_STATS_MODE_READ, "READ"},
        {SAI_STATS_MODE_READ_AND_CLEAR, "READ_AND_CLEAR"},
        {SAI_STATS_MODE_BULK_READ, "BULK_READ"},
        {SAI_STATS_MODE_BULK_CLEAR, "BULK_CLEAR"},
        {SAI_STATS_MODE_BULK_READ_AND_CLEAR, "BULK_READ_AND_CLEAR"},
    };

    if (modes == 0) {
        /*
         * A zero mask almost always means the adapter did not report modes,
         * not that the counter supports none. Report it explicitly so it is
         * not read as a contradiction.
         */
        return "UNREPORTED(0x0)";
    }

    std::string result;
    uint32_t known = 0;
    for (const auto &entry : names) {
        known |= entry.bit;
        if ((modes & entry.bit) == 0) {
            continue;
        }
        if (!result.empty()) {
            result += "|";
        }
        result += entry.name;
    }

    const uint32_t unknown = modes & ~known;
    if (unknown != 0) {
        char text[32];
        std::snprintf(text, sizeof(text), "UNKNOWN(0x%x)", unknown);
        if (!result.empty()) {
            result += "|";
        }
        result += text;
    }

    return result;
}

/*
 * Pick a concrete statistics mode for a probe, based on what the adapter
 * declared and what the probe is allowed to use.
 *
 * READ is preferred because it is non-destructive. READ_AND_CLEAR is only
 * chosen when explicitly allowed, because it mutates counters and affects
 * production monitoring. Returns 0 when nothing suitable was declared.
 */
inline uint32_t
select_read_only_stats_mode(uint32_t declared_modes, bool allow_clear)
{
    if ((declared_modes & SAI_STATS_MODE_READ) != 0) {
        return SAI_STATS_MODE_READ;
    }
    if (allow_clear &&
        (declared_modes & SAI_STATS_MODE_READ_AND_CLEAR) != 0) {
        return SAI_STATS_MODE_READ_AND_CLEAR;
    }
    return 0;
}

/*
 * Compare a reviewed capability record against the live probe outcome.
 *
 * This is how a vendor's claim is falsified: a stat the adapter said supports
 * READ should actually be readable.
 */
enum class Agreement
{
    Agree,             /* claim and probe match */
    Contradiction,     /* claim positive, probe negative */
    Unverifiable,      /* no usable live object to probe */
};

inline Agreement
compare_capability_with_probe(bool claimed_supported, bool probe_ok)
{
    if (claimed_supported == probe_ok) {
        return Agreement::Agree;
    }
    if (claimed_supported && !probe_ok) {
        return Agreement::Contradiction;
    }
    return Agreement::Unverifiable;
}

inline const char *
agreement_name(Agreement agreement)
{
    switch (agreement) {
        case Agreement::Agree:
            return "AGREE";
        case Agreement::Contradiction:
            return "CONTRADICTION";
        case Agreement::Unverifiable:
            return "UNVERIFIABLE";
    }
    return "UNKNOWN";
}

/*
 * Compare an attribute capability claim against a real GET on a live object.
 *
 * Attributes that only exist under a condition (isconditional / isvalidonly)
 * may legitimately reject a GET when the condition is not met on this object,
 * so a failed probe there is Unverifiable, not a Contradiction. Without this
 * distinction the tool would emit false contradictions for conditional
 * attributes, which is exactly the kind of false positive it exists to avoid.
 */
inline Agreement
compare_attribute_capability_with_probe(
    bool claimed_get,
    bool probe_ok,
    bool conditionally_valid)
{
    if (claimed_get == probe_ok) {
        return Agreement::Agree;
    }
    if (claimed_get && !probe_ok) {
        return conditionally_valid
            ? Agreement::Unverifiable
            : Agreement::Contradiction;
    }
    /* Claimed not-gettable but the GET actually worked: not a false claim. */
    return Agreement::Unverifiable;
}

inline std::string
format_api_version(sai_api_version_t version)
{
    const uint64_t numeric = static_cast<uint64_t>(version);
    const uint64_t major = numeric / 10000;
    const uint64_t minor = (numeric / 100) % 100;
    const uint64_t revision = numeric % 100;

    return std::to_string(major) + "." +
        std::to_string(minor) + "." +
        std::to_string(revision) +
        " (" + std::to_string(numeric) + ")";
}

inline std::string
to_upper(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });
    return value;
}

inline bool
object_name_matches(const char *object_type_name, const std::string &filter)
{
    if (filter.empty()) {
        return true;
    }
    return to_upper(object_type_name == nullptr ? "" : object_type_name)
               .find(to_upper(filter)) != std::string::npos;
}

/*
 * Statistics enums contain range markers such as ..._CUSTOM_RANGE_BASE and
 * ..._RANGE_START that are not real counters. Metadata normally excludes them,
 * but older or vendor-generated metadata can still carry them, and probing a
 * marker can produce misleading results.
 */
inline bool
is_stat_marker_name(const std::string &name)
{
    if (name.find("_CUSTOM_RANGE_") != std::string::npos ||
        name.find("_EXTENSIONS_RANGE_") != std::string::npos ||
        name.find("_RANGE_BASE") != std::string::npos ||
        name.find("_RANGE_END") != std::string::npos) {
        return true;
    }
    if (name.size() >= 6 &&
        name.compare(name.size() - 6, 6, "_START") == 0) {
        return true;
    }
    if (name.size() >= 4 &&
        name.compare(name.size() - 4, 4, "_END") == 0) {
        return true;
    }
    return false;
}

} // namespace cap

#endif /* SAI_CAP_LOGIC_H */
