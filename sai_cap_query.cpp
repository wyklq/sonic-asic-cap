/*
 * sai_cap_query - discover the capabilities an ASIC exposes through SAI.
 *
 * The tool links against libsairedis and therefore talks to the running syncd
 * over the regular SAI Redis / ZMQ transport.
 *
 * P0 changes (see README.md "P0 hardening"):
 *   - it runs as a sairedis CLIENT by default (SAI_REDIS_ENABLE_CLIENT=true),
 *     so it never binds the server endpoint that syncd already owns;
 *   - every libsairedis call is wrapped in try/catch, because libsairedis
 *     throws on malformed/unexpected responses;
 *   - the switch VID is validated against the live switch table before any
 *     capability query, so a bad VID can never be mistaken for "unsupported";
 *   - "tool skipped this" is reported separately from "adapter rejected it";
 *   - extension/range status codes are normalized for the summaries;
 *   - SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST drives a three-state verdict
 *     (asic supported / asic unsupported / not listed).
 */

/*
 * The SAI headers define a C ABI but do not carry extern "C" guards, so all
 * of them must be included inside an extern "C" block to match libsairedis /
 * libsaimetadata and actually link.
 */
extern "C" {
#include <sai.h>
#include <saiversion.h>
#include <saimetadata.h>
#include <saimetadatautils.h>
#include "sairedis.h"
}

#include <string>
#include <vector>

/* Pure, unit-testable helpers (status/enum formatting). */
#include "cap_logic.h"

/*
 * libsairedis provides these serializers through libsaimeta, but the public
 * packaging does not install <sai_serialize.h>. Declaring the two functions
 * used here keeps the build self-contained; the signatures are stable across
 * sairedis releases (see sairedis meta/sai_serialize.h).
 */
std::string sai_serialize_attr_value(
    const sai_attr_metadata_t &metadata,
    const sai_attribute_t &attribute,
    bool count_only);
std::string sai_serialize_status(sai_status_t status);

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>
namespace {

using namespace cap;

/* Thin adapters over cap:: so call sites read naturally with SAI types. */
bool
matches_object_filter(
    const sai_object_type_info_t *info,
    const std::string &filter)
{
    return object_name_matches(info->objecttypename, filter);
}

bool
is_stat_marker_name(const char *name)
{
    return cap::is_stat_marker_name(name == nullptr ? "" : name);
}

constexpr uint32_t kInitialListCapacity = 64;
constexpr uint32_t kMaximumListCapacity = 1024 * 1024;

/* ------------------------------------------------------------------ */
/* options                                                             */
/* ------------------------------------------------------------------ */

enum class Transport
{
    Client, /* connect to the running server (default, safe) */
    Server, /* become a sairedis server (only if no syncd runs) */
};

struct Options
{
    bool all = false;
    bool include_unsupported = false;
    bool probe_stats = false;
    bool show_help = false;
    bool list_switches = false;
    bool server_mode = false;
    bool allow_clear = false;
    std::string object_filter;
    std::string client_config;
    std::string context_config;
    std::string server_config;
    const char *switch_vid = nullptr;
    uint64_t response_timeout_ms = 0; /* 0 = library default */
};

/* ------------------------------------------------------------------ */
/* attribute value buffers                                             */
/* ------------------------------------------------------------------ */

struct AttributeStorage
{
    std::vector<sai_object_id_t> object_ids;
    std::vector<uint8_t> u8_values;
    std::vector<int8_t> s8_values;
    std::vector<uint16_t> u16_values;
    std::vector<int16_t> s16_values;
    std::vector<uint32_t> u32_values;
    std::vector<int32_t> s32_values;
    std::vector<sai_u16_range_t> u16_ranges;
    std::vector<sai_vlan_id_t> vlans;
    std::vector<sai_qos_map_t> qos_maps;
    std::vector<sai_acl_resource_t> acl_resources;
    std::vector<sai_ip_address_t> ip_addresses;
    std::vector<sai_system_port_config_t> system_ports;
    std::vector<sai_ip_prefix_t> ip_prefixes;
    std::vector<sai_acl_chain_t> acl_chains;
    std::vector<sai_map_t> map_entries;
    std::vector<sai_tlv_t> tlv_entries;
    /*
     * sai_segment_list_t stores raw sai_ip6_t entries (uint8_t[16]). A raw
     * array cannot be a std::vector element type, so store layout-compatible
     * wrappers and reinterpret_cast when handing the buffer to SAI.
     */
    std::vector<std::array<uint8_t, 16>> segments;
};

using AttributeGetter = std::function<sai_status_t(sai_attribute_t *)>;
using StatsGetter = std::function<sai_status_t(
    sai_object_id_t,
    uint32_t,
    const sai_stat_id_t *,
    uint64_t *)>;

/* Extended stats getter: takes an explicit sai_stats_mode_t. */
using StatsExtGetter = std::function<sai_status_t(
    sai_object_id_t,
    uint32_t,
    const sai_stat_id_t *,
    sai_stats_mode_t,
    uint64_t *)>;

/* ------------------------------------------------------------------ */
/* status classification                                               */


/*
 * Full human-readable form of a status: name + numeric value.
 */
std::string
format_status(sai_status_t status)
{
    try {
        return sai_serialize_status(status) +
            " (" + std::to_string(status) + ")";
    } catch (const std::exception &) {
        return std::string(status_name(status)) +
            " (" + std::to_string(status) + ")";
    }
}

std::string
format_enum_value(
    const sai_enum_metadata_t *metadata,
    int32_t value)
{
    const char *name =
        metadata == nullptr
            ? nullptr
            : sai_metadata_get_enum_value_name(metadata, value);

    char numeric[64];
    std::snprintf(
        numeric,
        sizeof(numeric),
        "%d/0x%08" PRIx32,
        value,
        static_cast<uint32_t>(value));

    if (name != nullptr) {
        return std::string(name) + " (" + numeric + ")";
    }
    return classify_unknown_value(value) + " (" + numeric + ")";
}

std::string
format_object_tags(const sai_object_type_info_t *info)
{
    std::string result;
    if (info->isexperimental) {
        result += " experimental/extension";
    }
    if (info->iscustom) {
        result += " vendor-custom";
    }
    return result;
}

std::string
format_attribute_tags(const sai_attr_metadata_t *metadata)
{
    std::string result;
    if (metadata->isextensionattr) {
        result += " extension";
    }
    if (metadata->iscustom) {
        result += " vendor-custom";
    }
    if (metadata->isdeprecated) {
        result += " deprecated";
    }
    if (metadata->nextrelease) {
        result += " next-release";
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* attribute buffer binding                                            */
/* ------------------------------------------------------------------ */

uint32_t
get_buffer_count(
    sai_attr_value_type_t type,
    const sai_attribute_t &attribute)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
            return attribute.value.objlist.count;
        case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
            return attribute.value.u8list.count;
        case SAI_ATTR_VALUE_TYPE_INT8_LIST:
            return attribute.value.s8list.count;
        case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
            return attribute.value.u16list.count;
        case SAI_ATTR_VALUE_TYPE_INT16_LIST:
            return attribute.value.s16list.count;
        case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
            return attribute.value.u32list.count;
        case SAI_ATTR_VALUE_TYPE_INT32_LIST:
            return attribute.value.s32list.count;
        case SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
            return attribute.value.u16rangelist.count;
        case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
            return attribute.value.vlanlist.count;
        case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
            return attribute.value.qosmap.count;
        case SAI_ATTR_VALUE_TYPE_MAP_LIST:
            return attribute.value.maplist.count;
        case SAI_ATTR_VALUE_TYPE_TLV_LIST:
            return attribute.value.tlvlist.count;
        case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
            return attribute.value.segmentlist.count;
        case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
            return attribute.value.aclcapability.action_list.count;
        case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
            return attribute.value.aclresource.count;
        case SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
            return attribute.value.ipaddrlist.count;
        case SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
            return attribute.value.sysportconfiglist.count;
        case SAI_ATTR_VALUE_TYPE_JSON:
            return attribute.value.json.json.count;
        case SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
            return attribute.value.ipprefixlist.count;
        case SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
            return attribute.value.aclchainlist.count;
        default:
            return 0;
    }
}

bool
bind_attribute_buffer(
    sai_attr_value_type_t type,
    uint32_t count,
    sai_attribute_t &attribute,
    AttributeStorage &storage)
{
    if (count > kMaximumListCapacity) {
        return false;
    }

    switch (type) {
        case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
            storage.object_ids.resize(count);
            attribute.value.objlist = {
                count,
                storage.object_ids.empty()
                    ? nullptr
                    : storage.object_ids.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
            storage.u8_values.resize(count);
            attribute.value.u8list = {
                count,
                storage.u8_values.empty()
                    ? nullptr
                    : storage.u8_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_INT8_LIST:
            storage.s8_values.resize(count);
            attribute.value.s8list = {
                count,
                storage.s8_values.empty()
                    ? nullptr
                    : storage.s8_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
            storage.u16_values.resize(count);
            attribute.value.u16list = {
                count,
                storage.u16_values.empty()
                    ? nullptr
                    : storage.u16_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_INT16_LIST:
            storage.s16_values.resize(count);
            attribute.value.s16list = {
                count,
                storage.s16_values.empty()
                    ? nullptr
                    : storage.s16_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
            storage.u32_values.resize(count);
            attribute.value.u32list = {
                count,
                storage.u32_values.empty()
                    ? nullptr
                    : storage.u32_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_INT32_LIST:
            storage.s32_values.resize(count);
            attribute.value.s32list = {
                count,
                storage.s32_values.empty()
                    ? nullptr
                    : storage.s32_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
            storage.u16_ranges.resize(count);
            attribute.value.u16rangelist = {
                count,
                storage.u16_ranges.empty()
                    ? nullptr
                    : storage.u16_ranges.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
            storage.vlans.resize(count);
            attribute.value.vlanlist = {
                count,
                storage.vlans.empty()
                    ? nullptr
                    : storage.vlans.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
            storage.qos_maps.resize(count);
            attribute.value.qosmap = {
                count,
                storage.qos_maps.empty()
                    ? nullptr
                    : storage.qos_maps.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_MAP_LIST:
            storage.map_entries.resize(count);
            attribute.value.maplist = {
                count,
                storage.map_entries.empty()
                    ? nullptr
                    : storage.map_entries.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_TLV_LIST:
            storage.tlv_entries.resize(count);
            attribute.value.tlvlist = {
                count,
                storage.tlv_entries.empty()
                    ? nullptr
                    : storage.tlv_entries.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
            storage.segments.resize(count);
            attribute.value.segmentlist = {
                count,
                storage.segments.empty()
                    ? nullptr
                    : reinterpret_cast<sai_ip6_t *>(
                          storage.segments.data())};
            return true;
        case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
            storage.s32_values.resize(count);
            attribute.value.aclcapability.action_list = {
                count,
                storage.s32_values.empty()
                    ? nullptr
                    : storage.s32_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
            storage.acl_resources.resize(count);
            attribute.value.aclresource = {
                count,
                storage.acl_resources.empty()
                    ? nullptr
                    : storage.acl_resources.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
            storage.ip_addresses.resize(count);
            attribute.value.ipaddrlist = {
                count,
                storage.ip_addresses.empty()
                    ? nullptr
                    : storage.ip_addresses.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
            storage.system_ports.resize(count);
            attribute.value.sysportconfiglist = {
                count,
                storage.system_ports.empty()
                    ? nullptr
                    : storage.system_ports.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_JSON:
            storage.s8_values.resize(count);
            attribute.value.json.json = {
                count,
                storage.s8_values.empty()
                    ? nullptr
                    : storage.s8_values.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
            storage.ip_prefixes.resize(count);
            attribute.value.ipprefixlist = {
                count,
                storage.ip_prefixes.empty()
                    ? nullptr
                    : storage.ip_prefixes.data()};
            return true;
        case SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
            storage.acl_chains.resize(count);
            attribute.value.aclchainlist = {
                count,
                storage.acl_chains.empty()
                    ? nullptr
                    : storage.acl_chains.data()};
            return true;

        default:
            return false;
    }
}

size_t
current_buffer_capacity(
    sai_attr_value_type_t type,
    const AttributeStorage &storage)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
            return storage.object_ids.size();
        case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
            return storage.u8_values.size();
        case SAI_ATTR_VALUE_TYPE_INT8_LIST:
        case SAI_ATTR_VALUE_TYPE_JSON:
            return storage.s8_values.size();
        case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
            return storage.u16_values.size();
        case SAI_ATTR_VALUE_TYPE_INT16_LIST:
            return storage.s16_values.size();
        case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
            return storage.u32_values.size();
        case SAI_ATTR_VALUE_TYPE_INT32_LIST:
        case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
            return storage.s32_values.size();
        case SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
            return storage.u16_ranges.size();
        case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
            return storage.vlans.size();
        case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
            return storage.qos_maps.size();
        case SAI_ATTR_VALUE_TYPE_MAP_LIST:
            return storage.map_entries.size();
        case SAI_ATTR_VALUE_TYPE_TLV_LIST:
            return storage.tlv_entries.size();
        case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
            return storage.segments.size();
        case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
            return storage.acl_resources.size();
        case SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
            return storage.ip_addresses.size();
        case SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
            return storage.system_ports.size();
        case SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
            return storage.ip_prefixes.size();
        case SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
            return storage.acl_chains.size();
        default:
            return 0;
    }
}

struct FetchOutcome
{
    FetchKind result = FetchKind::Failure;
    sai_status_t status = SAI_STATUS_FAILURE;
    std::string detail;
};

FetchOutcome
fetch_attribute(
    const sai_attr_metadata_t *metadata,
    const AttributeGetter &getter,
    sai_attribute_t &attribute,
    AttributeStorage &storage)
{
    FetchOutcome outcome;

    attribute = {};
    attribute.id = metadata->attrid;

    if (!can_fetch_value_type(metadata->attrvaluetype)) {
        outcome.result = FetchKind::Skipped;
        outcome.detail = "value type cannot be probed generically";
        return outcome;
    }

    if (is_buffered_value_type(metadata->attrvaluetype) &&
        !bind_attribute_buffer(
            metadata->attrvaluetype,
            kInitialListCapacity,
            attribute,
            storage)) {
        outcome.result = FetchKind::Skipped;
        outcome.detail = "unable to allocate initial list buffer";
        return outcome;
    }

    sai_status_t status = SAI_STATUS_FAILURE;
    try {
        status = getter(&attribute);
    } catch (const std::exception &exception) {
        outcome.status = SAI_STATUS_FAILURE;
        outcome.detail = std::string("SAI call threw: ") + exception.what();
        return outcome;
    }

    /*
     * Some adapters report the required size in the count field while others
     * do not touch it. Grow to whichever is larger and retry a bounded number
     * of times.
     */
    for (unsigned int attempt = 0;
         status == SAI_STATUS_BUFFER_OVERFLOW && attempt < 4;
         ++attempt) {
        uint32_t required = get_buffer_count(
            metadata->attrvaluetype, attribute);
        const size_t current =
            current_buffer_capacity(metadata->attrvaluetype, storage);

        if (current == 0) {
            outcome.detail = "BUFFER_OVERFLOW on a non-list value";
            outcome.status = status;
            return outcome;
        }

        if (required <= current) {
            required =
                current > kMaximumListCapacity / 2
                    ? kMaximumListCapacity + 1
                    : static_cast<uint32_t>(current * 2);
        }

        if (!bind_attribute_buffer(
                metadata->attrvaluetype,
                required,
                attribute,
                storage)) {
            outcome.detail =
                "reported list size " + std::to_string(required) +
                " exceeds safety limit";
            outcome.status = SAI_STATUS_NO_MEMORY;
            return outcome;
        }

        try {
            status = getter(&attribute);
        } catch (const std::exception &exception) {
            outcome.status = SAI_STATUS_FAILURE;
            outcome.detail =
                std::string("SAI call threw: ") + exception.what();
            return outcome;
        }
    }

    outcome.status = status;
    outcome.result =
        status == SAI_STATUS_SUCCESS
            ? FetchKind::Ok
            : FetchKind::Failure;
    return outcome;
}

std::string
serialize_attribute(
    const sai_attr_metadata_t *metadata,
    const sai_attribute_t &attribute)
{
    try {
        std::string value =
            sai_serialize_attr_value(*metadata, attribute, false);

        constexpr size_t kDisplayLimit = 4096;
        if (value.size() > kDisplayLimit) {
            value.resize(kDisplayLimit);
            value += "...<truncated>";
        }
        return value;
    } catch (const std::exception &exception) {
        return std::string("<serialization failed: ") +
            exception.what() + ">";
    }
}

const sai_attr_metadata_t *
find_attribute(const char *name)
{
    return sai_metadata_get_attr_metadata_by_attr_id_name(name);
}

void
print_metadata_inventory()
{
    size_t standard = 0;
    size_t experimental = 0;
    size_t custom = 0;
    size_t extension_attributes = 0;
    size_t custom_attributes = 0;

    for (size_t index = 1;
         sai_metadata_all_object_type_infos[index] != nullptr;
         ++index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[index];

        if (info->isexperimental) {
            ++experimental;
        } else if (info->iscustom) {
            ++custom;
        } else {
            ++standard;
        }

        for (size_t attribute_index = 0;
             info->attrmetadata[attribute_index] != nullptr;
             ++attribute_index) {
            const sai_attr_metadata_t *metadata =
                info->attrmetadata[attribute_index];
            extension_attributes += metadata->isextensionattr ? 1 : 0;
            custom_attributes += metadata->iscustom ? 1 : 0;
        }
    }

    std::printf(
        "Metadata inventory: standard_objects=%zu "
        "experimental_extension_objects=%zu vendor_custom_objects=%zu "
        "extension_attrs=%zu vendor_custom_attrs=%zu\n",
        standard,
        experimental,
        custom,
        extension_attributes,
        custom_attributes);
}

/* ------------------------------------------------------------------ */
/* status summary accumulation                                         */
/* ------------------------------------------------------------------ */

struct OutcomeSummary
{
    size_t ok = 0;
    size_t skipped = 0;
    std::map<std::string, size_t> failures;

    void add(const FetchOutcome &outcome)
    {
        const std::string bucket =
            summary_bucket(outcome.result, outcome.status);
        if (bucket == "ok") {
            ++ok;
        } else if (bucket == "skipped_by_tool") {
            ++skipped;
        } else {
            ++failures[bucket];
        }
    }

    void print(const char *indent = "  ") const
    {
        if (ok == 0 && skipped == 0 && failures.empty()) {
            return;
        }
        std::printf("%ssummary: ok=%zu", indent, ok);
        if (skipped != 0) {
            std::printf(" skipped_by_tool=%zu", skipped);
        }
        for (const auto &entry : failures) {
            std::printf(" %s=%zu", entry.first.c_str(), entry.second);
        }
        std::printf("\n");
    }
};

/* ------------------------------------------------------------------ */
/* authoritative supported object type list                            */
/* ------------------------------------------------------------------ */

struct SupportedObjectTypes
{
    bool authoritative = false;
    std::set<int32_t> types;

    bool is_supported(sai_object_type_t type) const
    {
        return types.find(static_cast<int32_t>(type)) != types.end();
    }

    const char *
    verdict(sai_object_type_t type) const
    {
        if (!authoritative) {
            return "unknown (adapter did not expose the list)";
        }
        return is_supported(type)
            ? "asic_supported"
            : "asic_unsupported (not in SUPPORTED_OBJECT_TYPE_LIST)";
    }
};

SupportedObjectTypes
query_supported_object_types(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api)
{
    SupportedObjectTypes supported;
    const sai_attr_metadata_t *metadata =
        find_attribute("SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST");

    std::printf("\n=== Supported object types ===\n");

    if (metadata == nullptr) {
        std::printf("Metadata does not contain SUPPORTED_OBJECT_TYPE_LIST\n");
        return supported;
    }

    sai_attribute_t attribute{};
    AttributeStorage storage;
    const FetchOutcome outcome = fetch_attribute(
        metadata,
        [switch_api, switch_id](sai_attribute_t *value) {
            return switch_api->get_switch_attribute(
                switch_id,
                1,
                value);
        },
        attribute,
        storage);

    std::printf("status=%s", format_status(outcome.status).c_str());
    if (!outcome.detail.empty()) {
        std::printf(" detail=%s", outcome.detail.c_str());
    }
    std::printf("\n");

    if (outcome.result != FetchKind::Ok) {
        std::printf(
            "The adapter did not expose an authoritative object list; "
            "object type verdicts will be reported as unknown.\n");
        return supported;
    }

    supported.authoritative = true;
    for (uint32_t index = 0; index < attribute.value.s32list.count; ++index) {
        supported.types.insert(attribute.value.s32list.list[index]);
    }

    size_t position = 0;
    for (int32_t raw : supported.types) {
        const sai_object_type_info_t *info =
            sai_metadata_get_object_type_info(
                static_cast<sai_object_type_t>(raw));

        if (info != nullptr) {
            std::printf(
                "  [%zu] %s (%d/0x%08" PRIx32 ")%s\n",
                position++,
                info->objecttypename,
                raw,
                static_cast<uint32_t>(raw),
                format_object_tags(info).c_str());
        } else {
            std::printf(
                "  [%zu] %s (%d/0x%08" PRIx32 ")\n",
                position++,
                classify_unknown_value(raw).c_str(),
                raw,
                static_cast<uint32_t>(raw));
        }
    }

    return supported;
}

/* ------------------------------------------------------------------ */
/* switch attribute sections                                           */
/* ------------------------------------------------------------------ */

void
show_switch_attributes(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    const std::vector<const sai_attr_metadata_t *> &attributes,
    bool include_failures)
{
    OutcomeSummary summary;

    for (const sai_attr_metadata_t *metadata : attributes) {
        if (metadata == nullptr) {
            continue;
        }

        sai_attribute_t attribute{};
        AttributeStorage storage;
        const FetchOutcome outcome = fetch_attribute(
            metadata,
            [switch_api, switch_id](sai_attribute_t *value) {
                return switch_api->get_switch_attribute(
                    switch_id,
                    1,
                    value);
            },
            attribute,
            storage);

        if (outcome.result == FetchKind::Ok) {
            std::printf(
                "%-68s value=%s%s\n",
                metadata->attridname,
                serialize_attribute(metadata, attribute).c_str(),
                format_attribute_tags(metadata).c_str());
        } else if (include_failures) {
            std::printf(
                "%-68s result=%s status=%s",
                metadata->attridname,
                outcome.result == FetchKind::Skipped
                    ? "skipped_by_tool"
                    : "failure",
                format_status(outcome.status).c_str());
            if (!outcome.detail.empty()) {
                std::printf(" detail=%s", outcome.detail.c_str());
            }
            std::printf("%s\n", format_attribute_tags(metadata).c_str());
        }

        summary.add(outcome);
    }

    summary.print();
}

std::vector<const sai_attr_metadata_t *>
metadata_for_names(const char *const *names, size_t count)
{
    std::vector<const sai_attr_metadata_t *> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        result.push_back(find_attribute(names[index]));
    }
    return result;
}

void
show_switch_summary(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    bool include_failures)
{
    static const char *const names[] = {
        "SAI_SWITCH_ATTR_TYPE",
        "SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS",
        "SAI_SWITCH_ATTR_MAX_NUMBER_OF_SUPPORTED_PORTS",
        "SAI_SWITCH_ATTR_PORT_MAX_MTU",
        "SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS",
        "SAI_SWITCH_ATTR_FDB_TABLE_SIZE",
        "SAI_SWITCH_ATTR_L3_NEIGHBOR_TABLE_SIZE",
        "SAI_SWITCH_ATTR_L3_ROUTE_TABLE_SIZE",
        "SAI_SWITCH_ATTR_LAG_MEMBERS",
        "SAI_SWITCH_ATTR_NUMBER_OF_LAGS",
        "SAI_SWITCH_ATTR_ECMP_MEMBERS",
        "SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS",
        "SAI_SWITCH_ATTR_MAX_ECMP_MEMBER_COUNT",
        "SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES",
        "SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES",
        "SAI_SWITCH_ATTR_NUMBER_OF_QUEUES",
        "SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES",
        "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_TRAFFIC_CLASSES",
        "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUP_HIERARCHY_LEVELS",
        "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_PER_SCHEDULER_GROUP",
        "SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE",
        "SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM",
        "SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM",
        "SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT",
        "SAI_SWITCH_ATTR_MAX_ACL_RANGE_COUNT",
        "SAI_SWITCH_ATTR_MAX_MIRROR_SESSION",
        "SAI_SWITCH_ATTR_MAX_SAMPLED_MIRROR_SESSION",
        "SAI_SWITCH_ATTR_MAX_BFD_SESSION",
        "SAI_SWITCH_ATTR_MAX_NUMBER_OF_FORWARDING_CLASSES",
        "SAI_SWITCH_ATTR_MAX_TWAMP_SESSION",
        "SAI_SWITCH_ATTR_MAX_ICMP_ECHO_SESSION",
        "SAI_SWITCH_ATTR_SUPPORTED_EXTENDED_STATS_MODE",
        "SAI_SWITCH_ATTR_FIRMWARE_MAJOR_VERSION",
        "SAI_SWITCH_ATTR_FIRMWARE_MINOR_VERSION",
    };

    std::printf("\n=== Switch limits and characteristics ===\n");
    show_switch_attributes(
        switch_id,
        switch_api,
        metadata_for_names(names, sizeof(names) / sizeof(names[0])),
        include_failures);
}

void
show_all_read_only_switch_attributes(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    bool include_failures)
{
    const sai_object_type_info_t *info =
        sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_SWITCH);
    std::vector<const sai_attr_metadata_t *> attributes;

    if (info == nullptr) {
        return;
    }

    for (size_t index = 0;
         info->attrmetadata[index] != nullptr;
         ++index) {
        const sai_attr_metadata_t *metadata = info->attrmetadata[index];
        if (metadata->isreadonly) {
            attributes.push_back(metadata);
        }
    }

    std::printf("\n=== All readable switch attributes ===\n");
    show_switch_attributes(
        switch_id,
        switch_api,
        attributes,
        include_failures);
}

/* ------------------------------------------------------------------ */
/* enum capability                                                     */
/* ------------------------------------------------------------------ */

struct EnumCapabilityResult
{
    sai_status_t status = SAI_STATUS_FAILURE;
    std::vector<int32_t> values;
    uint32_t required_count = 0;
};

EnumCapabilityResult
query_enum_capability(
    sai_object_id_t switch_id,
    const sai_attr_metadata_t *metadata)
{
    EnumCapabilityResult result;

    uint32_t capacity = kInitialListCapacity;
    if (metadata->enummetadata != nullptr) {
        capacity = std::max<uint32_t>(
            capacity,
            static_cast<uint32_t>(
                metadata->enummetadata->valuescount + 16));
    }

    for (unsigned int attempt = 0; attempt < 5; ++attempt) {
        result.values.assign(capacity, 0);

        sai_s32_list_t values{};
        values.count = capacity;
        values.list = result.values.data();

        try {
            result.status =
                sai_query_attribute_enum_values_capability(
                    switch_id,
                    metadata->objecttype,
                    metadata->attrid,
                    &values);
        } catch (const std::exception &) {
            result.status = SAI_STATUS_FAILURE;
        }
        result.required_count = values.count;

        if (result.status != SAI_STATUS_BUFFER_OVERFLOW) {
            if (result.status == SAI_STATUS_SUCCESS) {
                result.values.resize(
                    std::min<uint32_t>(values.count, capacity));
            } else {
                result.values.clear();
            }
            return result;
        }

        if (values.count <= capacity) {
            if (capacity > kMaximumListCapacity / 2) {
                break;
            }
            capacity *= 2;
        } else {
            capacity = values.count;
        }

        if (capacity > kMaximumListCapacity) {
            break;
        }
    }

    result.values.clear();
    return result;
}

void
print_enum_capability(
    const sai_attr_metadata_t *metadata,
    const EnumCapabilityResult &result,
    const char *indent)
{
    std::printf(
        "%senum status=%s",
        indent,
        format_status(result.status).c_str());

    if (result.status == SAI_STATUS_SUCCESS) {
        /*
         * An enum list attribute holds enum values but is not itself an enum,
         * so sai_metadata_is_allowed_enum_value() must only be used when the
         * attribute is backed by an enum metadata object.
         */
        const bool can_validate = metadata->enummetadata != nullptr;
        std::printf(" count=%zu\n", result.values.size());
        for (size_t index = 0; index < result.values.size(); ++index) {
            const int32_t value = result.values[index];
            const bool known =
                can_validate &&
                sai_metadata_is_allowed_enum_value(metadata, value);
            std::printf(
                "%s  [%zu] %s%s\n",
                indent,
                index,
                format_enum_value(metadata->enummetadata, value).c_str(),
                (can_validate && !known)
                    ? " <not in local metadata>"
                    : "");
        }
    } else if (result.status == SAI_STATUS_BUFFER_OVERFLOW) {
        std::printf(" required_count=%u\n", result.required_count);
    } else {
        std::printf("\n");
    }
}

sai_status_t
show_attribute_capability(
    sai_object_id_t switch_id,
    const sai_attr_metadata_t *metadata,
    bool include_enum_failure)
{
    sai_attr_capability_t capability{};
    sai_status_t status = SAI_STATUS_FAILURE;

    try {
        status = sai_query_attribute_capability(
            switch_id,
            metadata->objecttype,
            metadata->attrid,
            &capability);
    } catch (const std::exception &exception) {
        std::printf(
            "%-66s status=threw detail=%s\n",
            metadata->attridname,
            exception.what());
        return SAI_STATUS_FAILURE;
    }

    std::printf(
        "%-66s status=%s",
        metadata->attridname,
        format_status(status).c_str());

    if (status == SAI_STATUS_SUCCESS) {
        std::printf(
            " create=%s set=%s get=%s",
            capability.create_implemented ? "yes" : "no",
            capability.set_implemented ? "yes" : "no",
            capability.get_implemented ? "yes" : "no");
    }

    std::printf("%s\n", format_attribute_tags(metadata).c_str());

    if ((metadata->isenum || metadata->isenumlist) &&
        (status == SAI_STATUS_SUCCESS || include_enum_failure)) {
        const EnumCapabilityResult enum_result =
            query_enum_capability(switch_id, metadata);
        if (enum_result.status == SAI_STATUS_SUCCESS ||
            include_enum_failure) {
            print_enum_capability(metadata, enum_result, "    ");
        }
    }

    return status;
}

void
show_focused_capabilities(sai_object_id_t switch_id)
{
    static const char *const names[] = {
        "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL",
        "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE",
        "SAI_PORT_ATTR_AUTO_NEG_MODE",
        "SAI_PORT_ATTR_FEC_MODE",
        "SAI_PORT_ATTR_MEDIA_TYPE",
        "SAI_PORT_ATTR_INTERFACE_TYPE",
        "SAI_NEXT_HOP_ATTR_TYPE",
        "SAI_NEXT_HOP_GROUP_ATTR_TYPE",
        "SAI_NEXT_HOP_GROUP_ATTR_HIERARCHICAL_NEXTHOP",
        "SAI_NEXT_HOP_GROUP_ATTR_ARS_OBJECT_ID",
        "SAI_ROUTER_INTERFACE_ATTR_TYPE",
        "SAI_TUNNEL_ATTR_TYPE",
        "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE",
        "SAI_WRED_ATTR_ECN_MARK_MODE",
        "SAI_QOS_MAP_ATTR_TYPE",
        "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE",
        "SAI_MIRROR_SESSION_ATTR_TYPE",
        "SAI_SAMPLEPACKET_ATTR_TYPE",
        "SAI_ACL_TABLE_ATTR_STAGE",
        "SAI_DEBUG_COUNTER_ATTR_TYPE",
        "SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST",
        "SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST",
    };

    std::printf("\n=== Focused attribute and enum capabilities ===\n");
    std::printf(
        "NOTE: these are adapter DECLARATIONS. A 'yes' here is not proof the\n"
        "      ASIC accepted the attribute; use the live sections or --probe-stats\n"
        "      to cross-check.\n");

    for (const char *name : names) {
        const sai_attr_metadata_t *metadata = find_attribute(name);
        if (metadata == nullptr) {
            std::printf("%-66s metadata=missing\n", name);
            continue;
        }
        show_attribute_capability(switch_id, metadata, true);
    }
}

void
show_all_attribute_capabilities(
    sai_object_id_t switch_id,
    const SupportedObjectTypes &supported,
    const std::string &object_filter,
    bool include_unsupported)
{
    OutcomeSummary summary;
    size_t queried = 0;
    size_t matched_objects = 0;

    std::printf("\n=== Full attribute capability scan ===\n");
    std::printf(
        "NOTE: sairedis forwards these to the adapter; many vendors answer\n"
        "      without touching hardware, so treat them as declarations.\n");

    for (size_t object_index = 1;
         sai_metadata_all_object_type_infos[object_index] != nullptr;
         ++object_index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[object_index];

        if (!matches_object_filter(info, object_filter)) {
            continue;
        }

        /*
         * When the adapter published an authoritative object list and this
         * type is absent from it, do not spend round trips asking. The verdict
         * is recorded so the report cannot silently imply support.
         */
        if (supported.authoritative &&
            !supported.is_supported(info->objecttype)) {
            std::printf(
                "\n[%s%s] verdict=%s (capability queries skipped)\n",
                info->objecttypename,
                format_object_tags(info).c_str(),
                supported.verdict(info->objecttype));
            continue;
        }

        ++matched_objects;
        bool printed_header = false;

        for (size_t attribute_index = 0;
             info->attrmetadata[attribute_index] != nullptr;
             ++attribute_index) {
            const sai_attr_metadata_t *metadata =
                info->attrmetadata[attribute_index];
            sai_attr_capability_t capability{};
            sai_status_t status = SAI_STATUS_FAILURE;

            try {
                status = sai_query_attribute_capability(
                    switch_id,
                    metadata->objecttype,
                    metadata->attrid,
                    &capability);
            } catch (const std::exception &) {
                status = SAI_STATUS_FAILURE;
            }

            ++queried;
            if (status != SAI_STATUS_SUCCESS && !include_unsupported) {
                summary.failures[classify_status(status)]++;
                continue;
            }

            if (!printed_header) {
                std::printf(
                    "\n[%s%s]\n",
                    info->objecttypename,
                    format_object_tags(info).c_str());
                printed_header = true;
            }

            std::printf(
                "  %-64s status=%s",
                metadata->attridname,
                format_status(status).c_str());

            if (status == SAI_STATUS_SUCCESS) {
                std::printf(
                    " create=%s set=%s get=%s",
                    capability.create_implemented ? "yes" : "no",
                    capability.set_implemented ? "yes" : "no",
                    capability.get_implemented ? "yes" : "no");
                ++summary.ok;
            } else {
                summary.failures[classify_status(status)]++;
            }

            std::printf("%s\n", format_attribute_tags(metadata).c_str());

            if ((metadata->isenum || metadata->isenumlist) &&
                status == SAI_STATUS_SUCCESS &&
                (capability.create_implemented ||
                 capability.set_implemented ||
                 capability.get_implemented)) {
                const EnumCapabilityResult enum_result =
                    query_enum_capability(switch_id, metadata);
                if (enum_result.status == SAI_STATUS_SUCCESS ||
                    include_unsupported) {
                    print_enum_capability(
                        metadata,
                        enum_result,
                        "    ");
                }
            }
        }
    }

    if (matched_objects == 0 && object_filter.empty()) {
        std::printf(
            "No object type was queried (all filtered by the authoritative "
            "supported list).\n");
    } else if (matched_objects == 0) {
        std::printf(
            "No metadata object type matched filter '%s'\n",
            object_filter.c_str());
    }

    std::printf(
        "\nAttribute scan summary: objects=%zu attributes=%zu",
        matched_objects,
        queried);
    for (const auto &entry : summary.failures) {
        std::printf(" %s=%zu", entry.first.c_str(), entry.second);
    }
    std::printf("\n");
}

/* ------------------------------------------------------------------ */
/* stats capability                                                    */
/* ------------------------------------------------------------------ */

struct StatsCapabilityResult
{
    sai_status_t status = SAI_STATUS_FAILURE;
    std::vector<sai_stat_capability_t> values;
    uint32_t required_count = 0;
};

StatsCapabilityResult
query_stats_capability(
    sai_object_id_t switch_id,
    const sai_object_type_info_t *info)
{
    StatsCapabilityResult result;
    uint32_t capacity = std::max<uint32_t>(
        kInitialListCapacity,
        static_cast<uint32_t>(
            info->statenum == nullptr
                ? kInitialListCapacity
                : info->statenum->valuescount + 16));

    for (unsigned int attempt = 0; attempt < 5; ++attempt) {
        result.values.assign(capacity, {});

        sai_stat_capability_list_t list{};
        list.count = capacity;
        list.list = result.values.data();

        try {
            result.status = sai_query_stats_capability(
                switch_id,
                info->objecttype,
                &list);
        } catch (const std::exception &) {
            result.status = SAI_STATUS_FAILURE;
        }
        result.required_count = list.count;

        if (result.status != SAI_STATUS_BUFFER_OVERFLOW) {
            if (result.status == SAI_STATUS_SUCCESS) {
                result.values.resize(
                    std::min<uint32_t>(list.count, capacity));
            } else {
                result.values.clear();
            }
            return result;
        }

        if (list.count <= capacity) {
            if (capacity > kMaximumListCapacity / 2) {
                break;
            }
            capacity *= 2;
        } else {
            capacity = list.count;
        }

        if (capacity > kMaximumListCapacity) {
            break;
        }
    }

    result.values.clear();
    return result;
}

void
print_stats_capability(
    const sai_object_type_info_t *info,
    const StatsCapabilityResult &result)
{
    std::printf(
        "%s statistics: status=%s",
        info->objecttypename,
        format_status(result.status).c_str());

    if (result.status == SAI_STATUS_SUCCESS) {
        std::printf(" count=%zu\n", result.values.size());
        for (const auto &value : result.values) {
            std::printf(
                "  %s modes=0x%x (%s)\n",
                format_enum_value(
                    info->statenum,
                    value.stat_enum).c_str(),
                value.stat_modes,
                format_stats_modes(value.stat_modes).c_str());
        }
    } else if (result.status == SAI_STATUS_BUFFER_OVERFLOW) {
        std::printf(" required_count=%u\n", result.required_count);
    } else {
        std::printf("\n");
    }
}

/*
 * Stream-telemetry statistics capability.
 *
 * Unlike sai_query_stats_capability, this reports the minimal polling interval
 * each counter can sustain. It is a newer API, so NOT_IMPLEMENTED /
 * NOT_SUPPORTED is an expected and legitimate answer rather than an error.
 */
struct StatsStCapabilityResult
{
    sai_status_t status = SAI_STATUS_FAILURE;
    std::vector<sai_stat_st_capability_t> values;
    uint32_t required_count = 0;
};

StatsStCapabilityResult
query_stats_st_capability(
    sai_object_id_t switch_id,
    const sai_object_type_info_t *info)
{
    StatsStCapabilityResult result;
    uint32_t capacity = std::max<uint32_t>(
        kInitialListCapacity,
        static_cast<uint32_t>(
            info->statenum == nullptr
                ? kInitialListCapacity
                : info->statenum->valuescount + 16));

    for (unsigned int attempt = 0; attempt < 5; ++attempt) {
        result.values.assign(capacity, {});

        sai_stat_st_capability_list_t list{};
        list.count = capacity;
        list.list = result.values.data();

        try {
            result.status = sai_query_stats_st_capability(
                switch_id,
                info->objecttype,
                &list);
        } catch (const std::exception &) {
            result.status = SAI_STATUS_FAILURE;
        }
        result.required_count = list.count;

        if (result.status != SAI_STATUS_BUFFER_OVERFLOW) {
            if (result.status == SAI_STATUS_SUCCESS) {
                result.values.resize(
                    std::min<uint32_t>(list.count, capacity));
            } else {
                result.values.clear();
            }
            return result;
        }

        if (list.count <= capacity) {
            if (capacity > kMaximumListCapacity / 2) {
                break;
            }
            capacity *= 2;
        } else {
            capacity = list.count;
        }

        if (capacity > kMaximumListCapacity) {
            break;
        }
    }

    result.values.clear();
    return result;
}

void
print_stats_st_capability(
    const sai_object_type_info_t *info,
    const StatsStCapabilityResult &result)
{
    std::printf(
        "%s stream-telemetry stats: status=%s",
        info->objecttypename,
        format_status(result.status).c_str());

    if (result.status == SAI_STATUS_SUCCESS) {
        std::printf(" count=%zu\n", result.values.size());
        for (const auto &value : result.values) {
            std::printf(
                "  %s modes=0x%x (%s) min_polling_ns=%" PRIu64 "\n",
                format_enum_value(
                    info->statenum,
                    value.capability.stat_enum).c_str(),
                value.capability.stat_modes,
                format_stats_modes(
                    value.capability.stat_modes).c_str(),
                value.minimal_polling_interval);
        }
    } else if (result.status == SAI_STATUS_BUFFER_OVERFLOW) {
        std::printf(" required_count=%u\n", result.required_count);
    } else {
        std::printf("\n");
    }
}

/*
 * Cached per-object-type statistics capability, used both for the report and
 * to cross-check the live probe. Querying once avoids doubling the number of
 * round trips during a scan.
 */
class StatsCapabilityCache
{
    public:
        explicit StatsCapabilityCache(sai_object_id_t switch_id)
            : m_switch_id(switch_id)
        {
        }

        const StatsCapabilityResult &
        get(const sai_object_type_info_t *info)
        {
            auto it = m_cache.find(info->objecttype);
            if (it != m_cache.end()) {
                return it->second;
            }
            auto inserted = m_cache.emplace(
                info->objecttype,
                query_stats_capability(m_switch_id, info));
            return inserted.first->second;
        }

    private:
        sai_object_id_t m_switch_id;
        std::map<sai_object_type_t, StatsCapabilityResult> m_cache;
};

void
show_stats_capabilities(
    const SupportedObjectTypes &supported,
    StatsCapabilityCache &cache,
    bool all,
    const std::string &object_filter,
    bool include_unsupported)
{
    static const sai_object_type_t focused_types[] = {
        SAI_OBJECT_TYPE_PORT,
        SAI_OBJECT_TYPE_QUEUE,
        SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
        SAI_OBJECT_TYPE_ROUTER_INTERFACE,
        SAI_OBJECT_TYPE_SWITCH,
    };

    std::printf("\n=== Statistics capabilities ===\n");

    if (!all && object_filter.empty()) {
        for (sai_object_type_t type : focused_types) {
            const sai_object_type_info_t *info =
                sai_metadata_get_object_type_info(type);
            if (info != nullptr && info->statenum != nullptr) {
                print_stats_capability(info, cache.get(info));
            }
        }
        return;
    }

    for (size_t index = 1;
         sai_metadata_all_object_type_infos[index] != nullptr;
         ++index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[index];

        if (info->statenum == nullptr ||
            !matches_object_filter(info, object_filter)) {
            continue;
        }

        if (supported.authoritative &&
            !supported.is_supported(info->objecttype)) {
            if (include_unsupported) {
                std::printf(
                    "%-52s verdict=%s (stats query skipped)\n",
                    info->objecttypename,
                    supported.verdict(info->objecttype));
            }
            continue;
        }

        const StatsCapabilityResult &result = cache.get(info);
        if (result.status == SAI_STATUS_SUCCESS ||
            include_unsupported) {
            print_stats_capability(info, result);
        }
    }
}

void
show_stream_telemetry_capabilities(
    sai_object_id_t switch_id,
    const SupportedObjectTypes &supported,
    bool all,
    const std::string &object_filter,
    bool include_unsupported)
{
    static const sai_object_type_t focused_types[] = {
        SAI_OBJECT_TYPE_PORT,
        SAI_OBJECT_TYPE_QUEUE,
        SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
        SAI_OBJECT_TYPE_SWITCH,
    };

    std::printf("\n=== Stream-telemetry statistics capabilities ===\n");
    std::printf(
        "min_polling_ns is the shortest interval the adapter accepts for that\n"
        "counter. NOT_IMPLEMENTED/NOT_SUPPORTED here just means the adapter\n"
        "does not expose the stream-telemetry query.\n");

    auto one = [&](const sai_object_type_info_t *info) {
        const StatsStCapabilityResult result =
            query_stats_st_capability(switch_id, info);
        if (result.status == SAI_STATUS_SUCCESS || include_unsupported) {
            print_stats_st_capability(info, result);
        }
    };

    if (!all && object_filter.empty()) {
        for (sai_object_type_t type : focused_types) {
            const sai_object_type_info_t *info =
                sai_metadata_get_object_type_info(type);
            if (info != nullptr && info->statenum != nullptr) {
                one(info);
            }
        }
        return;
    }

    for (size_t index = 1;
         sai_metadata_all_object_type_infos[index] != nullptr;
         ++index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[index];
        if (info->statenum == nullptr ||
            !matches_object_filter(info, object_filter)) {
            continue;
        }
        if (supported.authoritative &&
            !supported.is_supported(info->objecttype)) {
            continue;
        }
        one(info);
    }
}

/* ------------------------------------------------------------------ */
/* generic resource availability                                       */
/* ------------------------------------------------------------------ */

void
show_generic_availability(
    sai_object_id_t switch_id,
    const SupportedObjectTypes &supported,
    bool all,
    const std::string &object_filter,
    bool include_unsupported)
{
    static const sai_object_type_t focused_types[] = {
        SAI_OBJECT_TYPE_ROUTE_ENTRY,
        SAI_OBJECT_TYPE_NEXT_HOP,
        SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
        SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
        SAI_OBJECT_TYPE_FDB_ENTRY,
        SAI_OBJECT_TYPE_ACL_ENTRY,
    };

    std::printf("\n=== Generic resource availability ===\n");
    std::printf(
        "NOTE: queried with attr_count=0, so resource variants that need a\n"
        "      discriminator attribute (for example ACL stage) may report\n"
        "      NOT_SUPPORTED even when the ASIC supports the resource.\n");

    auto print_one = [switch_id](
                         const sai_object_type_info_t *info,
                         bool print_failure) {
        uint64_t count = 0;
        sai_status_t status = SAI_STATUS_FAILURE;
        try {
            status = sai_object_type_get_availability(
                switch_id,
                info->objecttype,
                0,
                nullptr,
                &count);
        } catch (const std::exception &) {
            status = SAI_STATUS_FAILURE;
        }

        if (status == SAI_STATUS_SUCCESS) {
            std::printf(
                "%-52s status=%s available=%" PRIu64 "\n",
                info->objecttypename,
                format_status(status).c_str(),
                count);
        } else if (print_failure) {
            std::printf(
                "%-52s status=%s available=n/a\n",
                info->objecttypename,
                format_status(status).c_str());
        }

        return status;
    };

    if (!all && object_filter.empty()) {
        bool all_not_implemented = true;
        for (sai_object_type_t type : focused_types) {
            const sai_object_type_info_t *info =
                sai_metadata_get_object_type_info(type);
            if (info == nullptr) {
                continue;
            }
            const sai_status_t status = print_one(info, true);
            all_not_implemented &=
                (status == SAI_STATUS_NOT_IMPLEMENTED ||
                 status == SAI_STATUS_NOT_SUPPORTED);
        }

        if (all_not_implemented) {
            std::printf(
                "Generic availability is not implemented by this vendor "
                "SAI; use the legacy switch attributes below.\n");
        }
        return;
    }

    for (size_t index = 1;
         sai_metadata_all_object_type_infos[index] != nullptr;
         ++index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[index];
        if (!matches_object_filter(info, object_filter)) {
            continue;
        }
        if (supported.authoritative &&
            !supported.is_supported(info->objecttype) &&
            !include_unsupported) {
            continue;
        }
        print_one(info, include_unsupported);
    }
}

void
show_resource_type_availability(
    sai_object_id_t switch_id,
    const SupportedObjectTypes &supported,
    bool include_unsupported)
{
    std::printf("\n=== Resource availability by discriminator attribute ===\n");
    std::printf(
        "SAI object_type_get_availability accepts a resource-type attribute to\n"
        "distinguish pools (for example ACL stage or next-hop type). This\n"
        "section probes the declared resource-type ENUM attributes with their\n"
        "documented values, which the plain attr_count=0 query cannot reach.\n");

    size_t queried = 0;
    size_t succeeded = 0;

    for (size_t index = 1;
         sai_metadata_all_object_type_infos[index] != nullptr;
         ++index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[index];

        if (supported.authoritative &&
            !supported.is_supported(info->objecttype)) {
            continue;
        }

        for (size_t attribute_index = 0;
             info->attrmetadata[attribute_index] != nullptr;
             ++attribute_index) {
            const sai_attr_metadata_t *metadata =
                info->attrmetadata[attribute_index];

            /* Only enum attributes can be enumerated with known values. */
            if (!metadata->isresourcetype ||
                !metadata->isenum ||
                metadata->enummetadata == nullptr) {
                continue;
            }

            const sai_enum_metadata_t *enum_metadata =
                metadata->enummetadata;

            bool printed_header = false;
            for (size_t value_index = 0;
                 value_index < enum_metadata->valuescount;
                 ++value_index) {
                const int32_t enum_value =
                    enum_metadata->values[value_index];

                sai_attribute_t attribute{};
                attribute.id = metadata->attrid;
                attribute.value.s32 = enum_value;

                uint64_t count = 0;
                sai_status_t status = SAI_STATUS_FAILURE;
                try {
                    status = sai_object_type_get_availability(
                        switch_id,
                        info->objecttype,
                        1,
                        &attribute,
                        &count);
                } catch (const std::exception &) {
                    status = SAI_STATUS_FAILURE;
                }

                ++queried;
                if (status == SAI_STATUS_SUCCESS) {
                    ++succeeded;
                } else if (!include_unsupported) {
                    continue;
                }

                if (!printed_header) {
                    std::printf(
                        "\n[%s] discriminator=%s\n",
                        info->objecttypename,
                        metadata->attridname);
                    printed_header = true;
                }

                if (status == SAI_STATUS_SUCCESS) {
                    std::printf(
                        "  %-56s available=%" PRIu64 "\n",
                        format_enum_value(
                            enum_metadata,
                            enum_value).c_str(),
                        count);
                } else {
                    std::printf(
                        "  %-56s status=%s\n",
                        format_enum_value(
                            enum_metadata,
                            enum_value).c_str(),
                        format_status(status).c_str());
                }
            }
        }
    }

    std::printf(
        "Resource-type availability summary: queried=%zu succeeded=%zu\n",
        queried,
        succeeded);
    if (queried == 0) {
        std::printf(
            "No resource-type enum attributes found in metadata for the "
            "queried object types; nothing to distinguish.\n");
    } else if (succeeded == 0) {
        std::printf(
            "No discriminator query succeeded. This is common: many vendors "
            "only implement attr_count=0 availability.\n");
    }
}

void
show_legacy_resource_attributes(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    bool include_failures)
{
    static const char *const names[] = {
        "SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IP_NEXT_HOP_GROUP_MEMBER_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_L2MC_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_IPMC_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_SNAT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_DNAT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_DOUBLE_NAT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_SNAPT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_DNAPT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_DOUBLE_NAPT_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE",
        "SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP",
        "SAI_SWITCH_ATTR_AVAILABLE_MY_SID_ENTRY",
        "SAI_SWITCH_ATTR_AVAILABLE_MY_MAC_ENTRIES",
        "SAI_SWITCH_ATTR_AVAILABLE_TWAMP_SESSION",
        "SAI_SWITCH_ATTR_AVAILABLE_SYSTEM_VOQS",
        "SAI_SWITCH_ATTR_AVAILABLE_ICMP_ECHO_SESSION",
        "SAI_SWITCH_ATTR_PACKET_AVAILABLE_DMA_MEMORY_POOL_SIZE",
    };

    std::printf("\n=== Legacy switch resource attributes (fallback) ===\n");
    show_switch_attributes(
        switch_id,
        switch_api,
        metadata_for_names(names, sizeof(names) / sizeof(names[0])),
        include_failures);
    std::printf(
        "Note: these are current free counts, not necessarily immutable ASIC "
        "maximums; shared tables may make values interdependent.\n");
}

/* ------------------------------------------------------------------ */
/* live statistics probe                                               */
/* ------------------------------------------------------------------ */

bool
get_object_list(
    const sai_attr_metadata_t *metadata,
    const AttributeGetter &getter,
    std::vector<sai_object_id_t> &objects,
    sai_status_t &status)
{
    if (metadata == nullptr ||
        metadata->attrvaluetype != SAI_ATTR_VALUE_TYPE_OBJECT_LIST) {
        status = SAI_STATUS_INVALID_PARAMETER;
        return false;
    }

    sai_attribute_t attribute{};
    AttributeStorage storage;
    const FetchOutcome outcome =
        fetch_attribute(metadata, getter, attribute, storage);

    status = outcome.status;
    if (outcome.result != FetchKind::Ok) {
        return false;
    }

    objects.assign(
        attribute.value.objlist.list,
        attribute.value.objlist.list + attribute.value.objlist.count);
    return true;
}

/*
 * Look up the declared capability for one stat id. Returns false when the
 * adapter did not report any capability for that stat.
 */
bool
find_declared_stat(
    const StatsCapabilityResult &capability,
    sai_stat_id_t stat,
    uint32_t &modes)
{
    for (const auto &entry : capability.values) {
        if (entry.stat_enum == stat) {
            modes = entry.stat_modes;
            return true;
        }
    }
    return false;
}

void
probe_stats_on_object(
    const sai_object_type_info_t *info,
    sai_object_id_t object_id,
    const StatsCapabilityResult &capability,
    const StatsGetter &getter,
    bool include_failures)
{
    std::map<std::string, size_t> failures;
    size_t success_count = 0;
    size_t contradictions = 0;
    size_t unclaimed = 0;
    bool const capability_known =
        capability.status == SAI_STATUS_SUCCESS;

    std::printf(
        "\n%s read probe on sample object 0x%" PRIx64
        " (success proves READ acceptance on this object only):\n",
        info->objecttypename,
        static_cast<uint64_t>(object_id));

    for (size_t index = 0;
         index < info->statenum->valuescount;
         ++index) {
        const int32_t raw = info->statenum->values[index];
        const char *name = info->statenum->valuesnames[index];

        if (is_stat_marker_name(name)) {
            continue;
        }

        const sai_stat_id_t stat = raw;
        uint64_t value = 0;
        sai_status_t status = SAI_STATUS_FAILURE;
        try {
            status = getter(object_id, 1, &stat, &value);
        } catch (const std::exception &) {
            status = SAI_STATUS_FAILURE;
        }

        const bool probe_ok = status == SAI_STATUS_SUCCESS;

        /*
         * Cross-check the declaration: a counter the adapter said supports
         * READ must actually be readable. This is what turns the capability
         * report from a claim into a verified statement.
         */
        uint32_t declared_modes = 0;
        const bool claimed = capability_known
            ? find_declared_stat(capability, stat, declared_modes)
            : false;
        const bool claimed_read = claimed
            ? (declared_modes & SAI_STATS_MODE_READ) != 0
            : claimed;

        if (capability_known && !claimed) {
            ++unclaimed;
        }

        if (probe_ok) {
            ++success_count;
            std::printf(
                "  %-64s sample_value=%" PRIu64 "\n",
                format_enum_value(info->statenum, raw).c_str(),
                value);
            continue;
        }

        if (capability_known && claimed_read) {
            ++contradictions;
            std::printf(
                "  %-64s CONTRADICTION: declared READ-capable but probe "
                "failed (%s)\n",
                format_enum_value(info->statenum, raw).c_str(),
                format_status(status).c_str());
        } else {
            ++failures[classify_status(status)];
            if (include_failures) {
                std::printf(
                    "  %-64s status=%s\n",
                    format_enum_value(info->statenum, raw).c_str(),
                    format_status(status).c_str());
            }
        }
    }

    std::printf("  probe summary: accepted=%zu", success_count);
    if (capability_known) {
        std::printf(
            " declared=%zu contradictions=%zu unclaimed=%zu",
            capability.values.size(),
            contradictions,
            unclaimed);
    } else {
        std::printf(" capability=unavailable");
    }
    for (const auto &entry : failures) {
        std::printf(" %s=%zu", entry.first.c_str(), entry.second);
    }
    std::printf("\n");
}

/*
 * Validate the declared stat_modes bitmask against real reads.
 *
 * sai_query_stats_capability is a declaration; this asks the adapter to
 * actually perform a read under each mode it claims, so BULK_READ /
 * READ_AND_CLEAR support can be falsified instead of repeated.
 *
 * Only SAI_STATS_MODE_READ is exercised by default. READ_AND_CLEAR mutates
 * counters, so it is only attempted when the caller passes --allow-clear.
 */
void
validate_stats_modes_on_object(
    const sai_object_type_info_t *info,
    sai_object_id_t object_id,
    const StatsCapabilityResult &capability,
    const StatsExtGetter &ext_getter,
    bool allow_clear)
{
    if (capability.status != SAI_STATUS_SUCCESS) {
        std::printf(
            "\n%s stat_modes validation skipped: capability unavailable\n",
            info->objecttypename);
        return;
    }

    std::printf(
        "\n%s stat_modes validation on sample object 0x%" PRIx64
        "%s:\n",
        info->objecttypename,
        static_cast<uint64_t>(object_id),
        allow_clear ? " (clear allowed)" : " (read-only)");

    size_t agree = 0;
    size_t contradictions = 0;
    size_t unverifiable = 0;
    size_t no_mode = 0;

    for (const auto &entry : capability.values) {
        const sai_stat_id_t stat = entry.stat_enum;
        const uint32_t modes = entry.stat_modes;

        const char *stat_name =
            sai_metadata_get_enum_value_name(info->statenum, stat);
        if (is_stat_marker_name(stat_name)) {
            continue;
        }

        const uint32_t mode =
            select_read_only_stats_mode(modes, allow_clear);
        if (mode == 0) {
            ++no_mode;
            continue;
        }

        uint64_t value = 0;
        sai_status_t status = SAI_STATUS_FAILURE;
        try {
            status = ext_getter(
                object_id,
                1,
                &stat,
                static_cast<sai_stats_mode_t>(mode),
                &value);
        } catch (const std::exception &) {
            status = SAI_STATUS_FAILURE;
        }

        const bool probe_ok = status == SAI_STATUS_SUCCESS;
        const bool claimed = true; /* the adapter listed this stat */
        const Agreement agreement =
            compare_capability_with_probe(claimed, probe_ok);

        switch (agreement) {
            case Agreement::Agree:
                ++agree;
                break;
            case Agreement::Contradiction:
                ++contradictions;
                std::printf(
                    "  %-56s %s claimed 0x%x but ext read failed (%s)\n",
                    format_enum_value(info->statenum, stat).c_str(),
                    agreement_name(agreement),
                    modes,
                    format_status(status).c_str());
                break;
            case Agreement::Unverifiable:
                ++unverifiable;
                break;
        }
    }

    std::printf(
        "  modes summary: agree=%zu contradictions=%zu "
        "unverifiable=%zu no_read_mode=%zu\n",
        agree,
        contradictions,
        unverifiable,
        no_mode);
    if (!allow_clear) {
        std::printf(
            "  note: READ_AND_CLEAR/BULK_* modes were not exercised; "
            "pass --allow-clear to test READ_AND_CLEAR (mutates counters).\n");
    }
}

/*
 * Pick a usable front-panel port instead of blindly taking ports.front(),
 * which on SONiC is often a CPU or management port whose queue list is empty.
 */
sai_object_id_t
select_sample_port(const std::vector<sai_object_id_t> &ports)
{
    const sai_attr_metadata_t *type_metadata =
        find_attribute("SAI_PORT_ATTR_TYPE");
    const sai_attr_metadata_t *queue_metadata =
        find_attribute("SAI_PORT_ATTR_QOS_QUEUE_LIST");

    void *api_table = nullptr;
    if (sai_api_query(SAI_API_PORT, &api_table) != SAI_STATUS_SUCCESS ||
        api_table == nullptr) {
        return ports.empty() ? SAI_NULL_OBJECT_ID : ports.front();
    }
    const auto *port_api = static_cast<const sai_port_api_t *>(api_table);

    auto has_queues = [&](sai_object_id_t port) {
        if (queue_metadata == nullptr) {
            return false;
        }
        std::vector<sai_object_id_t> queues;
        sai_status_t status = SAI_STATUS_FAILURE;
        get_object_list(
            queue_metadata,
            [port_api, port](sai_attribute_t *attribute) {
                return port_api->get_port_attribute(port, 1, attribute);
            },
            queues,
            status);
        return !queues.empty();
    };

    for (sai_object_id_t port : ports) {
        if (type_metadata != nullptr) {
            sai_attribute_t attribute{};
            attribute.id = type_metadata->attrid;
            try {
                if (port_api->get_port_attribute(port, 1, &attribute) ==
                        SAI_STATUS_SUCCESS &&
                    attribute.value.s32 != SAI_PORT_TYPE_LOGICAL) {
                    continue;
                }
            } catch (const std::exception &) {
                continue;
            }
        }
        if (has_queues(port)) {
            return port;
        }
    }

    return ports.empty() ? SAI_NULL_OBJECT_ID : ports.front();
}

void
probe_live_stats(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    StatsCapabilityCache &cache,
    bool include_failures,
    bool allow_clear)
{
    std::printf("\n=== Active read-only statistics probe ===\n");
    std::printf(
        "This probe never uses READ_AND_CLEAR, but it performs one SAI "
        "read per metadata-known counter on one sample object per type.\n"
        "Where the adapter declared READ support, a failed read is reported "
        "as a CONTRADICTION.\n");

    std::vector<sai_object_id_t> ports;
    sai_status_t status = SAI_STATUS_FAILURE;
    const sai_attr_metadata_t *port_list_metadata =
        find_attribute("SAI_SWITCH_ATTR_PORT_LIST");

    if (!get_object_list(
            port_list_metadata,
            [switch_api, switch_id](sai_attribute_t *attribute) {
                return switch_api->get_switch_attribute(
                    switch_id,
                    1,
                    attribute);
            },
            ports,
            status) ||
        ports.empty()) {
        std::printf(
            "Cannot obtain a sample port: %s\n",
            format_status(status).c_str());
        return;
    }

    const sai_object_id_t sample_port = select_sample_port(ports);
    if (sample_port == SAI_NULL_OBJECT_ID) {
        std::printf("No usable sample port found\n");
        return;
    }

    void *api_table = nullptr;
    status = sai_api_query(SAI_API_PORT, &api_table);
    if (status != SAI_STATUS_SUCCESS || api_table == nullptr) {
        std::printf(
            "sai_api_query(PORT) failed: %s\n",
            format_status(status).c_str());
        return;
    }
    const auto *port_api = static_cast<const sai_port_api_t *>(api_table);

    const sai_object_type_info_t *port_info =
        sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_PORT);
    if (port_info != nullptr && port_info->statenum != nullptr) {
        probe_stats_on_object(
            port_info,
            sample_port,
            cache.get(port_info),
            [port_api](
                sai_object_id_t object_id,
                uint32_t count,
                const sai_stat_id_t *ids,
                uint64_t *values) {
                return port_api->get_port_stats(
                    object_id, count, ids, values);
            },
            include_failures);

        if (port_api->get_port_stats_ext != nullptr) {
            validate_stats_modes_on_object(
                port_info,
                sample_port,
                cache.get(port_info),
                [port_api](
                    sai_object_id_t object_id,
                    uint32_t count,
                    const sai_stat_id_t *ids,
                    sai_stats_mode_t mode,
                    uint64_t *values) {
                    return port_api->get_port_stats_ext(
                        object_id, count, ids, mode, values);
                },
                allow_clear);
        }
    }

    std::vector<sai_object_id_t> queues;
    const sai_attr_metadata_t *queue_list_metadata =
        find_attribute("SAI_PORT_ATTR_QOS_QUEUE_LIST");
    get_object_list(
        queue_list_metadata,
        [port_api, sample_port](sai_attribute_t *attribute) {
            return port_api->get_port_attribute(
                sample_port, 1, attribute);
        },
        queues,
        status);

    if (!queues.empty()) {
        api_table = nullptr;
        status = sai_api_query(SAI_API_QUEUE, &api_table);
        if (status == SAI_STATUS_SUCCESS && api_table != nullptr) {
            const auto *queue_api =
                static_cast<const sai_queue_api_t *>(api_table);
            const sai_object_type_info_t *queue_info =
                sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_QUEUE);
            if (queue_info != nullptr && queue_info->statenum != nullptr) {
                probe_stats_on_object(
                    queue_info,
                    queues.front(),
                    cache.get(queue_info),
                    [queue_api](
                        sai_object_id_t object_id,
                        uint32_t count,
                        const sai_stat_id_t *ids,
                        uint64_t *values) {
                        return queue_api->get_queue_stats(
                            object_id, count, ids, values);
                    },
                    include_failures);
            }
        }
    } else {
        std::printf(
            "Cannot obtain a sample queue from port 0x%" PRIx64 ": %s\n",
            static_cast<uint64_t>(sample_port),
            format_status(status).c_str());
    }

    std::vector<sai_object_id_t> priority_groups;
    const sai_attr_metadata_t *ipg_list_metadata =
        find_attribute("SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST");
    get_object_list(
        ipg_list_metadata,
        [port_api, sample_port](sai_attribute_t *attribute) {
            return port_api->get_port_attribute(
                sample_port, 1, attribute);
        },
        priority_groups,
        status);

    if (!priority_groups.empty()) {
        api_table = nullptr;
        status = sai_api_query(SAI_API_BUFFER, &api_table);
        if (status == SAI_STATUS_SUCCESS && api_table != nullptr) {
            const auto *buffer_api =
                static_cast<const sai_buffer_api_t *>(api_table);
            const sai_object_type_info_t *ipg_info =
                sai_metadata_get_object_type_info(
                    SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP);
            if (ipg_info != nullptr && ipg_info->statenum != nullptr) {
                probe_stats_on_object(
                    ipg_info,
                    priority_groups.front(),
                    cache.get(ipg_info),
                    [buffer_api](
                        sai_object_id_t object_id,
                        uint32_t count,
                        const sai_stat_id_t *ids,
                        uint64_t *values) {
                        return buffer_api->
                            get_ingress_priority_group_stats(
                                object_id, count, ids, values);
                    },
                    include_failures);
            }
        }
    } else {
        std::printf(
            "Cannot obtain a sample ingress priority group from port "
            "0x%" PRIx64 ": %s\n",
            static_cast<uint64_t>(sample_port),
            format_status(status).c_str());
    }

    /* Switch-level counters, if the adapter exposes them. */
    const sai_object_type_info_t *switch_info =
        sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_SWITCH);
    if (switch_info != nullptr &&
        switch_info->statenum != nullptr &&
        switch_api->get_switch_stats != nullptr) {
        probe_stats_on_object(
            switch_info,
            switch_id,
            cache.get(switch_info),
            [switch_api, switch_id](
                sai_object_id_t object_id,
                uint32_t count,
                const sai_stat_id_t *ids,
                uint64_t *values) {
                return switch_api->get_switch_stats(
                    object_id, count, ids, values);
            },
            include_failures);
    }
}

/* ------------------------------------------------------------------ */
/* service method table / profile                                      */
/* ------------------------------------------------------------------ */

struct ProfileState
{
    Transport transport = Transport::Client;
    Options options;
    bool initialized = false;
};

ProfileState *
profile_state()
{
    static ProfileState state;
    return &state;
}

const char *
profile_get_value(
    sai_switch_profile_id_t profile_id,
    const char *variable)
{
    (void)profile_id;

    if (variable == nullptr) {
        return nullptr;
    }

    ProfileState *state = profile_state();
    const std::string key(variable);

    if (key == SAI_REDIS_KEY_ENABLE_CLIENT) {
        /*
         * Default to CLIENT. Acting as a server makes this tool bind the
         * endpoint syncd already owns and corrupts the shared response queue;
         * that is only acceptable when no syncd is running.
         */
        return state->transport == Transport::Client ? "true" : "false";
    }

    if (key == SAI_REDIS_KEY_CLIENT_CONFIG) {
        return state->options.client_config.empty()
            ? nullptr
            : state->options.client_config.c_str();
    }

    if (key == SAI_REDIS_KEY_CONTEXT_CONFIG) {
        return state->options.context_config.empty()
            ? nullptr
            : state->options.context_config.c_str();
    }

    if (key == SAI_REDIS_KEY_SERVER_CONFIG) {
        return state->options.server_config.empty()
            ? nullptr
            : state->options.server_config.c_str();
    }

    return nullptr;
}

int
profile_get_next_value(
    sai_switch_profile_id_t profile_id,
    const char **variable,
    const char **value)
{
    (void)profile_id;
    (void)variable;
    (void)value;
    return -1;
}

/* ------------------------------------------------------------------ */
/* usage / option parsing                                              */
/* ------------------------------------------------------------------ */

void
print_usage(const char *program)
{
    std::fprintf(
        stderr,
        "Usage: %s [options] <switch-VID-hex>\n"
        "\n"
        "The tool connects to the running syncd as a sairedis CLIENT by\n"
        "default. Use --server only on a box where syncd is stopped.\n"
        "\n"
        "Options:\n"
        "  --all                     Scan every metadata-known object and attribute\n"
        "  --object <name>           Scan object types matching name (for example PORT)\n"
        "  --include-unsupported     Print every failed/unsupported query\n"
        "  --probe-stats             Read-test every known stat on sample live objects\n"
        "  --allow-clear             Also probe READ_AND_CLEAR modes (mutates counters)\n"
        "  --list-switches           Validate and describe the supplied switch VID\n"
        "  --client                  Connect to running syncd (default)\n"
        "  --server                  Become a sairedis server (use only without syncd)\n"
        "  --client-config <file>    sairedis client_config.json\n"
        "  --context-config <file>   sairedis context_config.json\n"
        "  --server-config <file>    sairedis server_config.json\n"
        "  --timeout-ms <n>          Synchronous response timeout in milliseconds\n"
        "  -h, --help                Show this help\n"
        "\n"
        "Examples:\n"
        "  %s 0x21000000000000\n"
        "  %s --object PORT --include-unsupported 0x21000000000000\n"
        "  %s --all 0x21000000000000 > capabilities.txt\n"
        "  %s --probe-stats 0x21000000000000\n",
        program,
        program,
        program,
        program,
        program);
}

bool
parse_options(int argc, char **argv, Options &options)
{
    auto need_value = [&](int &index, const char *name, std::string &out) {
        if (++index >= argc) {
            std::fprintf(stderr, "%s requires a value\n", name);
            return false;
        }
        out = argv[index];
        return true;
    };

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);

        if (argument == "-h" || argument == "--help") {
            options.show_help = true;
        } else if (argument == "--all") {
            options.all = true;
        } else if (argument == "--include-unsupported") {
            options.include_unsupported = true;
        } else if (argument == "--probe-stats") {
            options.probe_stats = true;
        } else if (argument == "--allow-clear") {
            options.allow_clear = true;
        } else if (argument == "--list-switches") {
            options.list_switches = true;
        } else if (argument == "--client") {
            options.server_mode = false;
        } else if (argument == "--server") {
            options.server_mode = true;
        } else if (argument == "--object") {
            if (!need_value(index, "--object", options.object_filter)) {
                return false;
            }
        } else if (argument == "--client-config") {
            if (!need_value(index, "--client-config", options.client_config)) {
                return false;
            }
        } else if (argument == "--context-config") {
            if (!need_value(index, "--context-config", options.context_config)) {
                return false;
            }
        } else if (argument == "--server-config") {
            if (!need_value(index, "--server-config", options.server_config)) {
                return false;
            }
        } else if (argument == "--timeout-ms") {
            std::string value;
            if (!need_value(index, "--timeout-ms", value)) {
                return false;
            }
            errno = 0;
            char *end = nullptr;
            const unsigned long long parsed =
                std::strtoull(value.c_str(), &end, 0);
            if (errno != 0 || end == value.c_str() || *end != '\0') {
                std::fprintf(stderr, "Invalid --timeout-ms: %s\n", value.c_str());
                return false;
            }
            options.response_timeout_ms = parsed;
        } else if (argument.rfind("--object=", 0) == 0) {
            options.object_filter = argument.substr(std::strlen("--object="));
        } else if (argument.rfind("--client-config=", 0) == 0) {
            options.client_config = argument.substr(
                std::strlen("--client-config="));
        } else if (argument.rfind("--context-config=", 0) == 0) {
            options.context_config = argument.substr(
                std::strlen("--context-config="));
        } else if (argument.rfind("--server-config=", 0) == 0) {
            options.server_config = argument.substr(
                std::strlen("--server-config="));
        } else if (!argument.empty() && argument[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", argument.c_str());
            return false;
        } else if (options.switch_vid != nullptr) {
            std::fprintf(stderr, "Only one switch VID may be specified\n");
            return false;
        } else {
            options.switch_vid = argv[index];
        }
    }

    if (options.show_help) {
        return true;
    }
    return options.switch_vid != nullptr;
}

bool
parse_switch_vid(const char *text, sai_object_id_t &switch_id)
{
    errno = 0;
    char *end = nullptr;
    const uint64_t parsed = std::strtoull(text, &end, 0);

    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }

    switch_id = static_cast<sai_object_id_t>(parsed);
    return true;
}

} // namespace

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
    Options options;
    if (!parse_options(argc, argv, options)) {
        print_usage(argv[0]);
        return 2;
    }

    if (options.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    sai_object_id_t requested_switch = SAI_NULL_OBJECT_ID;
    if (!parse_switch_vid(options.switch_vid, requested_switch)) {
        std::fprintf(
            stderr,
            "Invalid switch VID: %s\n",
            options.switch_vid);
        return 2;
    }

    ProfileState *state = profile_state();
    state->options = options;
    state->transport =
        options.server_mode ? Transport::Server : Transport::Client;

    /*
     * The provided VID is validated against the live switch object below. A
     * bad VID must never be reported as "the ASIC does not support this".
     */

    sai_service_method_table_t services{};
    services.profile_get_value = profile_get_value;
    services.profile_get_next_value = profile_get_next_value;

    sai_status_t status = SAI_STATUS_FAILURE;
    try {
        status = sai_api_initialize(0, &services);
    } catch (const std::exception &exception) {
        std::fprintf(
            stderr,
            "sai_api_initialize threw: %s\n",
            exception.what());
        std::fprintf(
            stderr,
            "Hint: if syncd is running with ZMQ, ensure you did not pass "
            "--server; this tool defaults to client mode.\n");
        return 1;
    }

    if (status != SAI_STATUS_SUCCESS) {
        std::fprintf(
            stderr,
            "sai_api_initialize failed: %s\n",
            format_status(status).c_str());
        return 1;
    }

    std::printf(
        "Switch VID: 0x%" PRIx64 "\n",
        static_cast<uint64_t>(requested_switch));
    std::printf(
        "Transport: %s\n",
        state->transport == Transport::Client
            ? "client (connect to running syncd)"
            : "server (this process owns the sairedis endpoint)");
    if (state->transport == Transport::Server) {
        std::printf(
            "WARNING: server mode shares the synchronous response queue with "
            "any other client and must not be used while syncd is running.\n");
    }

    std::printf("\n=== Version context ===\n");
    std::printf(
        "Compiled SAI headers: %s\n",
        format_api_version(SAI_API_VERSION).c_str());
    std::printf(
        "Linked metadata:      %s\n",
        format_api_version(
            sai_metadata_query_api_version()).c_str());
    std::printf(
        "NOTE: 'Linked metadata' is what libsaimetadata was compiled with; it "
        "reflects the tool build, not the adapter's own metadata. Vendor\n"
        "      private attributes absent from these headers cannot appear in "
        "this report.\n");

    sai_api_version_t queried_version = 0;
    try {
        status = sai_query_api_version(&queried_version);
    } catch (const std::exception &) {
        status = SAI_STATUS_FAILURE;
    }
    std::printf(
        "Advisory query:       status=%s",
        format_status(status).c_str());
    if (status == SAI_STATUS_SUCCESS) {
        std::printf(
            " version=%s",
            format_api_version(queried_version).c_str());
    }
    std::printf("\n");
    std::printf(
        "NOTE: sairedis answers this with its own client-header version, so it "
        "is advisory only and does not identify the remote vendor libsai.\n");

    print_metadata_inventory();

    void *api_table = nullptr;
    status = sai_api_query(SAI_API_SWITCH, &api_table);
    if (status != SAI_STATUS_SUCCESS || api_table == nullptr) {
        std::fprintf(
            stderr,
            "sai_api_query(SWITCH) failed: %s\n",
            format_status(status).c_str());
        sai_api_uninitialize();
        return 1;
    }
    const auto *switch_api = static_cast<const sai_switch_api_t *>(api_table);

    /*
     * Validate the switch VID before running any capability query. This is the
     * guard that keeps a wrong/expired VID from turning the whole report into
     * "unsupported".
     */
    {
        const sai_attr_metadata_t *type_metadata =
            find_attribute("SAI_SWITCH_ATTR_TYPE");
        if (type_metadata == nullptr) {
            std::fprintf(
                stderr,
                "Metadata missing SAI_SWITCH_ATTR_TYPE; cannot validate VID\n");
            sai_api_uninitialize();
            return 1;
        }

        sai_attribute_t attribute{};
        attribute.id = type_metadata->attrid;
        status = SAI_STATUS_FAILURE;
        try {
            status = switch_api->get_switch_attribute(
                requested_switch, 1, &attribute);
        } catch (const std::exception &exception) {
            std::fprintf(
                stderr,
                "Switch VID validation threw: %s\n",
                exception.what());
            sai_api_uninitialize();
            return 1;
        }

        if (status != SAI_STATUS_SUCCESS) {
            std::fprintf(
                stderr,
                "\nFATAL: switch VID 0x%" PRIx64 " is not a valid live "
                "switch: %s\n"
                "Refusing to run capability queries, because every answer "
                "would be a false negative.\n"
                "Check the VID against ASIC_DB / syncd, and make sure the "
                "context config matches.\n",
                static_cast<uint64_t>(requested_switch),
                format_status(status).c_str());
            sai_api_uninitialize();
            return 3;
        }

        std::printf(
            "\nSwitch VID validation: OK (SAI_SWITCH_ATTR_TYPE=%s)\n",
            format_enum_value(
                type_metadata->enummetadata,
                attribute.value.s32).c_str());
    }

    if (options.response_timeout_ms != 0) {
        /*
         * sairedis exposes the synchronous timeout as an extension attribute.
         * In server mode it can be applied here; in client mode libsairedis
         * explicitly rejects extension attributes, so the request cannot be
         * honoured and that is reported rather than silently ignored.
         */
        if (state->transport == Transport::Server) {
            sai_attribute_t timeout_attr{};
            timeout_attr.id =
                SAI_REDIS_SWITCH_ATTR_SYNC_OPERATION_RESPONSE_TIMEOUT;
            timeout_attr.value.u64 = options.response_timeout_ms;

            sai_status_t timeout_status = SAI_STATUS_FAILURE;
            try {
                timeout_status = switch_api->set_switch_attribute(
                    requested_switch, &timeout_attr);
            } catch (const std::exception &) {
                timeout_status = SAI_STATUS_FAILURE;
            }

            std::printf(
                "Sync timeout: %s (requested %" PRIu64 " ms)\n",
                format_status(timeout_status).c_str(),
                options.response_timeout_ms);
        } else {
            std::printf(
                "Sync timeout: NOT APPLIED (--timeout-ms=%" PRIu64 "). "
                "libsairedis rejects extension attributes in client mode; "
                "use the default 60s timeout or run with --server.\n",
                options.response_timeout_ms);
        }
    }

    const SupportedObjectTypes supported =
        query_supported_object_types(requested_switch, switch_api);

    if (options.list_switches) {
        const std::string type_count = supported.authoritative
            ? std::to_string(supported.types.size())
            : "unknown";
        std::printf(
            "\n=== Switch VID description ===\n"
            "switch=0x%" PRIx64 " supported_object_types=%s\n",
            static_cast<uint64_t>(requested_switch),
            type_count.c_str());
        sai_api_uninitialize();
        return 0;
    }

    show_switch_summary(
        requested_switch,
        switch_api,
        options.include_unsupported);

    if (options.all) {
        show_all_read_only_switch_attributes(
            requested_switch,
            switch_api,
            options.include_unsupported);
    }

    if (options.all || !options.object_filter.empty()) {
        show_all_attribute_capabilities(
            requested_switch,
            supported,
            options.object_filter,
            options.include_unsupported);
    } else {
        show_focused_capabilities(requested_switch);
    }

    /*
     * Query statistics capability once per object type and share it between
     * the report and the cross-validating live probe.
     */
    StatsCapabilityCache stats_cache(requested_switch);

    show_stats_capabilities(
        supported,
        stats_cache,
        options.all,
        options.object_filter,
        options.include_unsupported);

    show_stream_telemetry_capabilities(
        requested_switch,
        supported,
        options.all,
        options.object_filter,
        options.include_unsupported);

    show_generic_availability(
        requested_switch,
        supported,
        options.all,
        options.object_filter,
        options.include_unsupported);

    show_resource_type_availability(
        requested_switch,
        supported,
        options.include_unsupported);

    show_legacy_resource_attributes(
        requested_switch,
        switch_api,
        options.include_unsupported);

    if (options.probe_stats) {
        probe_live_stats(
            requested_switch,
            switch_api,
            stats_cache,
            options.include_unsupported,
            options.allow_clear);
    }

    status = sai_api_uninitialize();
    if (status != SAI_STATUS_SUCCESS) {
        std::fprintf(
            stderr,
            "sai_api_uninitialize failed: %s\n",
            format_status(status).c_str());
        return 1;
    }

    return 0;
}
