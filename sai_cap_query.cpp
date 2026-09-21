/*
 * sai_cap_query - discover the capabilities an ASIC exposes through SAI.
 *
 * The tool links against libsairedis and therefore talks to the running syncd
 * over the regular SAI Redis / ZMQ transport.
 *
 * P0 changes (see README.md "P0 hardening"):
 *   - the transport defaults to the Redis channel (the sairedis server
 *     role, SAI_REDIS_ENABLE_CLIENT=false), which is what a stock syncd
 *     serves; --client opts into the ZMQ client role, which additionally
 *     needs syncd -z zmq_sync;
 *   - every libsairedis call is wrapped in try/catch, because libsairedis
 *     throws on malformed/unexpected responses;
 *   - the switch VID is probed with one live GET before any capability
 *     query: a structurally invalid oid (SAI_STATUS_INVALID_OBJECT_ID)
 *     refuses the run, because every answer would be a false negative,
 *     while an object merely absent from the ASIC view
 *     (SAI_STATUS_ITEM_NOT_FOUND) only warns -- a correct single-ASIC VID
 *     answers that way on a box whose view does not carry the switch yet,
 *     and the capability queries still work; the VID itself is optional --
 *     single-ASIC SONiC boxes all expose the same switch oid
 *     (kDefaultSwitchVidText), so a bare invocation targets it;
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

/* Dependency-free JSON builder for --format json. */
#include "json_value.h"

/*
 * ZMQ endpoint facts for the transport preflight. Kept in its own header
 * so the unit tests can exercise them without libsairedis, redis, or an
 * ASIC (see tests/test_zmq_endpoint.cpp).
 */
#include "zmq_endpoint.h"

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
#include <chrono>
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

/* json_value.h lives in namespace cap as well. */
using cap::JsonValue;

std::string
format_object_id_hex(sai_object_id_t object_id)
{
    char buffer[32];
    std::snprintf(
        buffer,
        sizeof(buffer),
        "0x%" PRIx64,
        static_cast<uint64_t>(object_id));
    return std::string(buffer);
}

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
/* Cap how many contradiction lines are printed; counts stay exact. */
constexpr size_t kMaxContradictionLines = 50;
constexpr uint32_t kMaximumListCapacity = 1024 * 1024;

/* ------------------------------------------------------------------ */
/* options                                                             */
/* ------------------------------------------------------------------ */

enum class Transport
{
    Client, /* connect to syncd's ZMQ server (--client; needs -z zmq_sync) */
    Server, /* Redis channel via the embedded sairedis server (default) */
};

/*
 * Default switch VID for single-ASIC SONiC boxes. Every single-ASIC switch
 * exposes the same switch object oid, so the positional VID is optional:
 * a bare invocation targets this one. Verified against ASIC_DB on a
 * z9332f-12 -- `redis-cli -n 1 --scan --pattern
 * 'ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*'` answers exactly this key. Multi-ASIC
 * (VoQ) boxes give every asic its own VID and must pass it explicitly.
 */
const char kDefaultSwitchVidText[] = "0x21000000000000";

struct Options
{
    bool all = false;
    bool include_unsupported = false;
    bool probe_stats = false;
    bool show_help = false;
    bool list_switches = false;
    /*
     * Which transport role to take. The default is the server role (the
     * Redis channel): a stock syncd serves no ZMQ endpoint at all, so the
     * client role cannot work on a normal box, while the server role
     * works against every syncd mode. --client opts into the client role.
     */
    bool client_mode = false;
    bool allow_clear = false;
    bool verify_attributes = false;
    bool debug = false;
    std::string format = "text";
    std::string object_filter;
    std::string client_config;
    std::string context_config;
    std::string server_config;
    const char *switch_vid = nullptr;
    /* True when switch_vid came from kDefaultSwitchVidText rather than the
     * command line, so the banner and the failure path can say so. */
    bool switch_vid_defaulted = false;
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

struct SupportedObjectTypesQuery
{
    SupportedObjectTypes supported;
    FetchOutcome outcome;
    bool metadata_present = false;
};

/*
 * Query the authoritative supported object type list. Printing is left to the
 * caller so the text and JSON reporters can share this logic.
 */
SupportedObjectTypesQuery
query_supported_object_types(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api)
{
    SupportedObjectTypesQuery result;
    const sai_attr_metadata_t *metadata =
        find_attribute("SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST");

    if (metadata == nullptr) {
        result.outcome.detail = "metadata missing";
        return result;
    }
    result.metadata_present = true;

    sai_attribute_t attribute{};
    AttributeStorage storage;
    result.outcome = fetch_attribute(
        metadata,
        [switch_api, switch_id](sai_attribute_t *value) {
            return switch_api->get_switch_attribute(
                switch_id,
                1,
                value);
        },
        attribute,
        storage);

    if (result.outcome.result != FetchKind::Ok) {
        return result;
    }

    result.supported.authoritative = true;
    for (uint32_t index = 0; index < attribute.value.s32list.count; ++index) {
        result.supported.types.insert(attribute.value.s32list.list[index]);
    }

    return result;
}

void
print_supported_object_types(const SupportedObjectTypesQuery &query)
{
    const SupportedObjectTypes &supported = query.supported;

    std::printf("\n=== Supported object types ===\n");

    if (!query.metadata_present) {
        std::printf("Metadata does not contain SUPPORTED_OBJECT_TYPE_LIST\n");
        return;
    }

    std::printf("status=%s", format_status(query.outcome.status).c_str());
    if (!query.outcome.detail.empty()) {
        std::printf(" detail=%s", query.outcome.detail.c_str());
    }
    std::printf("\n");

    if (!supported.authoritative) {
        std::printf(
            "The adapter did not expose an authoritative object list; "
            "object type verdicts will be reported as unknown.\n");
        return;
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
 * Live verification of attribute capability claims.
 *
 * sai_query_attribute_capability is a declaration. For attributes the adapter
 * says are gettable, this performs a real GET on a live object and reports any
 * claim it cannot substantiate as a CONTRADICTION.
 *
 * Conditionally-valid attributes (isconditional / isvalidonly) can legitimately
 * fail a GET when their condition is not met on the sampled object, so those
 * are reported as UNVERIFIABLE rather than as contradictions.
 *
 * Only object types for which the tool can obtain a live object are checked;
 * everything else is reported as not-verifiable instead of silently skipped.
 */
struct AttributeVerificationSummary
{
    size_t checked = 0;
    size_t agree = 0;
    size_t contradictions = 0;
    size_t unverifiable = 0;
    size_t skipped_value_type = 0;
    size_t condition_met = 0;
    size_t condition_not_met = 0;
    size_t condition_unknown = 0;
    std::set<std::string> contradictory_attributes;
};

/* Defined after the probe helpers; used to pick a sample port. */
sai_object_id_t
select_sample_port(const std::vector<sai_object_id_t> &ports);

/*
 * Per-object cache of the attributes referenced by condition predicates.
 *
 * Condition lists on one object tend to reference the same handful of
 * attributes (a queue count gating dozens of per-queue attributes, for
 * example), and each conditional attribute used to re-read every attribute
 * its conditions depend on. Caching by attribute id cuts the GET round
 * trips on one object scan from O(conditional attributes x referenced) to
 * O(distinct referenced).
 *
 * Failures are cached too: a predicate whose referenced attribute could
 * not be read stays Unknown without repeating the failing GET for every
 * consumer.
 *
 * Only condition-evaluable types reach this cache, and those are all
 * primitives held inline in the attribute union, so a cached value stays
 * valid once the fetch-time buffer goes out of scope. If conditions ever
 * become evaluable on a pointer-backed type, this class must change.
 */
class ConditionAttributeCache
{
public:
    explicit ConditionAttributeCache(const AttributeGetter &getter)
        : m_getter(getter) {}

    /*
     * Return the cached value of one referenced attribute, fetching it on
     * first use. The result is SAI_STATUS_SUCCESS only when the read
     * succeeded; any other status (including a cached earlier failure)
     * means the caller must treat the predicate as Unknown, exactly as a
     * direct fetch failure did.
     */
    sai_status_t read(
        const sai_attr_metadata_t *referenced,
        sai_attribute_t &attribute)
    {
        attribute = {};
        attribute.id = referenced->attrid;

        Entry &entry = m_entries[referenced->attrid];

        if (!entry.attempted) {
            entry.attempted = true;

            sai_attribute_t fetched{};
            AttributeStorage storage;
            const FetchOutcome outcome = fetch_attribute(
                referenced, m_getter, fetched, storage);

            entry.status = outcome.status;
            entry.ok = outcome.result == FetchKind::Ok;
            if (entry.ok) {
                entry.value = fetched;
            }
        }

        attribute = entry.value;
        return entry.ok ? SAI_STATUS_SUCCESS : entry.status;
    }

private:
    struct Entry
    {
        bool attempted = false;
        bool ok = false;
        sai_status_t status = SAI_STATUS_FAILURE;
        sai_attribute_t value{};
    };

    std::map<sai_attr_id_t, Entry> m_entries;
    const AttributeGetter &m_getter;
};

/*
 * Read the attributes one condition predicate depends on, so the SAI
 * metadata condition evaluator can be run against live values instead of
 * defaults.
 *
 * Reads go through the per-object ConditionAttributeCache, because the
 * same few attributes tend to gate many conditional attributes on one
 * object and re-reading them per consumer multiplies the GET round trips.
 *
 * Only attributes that can be read are passed through; if any referenced
 * attribute cannot be read, the predicate is reported as Unknown rather than
 * being silently evaluated against its default (which could differ from the
 * live value and yield a wrong verdict).
 *
 * conditional_predicate selects the evaluator and must match the flag whose
 * list is passed in: sai_metadata_is_condition_met answers false for an
 * attribute that is not conditional, and sai_metadata_is_validonly_met
 * answers false for one that is not valid-only (see
 * include/meta/saimetadatautils.h), so the two lists cannot share an
 * evaluator.
 */
ConditionState
evaluate_condition_list(
    const sai_attr_metadata_t *metadata,
    const sai_object_type_info_t *info,
    ConditionAttributeCache &cache,
    const sai_attr_condition_t *const *list,
    size_t count,
    bool conditional_predicate)
{
    if (count == 0 || list == nullptr) {
        return ConditionState::Unknown;
    }

    std::vector<sai_attribute_t> attributes;
    attributes.reserve(count);
    size_t usable = 0;

    for (size_t i = 0; i < count; ++i) {
        const sai_attr_condition_t *condition = list[i];
        if (condition == nullptr) {
            continue;
        }

        const sai_attr_metadata_t *referenced =
            sai_metadata_get_attr_metadata(
                info->objecttype, condition->attrid);
        if (referenced == nullptr ||
            !is_condition_evaluable_value_type(
                referenced->attrvaluetype)) {
            return ConditionState::Unknown;
        }

        /*
         * Skip duplicates: sai_metadata_get_attr_by_id selects only the first
         * matching entry, and passing the same id twice would be ambiguous.
         */
        bool already_read = false;
        for (const auto &existing : attributes) {
            if (existing.id == condition->attrid) {
                already_read = true;
                break;
            }
        }
        if (already_read) {
            continue;
        }

        sai_attribute_t attribute{};
        if (cache.read(referenced, attribute) != SAI_STATUS_SUCCESS) {
            return ConditionState::Unknown;
        }

        /*
         * The cached attribute is a copy of a condition-evaluable value,
         * which is always a primitive held inline in the union, so the
         * copy stays valid independently of the cache. If conditions ever
         * become evaluable on a pointer-backed type, ConditionAttributeCache
         * and this copy must both be revisited.
         */
        attributes.push_back(attribute);
        ++usable;
    }

    /*
     * No usable predicate entry (every entry was null): calling the evaluator
     * with an empty list would let it fall back to the referenced attributes'
     * default values, which this function exists to avoid.
     */
    if (usable == 0) {
        return ConditionState::Unknown;
    }

    const bool met = conditional_predicate
        ? sai_metadata_is_condition_met(
              metadata,
              static_cast<uint32_t>(attributes.size()),
              attributes.data())
        : sai_metadata_is_validonly_met(
              metadata,
              static_cast<uint32_t>(attributes.size()),
              attributes.data());

    return met ? ConditionState::Met : ConditionState::NotMet;
}

/*
 * Evaluate an attribute's conditions on the sampled object.
 *
 * isconditional and isvalidonly are independent predicates, each with its own
 * condition list and its own metadata evaluator. A single
 * `isconditional ? conditions : validonly` selection under-evaluates an
 * attribute carrying both flags: a NotMet valid-only condition could be
 * masked by a Met conditions list, the attribute wrongly treated as in force,
 * and a failed GET promoted to a false CONTRADICTION.
 *
 * Every flag the attribute carries is evaluated, and the results are combined
 * by combine_condition_states, which yields Met only when all of them are Met.
 *
 * The cache shared with the enclosing object scan keeps attributes that
 * both predicates reference down to a single GET per object.
 */
ConditionState
evaluate_attribute_condition(
    const sai_attr_metadata_t *metadata,
    const sai_object_type_info_t *info,
    ConditionAttributeCache &cache)
{
    ConditionState state = ConditionState::Met;

    if (metadata->isconditional) {
        state = evaluate_condition_list(
            metadata,
            info,
            cache,
            metadata->conditions,
            metadata->conditionslength,
            true);
    }

    if (metadata->isvalidonly) {
        const ConditionState validonly = evaluate_condition_list(
            metadata,
            info,
            cache,
            metadata->validonly,
            metadata->validonlylength,
            false);
        state = combine_condition_states(state, validonly);
    }

    return state;
}

void
verify_attribute_capabilities_on_object(
    const sai_object_type_info_t *info,
    sai_object_id_t switch_id,
    sai_object_id_t object_id,
    const AttributeGetter &getter,
    bool include_unsupported,
    AttributeVerificationSummary &summary)
{
    std::printf(
        "\n%s live attribute verification on object 0x%" PRIx64 ":\n",
        info->objecttypename,
        static_cast<uint64_t>(object_id));

    size_t object_checked = 0;
    size_t printed_contradictions = 0;
    size_t hidden_contradictions = 0;

    /*
     * One cache per object scan: attributes referenced by condition lists
     * are read once here and shared by every conditional attribute on this
     * object, instead of being re-fetched per consumer.
     */
    ConditionAttributeCache cache(getter);

    for (size_t index = 0;
         info->attrmetadata[index] != nullptr;
         ++index) {
        const sai_attr_metadata_t *metadata = info->attrmetadata[index];

        if (!can_fetch_value_type(metadata->attrvaluetype)) {
            ++summary.skipped_value_type;
            continue;
        }

        sai_attr_capability_t capability{};
        sai_status_t capability_status = SAI_STATUS_FAILURE;
        try {
            capability_status = sai_query_attribute_capability(
                switch_id,
                info->objecttype,
                metadata->attrid,
                &capability);
        } catch (const std::exception &) {
            capability_status = SAI_STATUS_FAILURE;
        }

        if (capability_status != SAI_STATUS_SUCCESS ||
            !capability.get_implemented) {
            continue;
        }

        ++object_checked;
        ++summary.checked;

        sai_attribute_t attribute{};
        AttributeStorage storage;
        const FetchOutcome outcome =
            fetch_attribute(metadata, getter, attribute, storage);

        const bool probe_ok = outcome.result == FetchKind::Ok;
        const bool conditional =
            metadata->isconditional || metadata->isvalidonly;

        ConditionState condition = ConditionState::Met;
        if (conditional) {
            condition = evaluate_attribute_condition(
                metadata, info, cache);
            switch (condition) {
                case ConditionState::Met:
                    ++summary.condition_met;
                    break;
                case ConditionState::NotMet:
                    ++summary.condition_not_met;
                    break;
                case ConditionState::Unknown:
                    ++summary.condition_unknown;
                    break;
            }
        }

        const Agreement agreement =
            compare_attribute_capability_with_condition(
                capability.get_implemented,
                probe_ok,
                conditional,
                condition);

        switch (agreement) {
            case Agreement::Agree:
                ++summary.agree;
                break;
            case Agreement::Contradiction:
                ++summary.contradictions;
                summary.contradictory_attributes.insert(
                    metadata->attridname);
                if (printed_contradictions < kMaxContradictionLines) {
                    ++printed_contradictions;
                    std::printf(
                        "  %-64s CONTRADICTION: declared gettable but GET "
                        "failed (%s)\n",
                        metadata->attridname,
                        format_status(outcome.status).c_str());
                } else {
                    ++hidden_contradictions;
                }
                break;
            case Agreement::Unverifiable:
                ++summary.unverifiable;
                if (include_unsupported) {
                    std::printf(
                        "  %-64s unverifiable (conditional, GET said %s)\n",
                        metadata->attridname,
                        format_status(outcome.status).c_str());
                }
                break;
        }
    }

    std::printf(
        "  %s live verification: checked=%zu\n",
        info->objecttypename,
        object_checked);
    if (hidden_contradictions != 0) {
        std::printf(
            "  ... %zu more contradiction(s) not printed; use the summary "
            "and the contradicted-attributes list below.\n",
            hidden_contradictions);
    }
}

/*
 * Attribute claims can only be verified on object types for which a live
 * object exists. SWITCH and PORT are always obtainable; that is stated
 * explicitly so an unverified attribute is never read as a verified one.
 */
void
verify_attribute_capabilities(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    bool include_unsupported)
{
    std::printf("\n=== Live attribute capability verification ===\n");
    std::printf(
        "Performs a real GET for every attribute the adapter declared gettable\n"
        "on a live object. Conditionally-valid attributes that reject a GET are\n"
        "reported as unverifiable, not as contradictions. Only SWITCH and PORT\n"
        "are verified; other object types cannot be sampled by this tool.\n");

    AttributeVerificationSummary summary;

    const sai_object_type_info_t *switch_info =
        sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_SWITCH);
    if (switch_info != nullptr) {
        verify_attribute_capabilities_on_object(
            switch_info,
            switch_id,
            switch_id,
            [switch_api, switch_id](sai_attribute_t *value) {
                return switch_api->get_switch_attribute(
                    switch_id, 1, value);
            },
            include_unsupported,
            summary);
    }

    std::vector<sai_object_id_t> ports;
    sai_status_t status = SAI_STATUS_FAILURE;
    if (get_object_list(
            find_attribute("SAI_SWITCH_ATTR_PORT_LIST"),
            [switch_api, switch_id](sai_attribute_t *value) {
                return switch_api->get_switch_attribute(
                    switch_id, 1, value);
            },
            ports,
            status) &&
        !ports.empty()) {
        const sai_object_type_info_t *port_info =
            sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_PORT);
        void *api_table = nullptr;
        if (port_info != nullptr &&
            sai_api_query(SAI_API_PORT, &api_table) == SAI_STATUS_SUCCESS &&
            api_table != nullptr) {
            const auto *port_api =
                static_cast<const sai_port_api_t *>(api_table);
            const sai_object_id_t sample_port = select_sample_port(ports);
            if (sample_port != SAI_NULL_OBJECT_ID) {
                verify_attribute_capabilities_on_object(
                    port_info,
                    switch_id,
                    sample_port,
                    [port_api, sample_port](sai_attribute_t *value) {
                        return port_api->get_port_attribute(
                            sample_port, 1, value);
                    },
                    include_unsupported,
                    summary);
            }
        }
    }

    std::printf(
        "\nAttribute verification summary: checked=%zu agree=%zu "
        "contradictions=%zu unverifiable=%zu skipped_value_type=%zu\n",
        summary.checked,
        summary.agree,
        summary.contradictions,
        summary.unverifiable,
        summary.skipped_value_type);
    if (summary.condition_met != 0 ||
        summary.condition_not_met != 0 ||
        summary.condition_unknown != 0) {
        std::printf(
            "  conditional attributes: condition_met=%zu "
            "condition_not_met=%zu condition_unknown=%zu\n",
            summary.condition_met,
            summary.condition_not_met,
            summary.condition_unknown);
        std::printf(
            "  A contradiction is only asserted when the condition was "
            "evaluated as met; unknown conditions are unverifiable.\n");
    }

    if (!summary.contradictory_attributes.empty()) {
        std::printf("  contradicted attributes (%zu):",
            summary.contradictory_attributes.size());
        size_t printed = 0;
        for (const auto &name : summary.contradictory_attributes) {
            if (printed++ >= kMaxContradictionLines) {
                std::printf(" ...");
                break;
            }
            std::printf(" %s", name.c_str());
        }
        std::printf("\n");
    }
    if (summary.checked == 0) {
        std::printf(
            "No gettable attribute claims were verifiable on the sampled "
            "objects.\n");
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
            [switch_api](
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
/* JSON report                                                         */
/* ------------------------------------------------------------------ */

/*
 * Build the machine-readable report.
 *
 * This reuses the same pure query helpers as the text path, so the two
 * formats cannot disagree about what was asked. Unlike the text output, JSON
 * mode does not truncate or cap anything: consumers are expected to filter,
 * and silently dropping data would be worse than a large document.
 */
JsonValue
build_json_report(
    const Options &options,
    sai_object_id_t requested_switch,
    Transport transport,
    const SupportedObjectTypesQuery &supported_query,
    const sai_switch_api_t *switch_api,
    StatsCapabilityCache &stats_cache)
{
    JsonValue root = JsonValue::make_object();

    root.set("tool", JsonValue::make_string("sai_cap_query"));
    root.set(
        "schema_version",
        JsonValue::make_uint(1));
    root.set(
        "compiled_sai_version",
        JsonValue::make_string(format_api_version(SAI_API_VERSION)));
    root.set(
        "linked_metadata_version",
        JsonValue::make_string(
            format_api_version(sai_metadata_query_api_version())));
    root.set(
        "switch_vid",
        JsonValue::make_string(
            format_object_id_hex(requested_switch)));
    root.set(
        "transport",
        JsonValue::make_string(
            transport == Transport::Client ? "client" : "server"));
    root.set(
        "object_filter",
        JsonValue::make_string(options.object_filter));
    root.set("all", JsonValue::make_bool(options.all));
    root.set(
        "include_unsupported",
        JsonValue::make_bool(options.include_unsupported));
    root.set("probe_stats", JsonValue::make_bool(options.probe_stats));
    root.set(
        "verify_attributes",
        JsonValue::make_bool(options.verify_attributes));

    /* Supported object types. */
    const SupportedObjectTypes &supported = supported_query.supported;
    JsonValue supported_json = JsonValue::make_object();
    supported_json.set(
        "authoritative",
        JsonValue::make_bool(supported.authoritative));
    supported_json.set(
        "status",
        JsonValue::make_string(
            format_status(supported_query.outcome.status)));
    if (!supported_query.outcome.detail.empty()) {
        supported_json.set(
            "detail",
            JsonValue::make_string(supported_query.outcome.detail));
    }
    JsonValue type_array = JsonValue::make_array();
    for (int32_t raw : supported.types) {
        const sai_object_type_info_t *info =
            sai_metadata_get_object_type_info(
                static_cast<sai_object_type_t>(raw));
        JsonValue entry = JsonValue::make_object();
        entry.set("value", JsonValue::make_int(raw));
        entry.set(
            "name",
            JsonValue::make_string(
                info != nullptr
                    ? info->objecttypename
                    : classify_unknown_value(raw)));
        entry.set(
            "in_local_metadata",
            JsonValue::make_bool(info != nullptr));
        if (info != nullptr) {
            entry.set(
                "experimental",
                JsonValue::make_bool(info->isexperimental));
            entry.set(
                "vendor_custom",
                JsonValue::make_bool(info->iscustom));
        }
        type_array.push(std::move(entry));
    }
    supported_json.set("types", std::move(type_array));
    root.set("supported_object_types", std::move(supported_json));

    /* Switch attributes (read-only sweep). */
    {
        std::vector<const sai_attr_metadata_t *> attributes;
        const sai_object_type_info_t *switch_info =
            sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_SWITCH);
        if (switch_info != nullptr) {
            for (size_t i = 0;
                 switch_info->attrmetadata[i] != nullptr;
                 ++i) {
                const sai_attr_metadata_t *metadata =
                    switch_info->attrmetadata[i];
                /*
                 * Only read-only attributes are swept. A GET is meaningless
                 * on create/set-only attributes (the adapter is expected to
                 * reject it), so querying them would only add failures and
                 * round trips; the text report's --all sweep applies the
                 * same restriction.
                 */
                if (metadata->isreadonly) {
                    attributes.push_back(metadata);
                }
            }
        }

        JsonValue attributes_json = JsonValue::make_array();
        for (const sai_attr_metadata_t *metadata : attributes) {
            if (metadata == nullptr) {
                continue;
            }
            sai_attribute_t attribute{};
            AttributeStorage storage;
            const FetchOutcome outcome = fetch_attribute(
                metadata,
                [switch_api, requested_switch](sai_attribute_t *value) {
                    return switch_api->get_switch_attribute(
                        requested_switch, 1, value);
                },
                attribute,
                storage);

            JsonValue entry = JsonValue::make_object();
            entry.set(
                "name", JsonValue::make_string(metadata->attridname));
            entry.set(
                "result",
                JsonValue::make_string(
                    summary_bucket(outcome.result, outcome.status)));
            entry.set(
                "status",
                JsonValue::make_string(format_status(outcome.status)));
            if (!outcome.detail.empty()) {
                entry.set(
                    "detail",
                    JsonValue::make_string(outcome.detail));
            }
            if (outcome.result == FetchKind::Ok) {
                entry.set(
                    "value",
                    JsonValue::make_string(
                        serialize_attribute(metadata, attribute)));
            }
            entry.set(
                "read_only",
                JsonValue::make_bool(metadata->isreadonly));
            entry.set(
                "deprecated",
                JsonValue::make_bool(metadata->isdeprecated));
            attributes_json.push(std::move(entry));
        }
        root.set("switch_attributes", std::move(attributes_json));
    }

    /*
     * Attribute capability declarations.
     *
     * This is the most expensive section (one round trip per attribute in the
     * whole schema). Mirror the text path in two ways:
     *   - scan everything only with --all or an --object filter, otherwise
     *     restrict to the focused object types;
     *   - when the adapter published an authoritative object list and a type
     *     is absent from it, do not spend a round trip per attribute asking
     *     about support for an object type the adapter itself excluded. The
     *     metadata-derived fields are still reported, and `verdict` explains
     *     why the live declaration is missing.
     */
    {
        static const sai_object_type_t focused_types[] = {
            SAI_OBJECT_TYPE_PORT,
            SAI_OBJECT_TYPE_QUEUE,
            SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
            SAI_OBJECT_TYPE_ROUTER_INTERFACE,
            SAI_OBJECT_TYPE_SWITCH,
        };
        const bool full_scan =
            options.all || !options.object_filter.empty();

        JsonValue capabilities_json = JsonValue::make_array();
        const std::string &filter = options.object_filter;
        for (size_t i = 1;
             sai_metadata_all_object_type_infos[i] != nullptr;
             ++i) {
            const sai_object_type_info_t *info =
                sai_metadata_all_object_type_infos[i];
            if (!object_name_matches(info->objecttypename, filter)) {
                continue;
            }
            if (!full_scan) {
                bool focused = false;
                for (sai_object_type_t type : focused_types) {
                    if (type == info->objecttype) {
                        focused = true;
                        break;
                    }
                }
                if (!focused) {
                    continue;
                }
            }
            const bool asic_supported =
                supported.authoritative &&
                supported.is_supported(info->objecttype);
            const bool query_capability =
                !supported.authoritative || asic_supported;
            for (size_t j = 0;
                 info->attrmetadata[j] != nullptr;
                 ++j) {
                const sai_attr_metadata_t *metadata =
                    info->attrmetadata[j];

                JsonValue entry = JsonValue::make_object();
                entry.set(
                    "object_type",
                    JsonValue::make_string(info->objecttypename));
                entry.set(
                    "asic_supported",
                    JsonValue::make_bool(asic_supported));
                entry.set(
                    "name",
                    JsonValue::make_string(metadata->attridname));

                if (!query_capability) {
                    entry.set(
                        "verdict",
                        JsonValue::make_string(
                            supported.verdict(info->objecttype)));
                    entry.set("queried", JsonValue::make_bool(false));
                    entry.set(
                        "conditional",
                        JsonValue::make_bool(metadata->isconditional));
                    entry.set(
                        "valid_only",
                        JsonValue::make_bool(metadata->isvalidonly));
                    entry.set(
                        "deprecated",
                        JsonValue::make_bool(metadata->isdeprecated));
                    capabilities_json.push(std::move(entry));
                    continue;
                }

                sai_attr_capability_t capability{};
                sai_status_t status = SAI_STATUS_FAILURE;
                try {
                    status = sai_query_attribute_capability(
                        requested_switch,
                        metadata->objecttype,
                        metadata->attrid,
                        &capability);
                } catch (const std::exception &) {
                    status = SAI_STATUS_FAILURE;
                }

                entry.set("queried", JsonValue::make_bool(true));
                entry.set(
                    "status",
                    JsonValue::make_string(format_status(status)));
                if (status == SAI_STATUS_SUCCESS) {
                    entry.set(
                        "create_implemented",
                        JsonValue::make_bool(capability.create_implemented));
                    entry.set(
                        "set_implemented",
                        JsonValue::make_bool(capability.set_implemented));
                    entry.set(
                        "get_implemented",
                        JsonValue::make_bool(capability.get_implemented));
                }
                entry.set(
                    "conditional",
                    JsonValue::make_bool(metadata->isconditional));
                entry.set(
                    "valid_only",
                    JsonValue::make_bool(metadata->isvalidonly));
                entry.set(
                    "deprecated",
                    JsonValue::make_bool(metadata->isdeprecated));
                capabilities_json.push(std::move(entry));
            }
        }
        root.set(
            "attribute_capabilities",
            std::move(capabilities_json));
    }

    /* Statistics capabilities. */
    /*
     * Statistics capabilities.
     *
     * Mirror show_stats_capabilities: without --all or an --object filter,
     * restrict the sweep to the focused object types instead of querying
     * stats and stream-telemetry capability for every supported type.
     */
    {
        static const sai_object_type_t focused_types[] = {
            SAI_OBJECT_TYPE_PORT,
            SAI_OBJECT_TYPE_QUEUE,
            SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP,
            SAI_OBJECT_TYPE_ROUTER_INTERFACE,
            SAI_OBJECT_TYPE_SWITCH,
        };
        const bool full_scan =
            options.all || !options.object_filter.empty();

        JsonValue stats_json = JsonValue::make_array();

        auto add_one = [&](const sai_object_type_info_t *info) {
            const StatsCapabilityResult &result = stats_cache.get(info);
            const StatsStCapabilityResult st_result =
                query_stats_st_capability(
                    requested_switch, info);

            JsonValue entry = JsonValue::make_object();
            entry.set(
                "object_type",
                JsonValue::make_string(info->objecttypename));
            entry.set(
                "status",
                JsonValue::make_string(format_status(result.status)));

            JsonValue counters = JsonValue::make_array();
            for (const auto &value : result.values) {
                const int32_t stat = value.stat_enum;
                JsonValue counter = JsonValue::make_object();
                counter.set("value", JsonValue::make_int(stat));
                counter.set(
                    "name",
                    JsonValue::make_string(
                        format_enum_value(info->statenum, stat)));
                counter.set(
                    "modes_raw",
                    JsonValue::make_uint(value.stat_modes));
                counter.set(
                    "modes",
                    JsonValue::make_string(
                        format_stats_modes(value.stat_modes)));
                counters.push(std::move(counter));
            }
            entry.set("counters", std::move(counters));

            JsonValue st_json = JsonValue::make_object();
            st_json.set(
                "status",
                JsonValue::make_string(format_status(st_result.status)));
            JsonValue st_counters = JsonValue::make_array();
            for (const auto &value : st_result.values) {
                JsonValue counter = JsonValue::make_object();
                counter.set(
                    "value",
                    JsonValue::make_int(value.capability.stat_enum));
                counter.set(
                    "name",
                    JsonValue::make_string(
                        format_enum_value(
                            info->statenum,
                            value.capability.stat_enum)));
                counter.set(
                    "modes_raw",
                    JsonValue::make_uint(
                        value.capability.stat_modes));
                counter.set(
                    "minimal_polling_interval_ns",
                    JsonValue::make_uint(
                        value.minimal_polling_interval));
                st_counters.push(std::move(counter));
            }
            st_json.set("counters", std::move(st_counters));
            entry.set("stream_telemetry", std::move(st_json));

            stats_json.push(std::move(entry));
        };

        if (!full_scan) {
            for (sai_object_type_t type : focused_types) {
                const sai_object_type_info_t *info =
                    sai_metadata_get_object_type_info(type);
                if (info != nullptr && info->statenum != nullptr) {
                    add_one(info);
                }
            }
        } else {
            for (size_t i = 1;
                 sai_metadata_all_object_type_infos[i] != nullptr;
                 ++i) {
                const sai_object_type_info_t *info =
                    sai_metadata_all_object_type_infos[i];
                if (info->statenum == nullptr ||
                    !object_name_matches(
                        info->objecttypename, options.object_filter)) {
                    continue;
                }
                if (supported.authoritative &&
                    !supported.is_supported(info->objecttype)) {
                    continue;
                }
                add_one(info);
            }
        }
        root.set("statistics_capabilities", std::move(stats_json));
    }

    /*
     * Generic resource availability.
     *
     * Mirror show_generic_availability: without --all or an --object filter,
     * restrict the sweep to the focused object types instead of querying
     * availability for every supported type.
     */
    {
        static const sai_object_type_t focused_types[] = {
            SAI_OBJECT_TYPE_ROUTE_ENTRY,
            SAI_OBJECT_TYPE_NEXT_HOP,
            SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
            SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
            SAI_OBJECT_TYPE_FDB_ENTRY,
            SAI_OBJECT_TYPE_ACL_ENTRY,
        };
        const bool full_scan =
            options.all || !options.object_filter.empty();

        JsonValue availability_json = JsonValue::make_array();

        auto add_one = [&](const sai_object_type_info_t *info) {
            uint64_t count = 0;
            sai_status_t status = SAI_STATUS_FAILURE;
            try {
                status = sai_object_type_get_availability(
                    requested_switch,
                    info->objecttype,
                    0,
                    nullptr,
                    &count);
            } catch (const std::exception &) {
                status = SAI_STATUS_FAILURE;
            }

            JsonValue entry = JsonValue::make_object();
            entry.set(
                "object_type",
                JsonValue::make_string(info->objecttypename));
            entry.set(
                "discriminator",
                JsonValue::make_string(""));
            entry.set(
                "status",
                JsonValue::make_string(format_status(status)));
            if (status == SAI_STATUS_SUCCESS) {
                entry.set(
                    "available",
                    JsonValue::make_uint(count));
            }
            availability_json.push(std::move(entry));
        };

        if (!full_scan) {
            for (sai_object_type_t type : focused_types) {
                const sai_object_type_info_t *info =
                    sai_metadata_get_object_type_info(type);
                if (info != nullptr) {
                    add_one(info);
                }
            }
        } else {
            for (size_t i = 1;
                 sai_metadata_all_object_type_infos[i] != nullptr;
                 ++i) {
                const sai_object_type_info_t *info =
                    sai_metadata_all_object_type_infos[i];
                if (!object_name_matches(
                        info->objecttypename, options.object_filter)) {
                    continue;
                }
                if (supported.authoritative &&
                    !supported.is_supported(info->objecttype)) {
                    continue;
                }
                add_one(info);
            }
        }
        root.set(
            "resource_availability",
            std::move(availability_json));
    }

    return root;
}

/* ------------------------------------------------------------------ */
/* service method table / profile                                      */
/* ------------------------------------------------------------------ */

struct ProfileState
{
    Transport transport = Transport::Server;
    Options options;
    bool initialized = false;
};

ProfileState *
profile_state()
{
    static ProfileState state;
    return &state;
}

/*
 * Diagnostic switches are enabled unless explicitly disabled with "0",
 * so the zero-value case (variable unset) keeps the check on.
 */
bool
env_switch_on(const char *name)
{
    const char *value = std::getenv(name);

    return value == nullptr || std::strcmp(value, "0") != 0;
}

/*
 * The ZMQ endpoint facts the transport preflight needs live in
 * zmq_endpoint.h so they can be unit tested without libsairedis, redis,
 * or an ASIC (see tests/test_zmq_endpoint.cpp).
 */
using zmqendpoint::endpoint_live;
using zmqendpoint::endpoint_owner;
using zmqendpoint::endpoint_state;
using zmqendpoint::endpoint_state_text;
using zmqendpoint::EndpointState;
using zmqendpoint::kDefaultClientEndpoints;
using zmqendpoint::kDefaultServerEndpoints;
using zmqendpoint::ZmqEndpoints;

/*
 * Single source of truth for every SAI_REDIS_KEY_* answer this process
 * gives libsairedis. Both the profile callback libsairedis sees and the
 * --debug dump go through here, so what gets printed is exactly what the
 * library received.
 *
 * The answers select the transport libsairedis uses:
 *   SAI_REDIS_KEY_ENABLE_CLIENT = "true" makes this process a sairedis
 *     CLIENT that talks to the server embedded in syncd over the ZMQ
 *     channels (from client_config.json or the built-in defaults);
 *   anything else (including nullptr) leaves libsairedis in its default
 *     server role, where operations are served through the Redis channel.
 * An environment that only serves one of these paths fails every call on
 * the other, so a wrong answer here breaks the entire report.
 *
 * SAI_CAP_ENABLE_CLIENT overrides the ENABLE_CLIENT answer for diagnosis:
 *   "true" / "false"              answer that string (force one path);
 *   "unset" / "none" / "absent"   answer nullptr, i.e. no override at all,
 *                                 exactly like the builds that predate
 *                                 client-mode support, so libsairedis
 *                                 applies its own default; this also tests
 *                                 whether the library treats a missing key
 *                                 differently from an explicit "false".
 * Any other value is ignored and the transport-derived default applies.
 */
const char *
redis_profile_answer(const ProfileState &state, const char *variable)
{
    if (variable == nullptr) {
        return nullptr;
    }

    const std::string key(variable);

    if (key == SAI_REDIS_KEY_ENABLE_CLIENT) {
        static const char *const override_env =
            std::getenv("SAI_CAP_ENABLE_CLIENT");

        if (override_env != nullptr) {
            if (std::strcmp(override_env, "true") == 0) {
                return "true";
            }
            if (std::strcmp(override_env, "false") == 0) {
                return "false";
            }
            if (std::strcmp(override_env, "unset") == 0 ||
                std::strcmp(override_env, "none") == 0 ||
                std::strcmp(override_env, "absent") == 0) {
                return nullptr;
            }
        }

        /*
         * Default to the Redis channel (server role). A stock syncd --
         * async, or -s redis_sync -- serves no ZMQ endpoint at all, so
         * the client role is dead on arrival on a normal box, while the
         * server role works against every syncd mode. The client role
         * stays opt-in (--client) for boxes running syncd -z zmq_sync,
         * where connecting beats binding because the running syncd owns
         * the endpoint.
         */
        return state.transport == Transport::Client ? "true" : "false";
    }

    if (key == SAI_REDIS_KEY_CLIENT_CONFIG) {
        return state.options.client_config.empty()
            ? nullptr
            : state.options.client_config.c_str();
    }

    if (key == SAI_REDIS_KEY_CONTEXT_CONFIG) {
        return state.options.context_config.empty()
            ? nullptr
            : state.options.context_config.c_str();
    }

    if (key == SAI_REDIS_KEY_SERVER_CONFIG) {
        return state.options.server_config.empty()
            ? nullptr
            : state.options.server_config.c_str();
    }

    return nullptr;
}

const char *
profile_get_value(
    sai_switch_profile_id_t profile_id,
    const char *variable)
{
    (void)profile_id;

    return redis_profile_answer(*profile_state(), variable);
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
        "Usage: %s [options] [switch-VID-hex]\n"
        "\n"
        "The tool talks to the running syncd over the Redis channel by\n"
        "default (the sairedis server role), which works against every\n"
        "syncd mode. On a box where syncd runs -z zmq_sync, pass --client\n"
        "to act as a sairedis ZMQ client instead.\n"
        "\n"
        "The switch VID is optional: on a single-ASIC SONiC box every switch\n"
        "exposes the same oid, so the default 0x21000000000000 is used when\n"
        "none is given. Pass an explicit VID on multi-ASIC (VoQ) boxes, where\n"
        "every asic has its own.\n"
        "\n"
        "Options:\n"
        "  --all                     Scan every metadata-known object and attribute\n"
        "  --object <name>           Scan object types matching name (for example PORT)\n"
        "  --include-unsupported     Print every failed/unsupported query\n"
        "  --probe-stats             Read-test every known stat on sample live objects\n"
        "  --allow-clear             Also probe READ_AND_CLEAR modes (mutates counters)\n"
        "  --verify-attributes       Real GET for every declared-gettable attribute\n"
        "  --format text|json        Output format (default text)\n"
        "  --list-switches           Describe the supplied switch VID (text mode only)\n"
        "  --client                  Act as a sairedis ZMQ client (needs syncd -z zmq_sync)\n"
        "  --server                  Use the Redis channel (default)\n"
        "  --client-config <file>    sairedis client_config.json\n"
        "  --context-config <file>   sairedis context_config.json\n"
        "  --server-config <file>    sairedis server_config.json\n"
        "  --timeout-ms <n>          Synchronous response timeout in milliseconds\n"
        "  --debug                   Print transport/profile diagnostics to stderr\n"
        "  -h, --help                Show this help\n"
        "\n"
        "Examples:\n"
        "  %s                          (default single-ASIC VID)\n"
        "  %s 0x21000000000000\n"
        "  %s --object PORT --include-unsupported 0x21000000000000\n"
        "  %s --all 0x21000000000000 > capabilities.txt\n"
        "  %s --probe-stats 0x21000000000000\n",
        program,
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
        } else if (argument == "--verify-attributes") {
            options.verify_attributes = true;
        } else if (argument == "--debug") {
            options.debug = true;
        } else if (argument == "--format") {
            if (!need_value(index, "--format", options.format)) {
                return false;
            }
            if (options.format != "text" && options.format != "json") {
                std::fprintf(
                    stderr,
                    "Invalid --format '%s' (expected text or json)\n",
                    options.format.c_str());
                return false;
            }
        } else if (argument.rfind("--format=", 0) == 0) {
            options.format = argument.substr(std::strlen("--format="));
            if (options.format != "text" && options.format != "json") {
                std::fprintf(
                    stderr,
                    "Invalid --format '%s' (expected text or json)\n",
                    options.format.c_str());
                return false;
            }
        } else if (argument == "--list-switches") {
            options.list_switches = true;
        } else if (argument == "--client") {
            options.client_mode = true;
        } else if (argument == "--server") {
            options.client_mode = false;
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

    /*
     * --list-switches returns early from main with a one-line
     * human-readable description and never reaches the JSON builder.
     * Silently ignoring the combination would emit a JSON document that
     * pretends to honor a flag it dropped; treat it as a usage error.
     */
    if (options.list_switches && options.format == "json") {
        std::fprintf(
            stderr,
            "--list-switches cannot be combined with --format json: the "
            "switch description is a human-readable line, not a JSON "
            "document.\n");
        return false;
    }

    if (options.show_help) {
        return true;
    }

    /*
     * The switch VID is optional. On a single-ASIC SONiC box it is always
     * kDefaultSwitchVidText (verified against ASIC_DB), so a bare invocation
     * works and nobody has to type the 16-digit oid every time; an explicit
     * VID on the command line overrides the default, which is what
     * multi-ASIC (VoQ) boxes need, since every asic has its own.
     */
    if (options.switch_vid == nullptr) {
        options.switch_vid = kDefaultSwitchVidText;
        options.switch_vid_defaulted = true;
    }

    return true;
}

bool
parse_switch_vid(const char *text, sai_object_id_t &switch_id)
{
    if (text == nullptr) {
        return false;
    }

    errno = 0;
    char *end = nullptr;
    const uint64_t parsed = std::strtoull(text, &end, 0);

    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }

    switch_id = static_cast<sai_object_id_t>(parsed);
    return true;
}

/*
 * Wall-clock timer for --debug, scoped around one libsairedis call. The
 * destructor prints the elapsed time even when the scope is left through
 * an early return or an exception, which is exactly the case where the
 * timing matters most: an instant SAI_STATUS_FAILURE means the transport
 * was refused or the library refused locally, while a long wait means the
 * request went out and the response never arrived.
 */
class DebugTimer
{
public:
    DebugTimer(const char *label, bool enabled)
        : m_label(label),
          m_enabled(enabled),
          m_start(std::chrono::steady_clock::now()) {}

    ~DebugTimer()
    {
        if (!m_enabled) {
            return;
        }
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_start)
                .count();
        std::fprintf(
            stderr,
            "debug: %s took %lld ms\n",
            m_label,
            static_cast<long long>(elapsed));
    }

private:
    const char *m_label;
    bool m_enabled;
    std::chrono::steady_clock::time_point m_start;
};

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
        options.client_mode ? Transport::Client : Transport::Server;

    /*
     * The provided VID is validated against the live switch object below. A
     * bad VID must never be reported as "the ASIC does not support this".
     */

    if (options.debug) {
        /*
         * Everything here goes to stderr unconditionally: in JSON mode
         * stdout must carry exactly one document, and in text mode the
         * diagnostics stay separable from the report.
         */
        std::fprintf(
            stderr,
            "debug: transport=%s%s\n",
            state->transport == Transport::Client ? "client" : "server",
            state->transport == Transport::Client
                ? " (SAI_REDIS_ENABLE_CLIENT=true)"
                : " (SAI_REDIS_ENABLE_CLIENT=false)");
        std::fprintf(stderr, "debug: profile answers to libsairedis:\n");
        static const char *const keys[] = {
            SAI_REDIS_KEY_ENABLE_CLIENT,
            SAI_REDIS_KEY_CLIENT_CONFIG,
            SAI_REDIS_KEY_CONTEXT_CONFIG,
            SAI_REDIS_KEY_SERVER_CONFIG,
        };
        for (const char *key : keys) {
            const char *answer = redis_profile_answer(*state, key);
            std::fprintf(
                stderr,
                "debug:   %s = %s\n",
                key,
                answer == nullptr ? "(nullptr)" : answer);
        }
    }

    /*
     * Transport preflight. The two transports have opposite expectations
     * about the ZMQ endpoints, and the failure modes are slow and silent:
     * zmq_connect to a missing (or stale) ipc:// path succeeds lazily, so
     * a client pointed at an endpoint with no server behind it waits out
     * the full 60s response timeout on every request before failing.
     * Check the filesystem first so that mistake fails in milliseconds
     * with advice.
     *
     * The server role gets no such gate on purpose: libzmq's ipc
     * listener unlinks whatever file sits at the path before binding
     * (ipc_listener_t::set_local_address), so a leftover socket never
     * blocks a bind -- it only matters that the owner of a LIVE endpoint
     * loses it, which is reported as a warning instead of an error.
     *
     * A supplied *_config.json relocates the endpoints, so the built-in
     * defaults say nothing about that setup and the check is skipped (for
     * the server role a context config can relocate them too, through
     * SAI_REDIS_COMMUNICATION_MODE_ZMQ_SYNC).
     * SAI_CAP_ZMQ_PRECHECK=0 restores the old wait-and-fail behaviour for
     * diagnosis.
     */
    const bool endpoints_relocated =
        (state->transport == Transport::Client &&
         !options.client_config.empty()) ||
        (state->transport == Transport::Server &&
         (!options.server_config.empty() || !options.context_config.empty()));

    if (env_switch_on("SAI_CAP_ZMQ_PRECHECK") && !endpoints_relocated) {
        if (state->transport == Transport::Client) {
            /*
             * Client mode CONNECTS to the sairedis server embedded in
             * syncd, so that server must be reachable at the endpoint
             * first. Find which default pair is in use instead of
             * discovering the missing one, one 60s timeout per request at
             * a time. A socket path with nothing behind it is called out
             * separately: it is a crashed syncd -z, not a missing one.
             */
            const ZmqEndpoints *server_pair = nullptr;
            const ZmqEndpoints *stale_pair = nullptr;
            for (const ZmqEndpoints &pair : kDefaultClientEndpoints) {
                if (endpoint_state(pair.main) != EndpointState::Socket) {
                    continue;
                }
                if (endpoint_live(pair.main)) {
                    server_pair = &pair;
                    break;
                }
                if (stale_pair == nullptr) {
                    stale_pair = &pair;
                }
            }

            if (server_pair == nullptr) {
                std::fprintf(
                    stderr,
                    "FATAL: client transport cannot reach syncd: no sairedis "
                    "server endpoint exists in this namespace.\n"
                    "  In client mode every request is CONNECTed to the "
                    "sairedis server embedded in\n"
                    "  syncd over ZMQ. zmq_connect succeeds even when nothing "
                    "is listening, so without\n"
                    "  the endpoint each call just waits out the full 60s "
                    "response timeout before\n"
                    "  failing. Checked the built-in defaults:\n");
                for (const ZmqEndpoints &pair : kDefaultClientEndpoints) {
                    std::fprintf(
                        stderr,
                        "    main %-20s %-12s ntf %-20s %s\n",
                        pair.main,
                        endpoint_state_text(endpoint_state(pair.main)),
                        pair.ntf,
                        endpoint_state_text(endpoint_state(pair.ntf)));
                }
                if (stale_pair != nullptr) {
                    std::fprintf(
                        stderr,
                        "  %s exists as a socket but nothing is listening on "
                        "it: a leftover from a sairedis\n"
                        "  process that died without cleanup -- a crashed "
                        "syncd -z, or an earlier run of this tool\n"
                        "  (the default server role binds this path; client "
                        "mode binds the ntf one) that was\n"
                        "  killed. Nothing can serve it now, so every request "
                        "would still wait out the 60s\n"
                        "  timeout. Remove it with: rm -f %s %s\n",
                        stale_pair->main,
                        stale_pair->main,
                        stale_pair->ntf);
                }
                std::fprintf(
                    stderr,
                    "  Either:\n"
                    "    - syncd is not serving ZMQ at all: that is the "
                    "normal case (an async syncd\n"
                    "      exposes no ZMQ endpoint). Run it in synchronous "
                    "mode (syncd -z zmq_sync) to\n"
                    "      serve this client, or\n"
                    "    - the endpoint exists but not HERE: ipc:// endpoints "
                    "are UNIX socket files\n"
                    "      living in the namespaces of the container that "
                    "created them. If syncd runs in\n"
                    "      a docker container, run this tool inside that "
                    "same container (docker exec\n"
                    "      <container> ...), share its IPC namespace, mount "
                    "the directory holding the\n"
                    "      socket, or publish the endpoint out and point the "
                    "client at it with\n"
                    "      --client-config <file>, or\n"
                    "    - drop client mode (re-run without --client) and use "
                    "the Redis channel, which\n"
                    "      works against a normal async syncd -- it is the "
                    "default (equivalently\n"
                    "      SAI_CAP_ENABLE_CLIENT=false).\n"
                    "  Set SAI_CAP_ZMQ_PRECHECK=0 to bypass this "
                    "preflight.\n");
                return 1;
            }

            /*
             * The main endpoint the client connects to is live. This
             * process also BINDS the notification endpoint, and libzmq
             * unlinks whatever file is there before binding, so an
             * existing one is not fatal -- but if a live sairedis client
             * of another instance sits behind it, that instance stops
             * receiving notifications, which is worth knowing up front.
             */
            const EndpointState ntf_state = endpoint_state(server_pair->ntf);
            if (ntf_state != EndpointState::Missing) {
                const std::string ntf_owner =
                    ntf_state == EndpointState::Socket
                        ? endpoint_owner(server_pair->ntf)
                        : std::string();
                const std::string ntf_note =
                    ntf_owner.empty()
                        ? std::string()
                        : " (held by " + ntf_owner + ")";
                std::fprintf(
                    stderr,
                    "WARNING: notification endpoint %s already exists%s; this "
                    "process binds it, so the previous\n"
                    "  owner stops receiving notifications. Remove the file "
                    "or relocate the endpoint with\n"
                    "  --client-config <file> if that matters.\n",
                    server_pair->ntf,
                    ntf_note.c_str());
            }

            if (options.debug) {
                std::fprintf(
                    stderr,
                    "debug: client endpoints: main=%s (connect), ntf=%s "
                    "(bind)\n",
                    server_pair->main,
                    server_pair->ntf);
            }
        } else {
            /*
             * Server mode BINDS the endpoint. A missing path is the normal
             * case -- it is how every build that talks to syncd over the
             * Redis channel has always worked -- and an existing one is
             * NOT fatal either: libzmq unlinks the file before binding
             * (ipc_listener_t::set_local_address), so the bind succeeds
             * regardless. What is worth reporting is who loses the
             * endpoint: if a live sairedis server owns it, that server
             * becomes unreachable and this process answers instead.
             */
            const EndpointState main_state =
                endpoint_state(kDefaultServerEndpoints.main);

            if (main_state != EndpointState::Missing) {
                const std::string owner =
                    main_state == EndpointState::Socket
                        ? endpoint_owner(kDefaultServerEndpoints.main)
                        : std::string();
                const std::string owner_note =
                    owner.empty() ? std::string()
                                  : " (held by " + owner + ")";

                if (main_state == EndpointState::Socket &&
                    endpoint_live(kDefaultServerEndpoints.main)) {
                    std::fprintf(
                        stderr,
                        "WARNING: server mode is about to bind %s, but a "
                        "sairedis server is already listening there%s.\n"
                        "  libzmq unlinks the file and binds anyway, so this "
                        "run continues -- but the running server loses its\n"
                        "  endpoint and THIS process answers requests from "
                        "then on. If that server is syncd -z zmq_sync,\n"
                        "  re-run with --client instead so the request "
                        "reaches the server that is already listening.\n"
                        "  Move the endpoint with --server-config <file>, or "
                        "relocate it via --context-config\n"
                        "  (SAI_REDIS_COMMUNICATION_MODE_ZMQ_SYNC). Remove "
                        "the leftover with: rm -f %s %s\n",
                        kDefaultServerEndpoints.main,
                        owner_note.c_str(),
                        kDefaultServerEndpoints.main,
                        kDefaultServerEndpoints.ntf);
                } else {
                    std::fprintf(
                        stderr,
                        "WARNING: server mode will bind %s, which already "
                        "exists as %s%s.\n"
                        "  libzmq unlinks it before binding, so the run "
                        "continues normally. A leftover socket file usually\n"
                        "  means an earlier sairedis process (possibly an "
                        "earlier run of this tool) was killed before it\n"
                        "  could clean up. Remove the leftover with: "
                        "rm -f %s %s\n",
                        kDefaultServerEndpoints.main,
                        endpoint_state_text(main_state),
                        owner_note.c_str(),
                        kDefaultServerEndpoints.main,
                        kDefaultServerEndpoints.ntf);
                }
            }

            if (options.debug) {
                std::fprintf(
                    stderr,
                    "debug: server endpoints: main=%s (bind), ntf=%s "
                    "(bind)\n",
                    kDefaultServerEndpoints.main,
                    kDefaultServerEndpoints.ntf);
            }
        }
    }

    sai_service_method_table_t services{};
    services.profile_get_value = profile_get_value;
    services.profile_get_next_value = profile_get_next_value;

    sai_status_t status = SAI_STATUS_FAILURE;
    try {
        DebugTimer timer("sai_api_initialize", options.debug);
        status = sai_api_initialize(0, &services);
    } catch (const std::exception &exception) {
        std::fprintf(
            stderr,
            "sai_api_initialize threw: %s\n",
            exception.what());
        std::fprintf(
            stderr,
            "Hint: if syncd is running with -z zmq_sync, pass --client; "
            "this tool defaults to the Redis channel.\n");
        return 1;
    }

    if (status != SAI_STATUS_SUCCESS) {
        std::fprintf(
            stderr,
            "sai_api_initialize failed: %s\n",
            format_status(status).c_str());
        return 1;
    }

    const bool json_output = options.format == "json";

    /* In JSON mode all human-readable preamble goes to stderr, so stdout
     * carries exactly one JSON document and nothing else. */
    FILE *const banner = json_output ? stderr : stdout;
    std::fprintf(
        banner,
        "Switch VID: 0x%" PRIx64 "%s\n",
        static_cast<uint64_t>(requested_switch),
        options.switch_vid_defaulted ? " (default)" : "");
    std::fprintf(
        banner,
        "Transport: %s\n",
        state->transport == Transport::Client
            ? "client (connect to running syncd)"
            : "server (Redis channel through this process)");

    std::fprintf(banner, "\n=== Version context ===\n");
    std::fprintf(
        banner,
        "Compiled SAI headers: %s\n",
        format_api_version(SAI_API_VERSION).c_str());
    std::fprintf(
        banner,
        "Linked metadata:      %s\n",
        format_api_version(
            sai_metadata_query_api_version()).c_str());
    std::fprintf(
        banner,
        "NOTE: 'Linked metadata' is what libsaimetadata was compiled with; it "
        "reflects the tool build, not the adapter's own metadata. Vendor\n"
        "      private attributes absent from these headers cannot appear in "
        "this report.\n");

    sai_api_version_t queried_version = 0;
    try {
        DebugTimer timer("sai_query_api_version", options.debug);
        status = sai_query_api_version(&queried_version);
    } catch (const std::exception &) {
        status = SAI_STATUS_FAILURE;
    }
    std::fprintf(
        banner,
        "Advisory query:       status=%s",
        format_status(status).c_str());
    if (status == SAI_STATUS_SUCCESS) {
        std::fprintf(
            banner,
            " version=%s",
            format_api_version(queried_version).c_str());
    }
    std::fprintf(banner, "\n");
    std::fprintf(
        banner,
        "NOTE: sairedis answers this with its own client-header version, so it "
        "is advisory only and does not identify the remote vendor libsai.\n");

    if (!json_output) {
        print_metadata_inventory();
    }

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
     * Probe the switch VID with one live GET before running any capability
     * query. The probe is a diagnostic, not a gate: see
     * cap::classify_switch_probe for why only SAI_STATUS_INVALID_OBJECT_ID
     * refuses the run. A structurally invalid oid makes every capability
     * query fail the same way, so the report would be a page of false
     * negatives; an object merely absent from the ASIC view does not,
     * because the adapter answers the capability queries itself.
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
        std::string probe_exception;
        try {
            DebugTimer timer("switch VID validation GET", options.debug);
            status = switch_api->get_switch_attribute(
                requested_switch, 1, &attribute);
        } catch (const std::exception &exception) {
            /*
             * libsairedis throws on malformed/unexpected responses. That
             * says the transport misbehaved, not that the VID is wrong,
             * so it must not abort the report either.
             */
            probe_exception = exception.what();
        }

        const SwitchProbeVerdict probe_verdict =
            probe_exception.empty()
                ? classify_switch_probe(status)
                : SwitchProbeVerdict::Environmental;

        char oid_text[32];
        std::snprintf(
            oid_text,
            sizeof(oid_text),
            "0x%" PRIx64,
            static_cast<uint64_t>(requested_switch));

        switch (probe_verdict) {
            case SwitchProbeVerdict::Ok:
                std::fprintf(
                    banner,
                    "\nSwitch VID validation: OK "
                    "(SAI_SWITCH_ATTR_TYPE=%s)\n",
                    format_enum_value(
                        type_metadata->enummetadata,
                        attribute.value.s32).c_str());
                break;

            case SwitchProbeVerdict::InvalidOid:
                std::fprintf(
                    stderr,
                    "\nFATAL: switch VID %s is not a valid live "
                    "switch: %s\n"
                    "Refusing to run capability queries, because every answer "
                    "would be a false negative.\n"
                    "Check the VID against ASIC_DB / syncd, and make sure the "
                    "context config matches.\n",
                    oid_text,
                    format_status(status).c_str());
                std::fprintf(
                    stderr,
                    "Triage on the switch:\n"
                    "  is the VID in the view? redis-cli -n 1 HGETALL "
                    "\"ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:oid:%s\"\n"
                    "                          (ASIC_DB is database 1; view "
                    "entries are per-object\n"
                    "                           hashes under ASIC_STATE:; with "
                    "syncd -u they may sit in\n"
                    "                           TEMP_ASIC_STATE: until "
                    "APPLY_VIEW)\n"
                    "  which switches exist?  redis-cli -n 1 --scan --pattern "
                    "'ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*'\n"
                    "  syncd serving ZMQ?      ps -o args= -C syncd   (-z zmq_sync "
                    "is needed only by the opt-in client\n"
                    "                          role, --client; -s is the "
                    "deprecated redis_sync alias; the default Redis\n"
                    "                          channel works against any syncd "
                    "mode)\n"
                    "  client endpoints?       ls -l /tmp/saiServer "
                    "/tmp/saiServerNtf /tmp/zmq_ep /tmp/zmq_ntf_ep\n",
                    oid_text);
                if (options.switch_vid_defaulted) {
                    std::fprintf(
                        stderr,
                        "NOTE: this run used the built-in default single-ASIC "
                        "VID 0x21000000000000;\n"
                        "      on a multi-ASIC (VoQ) box pass the real switch "
                        "VID explicitly.\n");
                }
                if (options.debug) {
                    std::fprintf(
                        stderr,
                        "debug: transport at failure=%s; rerun with "
                        "SAI_CAP_ENABLE_CLIENT=false|true|unset to bisect the "
                        "transport\n",
                        state->transport == Transport::Client ? "client"
                                                              : "server");
                }
                sai_api_uninitialize();
                return 3;

            case SwitchProbeVerdict::Environmental:
                /*
                 * The switch object is absent from the ASIC view this
                 * process reaches (or the probe GET threw). The report
                 * continues: capability queries are answered by the
                 * adapter itself, and live switch-object reads failing is
                 * visible in the report, not hidden behind an exit code.
                 */
                if (!probe_exception.empty()) {
                    std::fprintf(
                        banner,
                        "\nWARNING: switch VID validation GET threw: %s\n",
                        probe_exception.c_str());
                } else {
                    std::fprintf(
                        banner,
                        "\nWARNING: switch VID %s did not answer "
                        "SAI_SWITCH_ATTR_TYPE: %s\n",
                        oid_text,
                        format_status(status).c_str());
                }
                std::fprintf(
                    banner,
                    "  The report continues: the capability queries below are "
                    "answered by the adapter itself and are unaffected, but "
                    "live reads of the switch object may all fail the same "
                    "way.\n"
                    "  Check the VID against ASIC_DB / syncd, and make sure "
                    "the context config matches.\n"
                    "  is the VID in the view? redis-cli -n 1 HGETALL "
                    "\"ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:oid:%s\"\n"
                    "                        (with syncd -u the view entries "
                    "may sit in TEMP_ASIC_STATE:\n"
                    "                         until APPLY_VIEW)\n"
                    "  which switches exist? redis-cli -n 1 --scan --pattern "
                    "'ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*'\n",
                    oid_text);
                if (options.switch_vid_defaulted) {
                    std::fprintf(
                        banner,
                        "  NOTE: this run used the built-in default "
                        "single-ASIC VID 0x21000000000000;\n"
                        "        on a multi-ASIC (VoQ) box pass the real "
                        "switch VID explicitly.\n");
                }
                if (options.debug) {
                    std::fprintf(
                        banner,
                        "  debug: transport at failure=%s; rerun with "
                        "SAI_CAP_ENABLE_CLIENT=false|true|unset to bisect "
                        "the transport\n",
                        state->transport == Transport::Client ? "client"
                                                              : "server");
                }
                break;
        }
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

            std::fprintf(
                banner,
                "Sync timeout: %s (requested %" PRIu64 " ms)\n",
                format_status(timeout_status).c_str(),
                options.response_timeout_ms);
        } else {
            std::fprintf(
                banner,
                "Sync timeout: NOT APPLIED (--timeout-ms=%" PRIu64 "). "
                "libsairedis rejects extension attributes in client mode; "
                "use the default 60s timeout or drop --client.\n",
                options.response_timeout_ms);
        }
    }

    const SupportedObjectTypesQuery supported_query =
        query_supported_object_types(requested_switch, switch_api);

    if (json_output) {
        /*
         * JSON mode emits exactly one document on stdout. The live probe and
         * attribute verification are documented limitations of this mode
         * because they emit per-counter line output; run text mode for those.
         */
        StatsCapabilityCache json_stats_cache(requested_switch);
        const JsonValue report = build_json_report(
            options,
            requested_switch,
            state->transport,
            supported_query,
            switch_api,
            json_stats_cache);
        if (options.probe_stats || options.verify_attributes) {
            std::fprintf(
                stderr,
                "WARNING: --probe-stats and --verify-attributes produce "
                "line-oriented output and are not included in --format json. "
                "Run text mode for those.\n");
        }
        if (options.include_unsupported) {
            std::fprintf(
                stderr,
                "WARNING: --include-unsupported does not filter the JSON "
                "sweeps; every attribute of every scanned type is reported "
                "with its status, and the flag is only echoed in the options "
                "section. Run text mode for the filtered view.\n");
        }
        const std::string document = report.dump();
        std::fwrite(
            document.data(), 1, document.size(), stdout);
        sai_api_uninitialize();
        return 0;
    }

    print_supported_object_types(supported_query);
    const SupportedObjectTypes &supported = supported_query.supported;

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

    if (options.verify_attributes) {
        verify_attribute_capabilities(
            requested_switch,
            switch_api,
            options.include_unsupported);
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
