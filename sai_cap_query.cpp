extern "C" {
#include <sai.h>
#include <saimetadatatypes.h>
#include <saimetadatautils.h>

extern const sai_object_type_info_t *const sai_metadata_all_object_type_infos[];
}

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <map>
#include <string>
#include <vector>

/*
 * These C++ helpers are exported by libsaimeta.  Keeping the declarations
 * local avoids depending on sairedis' private source-tree include path.
 */
std::string sai_serialize_attr_value(
    const sai_attr_metadata_t &meta,
    const sai_attribute_t &attr,
    bool count_only);

std::string sai_serialize_status(sai_status_t status);

namespace {

constexpr uint32_t kInitialListCapacity = 64;
constexpr uint32_t kMaximumListCapacity = 1024 * 1024;

struct Options
{
    bool all = false;
    bool include_unsupported = false;
    bool probe_stats = false;
    bool show_help = false;
    std::string object_filter;
    const char *switch_vid = nullptr;
};

struct AttributeStorage
{
    std::vector<sai_object_id_t> object_ids;
    std::vector<uint8_t> u8_values;
    std::vector<int8_t> s8_values;
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
};

using AttributeGetter = std::function<sai_status_t(sai_attribute_t *)>;
using StatsGetter = std::function<sai_status_t(
    sai_object_id_t,
    uint32_t,
    const sai_stat_id_t *,
    uint64_t *)>;

static const char *
profile_get_value(
    sai_switch_profile_id_t profile_id,
    const char *variable)
{
    (void)profile_id;
    (void)variable;
    return nullptr;
}

static int
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

static void
print_usage(const char *program)
{
    std::fprintf(
        stderr,
        "Usage: %s [options] <switch-VID-hex>\n"
        "\n"
        "Options:\n"
        "  --all                  Scan every metadata-known object and attribute\n"
        "  --object <name>        Scan object types matching name (for example PORT)\n"
        "  --include-unsupported  Print every failed/unsupported full-scan query\n"
        "  --probe-stats          Read-test every known stat on sample live objects\n"
        "  -h, --help             Show this help\n"
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

static bool
parse_options(int argc, char **argv, Options &options)
{
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
        } else if (argument == "--object") {
            if (++index >= argc) {
                std::fprintf(stderr, "--object requires a value\n");
                return false;
            }
            options.object_filter = argv[index];
        } else if (argument.rfind("--object=", 0) == 0) {
            options.object_filter = argument.substr(std::strlen("--object="));
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

    return options.show_help || options.switch_vid != nullptr;
}

static std::string
format_status(sai_status_t status)
{
    try {
        return sai_serialize_status(status) +
            " (" + std::to_string(status) + ")";
    } catch (const std::exception &) {
        return std::to_string(status);
    }
}

static std::string
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

static std::string
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

static bool
matches_object_filter(
    const sai_object_type_info_t *info,
    const std::string &filter)
{
    if (filter.empty()) {
        return true;
    }

    return to_upper(info->objecttypename).find(to_upper(filter)) !=
        std::string::npos;
}

static std::string
classify_unknown_value(int32_t value)
{
    const uint32_t raw = static_cast<uint32_t>(value);

    if (raw >= 0x20000000u && raw < 0x30000000u) {
        return "UNKNOWN_EXTENSION_VALUE";
    }

    if (raw >= 0x10000000u && raw < 0x20000000u) {
        return "UNKNOWN_VENDOR_CUSTOM_VALUE";
    }

    return "UNKNOWN_VALUE";
}

static std::string
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

static std::string
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

    return result.empty() ? "NONE" : result;
}

static std::string
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

static std::string
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

static bool
is_buffered_value_type(sai_attr_value_type_t type)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_OBJECT_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT8_LIST:
        case SAI_ATTR_VALUE_TYPE_INT8_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        case SAI_ATTR_VALUE_TYPE_INT32_LIST:
        case SAI_ATTR_VALUE_TYPE_UINT16_RANGE_LIST:
        case SAI_ATTR_VALUE_TYPE_VLAN_LIST:
        case SAI_ATTR_VALUE_TYPE_QOS_MAP_LIST:
        case SAI_ATTR_VALUE_TYPE_ACL_CAPABILITY:
        case SAI_ATTR_VALUE_TYPE_ACL_RESOURCE_LIST:
        case SAI_ATTR_VALUE_TYPE_IP_ADDRESS_LIST:
        case SAI_ATTR_VALUE_TYPE_SYSTEM_PORT_CONFIG_LIST:
        case SAI_ATTR_VALUE_TYPE_JSON:
        case SAI_ATTR_VALUE_TYPE_IP_PREFIX_LIST:
        case SAI_ATTR_VALUE_TYPE_ACL_CHAIN_LIST:
            return true;

        default:
            return false;
    }
}

static bool
can_fetch_value_type(sai_attr_value_type_t type)
{
    switch (type) {
        case SAI_ATTR_VALUE_TYPE_POINTER:
        case SAI_ATTR_VALUE_TYPE_UINT16_LIST:
        case SAI_ATTR_VALUE_TYPE_INT16_LIST:
        case SAI_ATTR_VALUE_TYPE_MAP_LIST:
        case SAI_ATTR_VALUE_TYPE_TLV_LIST:
        case SAI_ATTR_VALUE_TYPE_SEGMENT_LIST:
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

static uint32_t
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

static bool
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

static size_t
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

static sai_status_t
fetch_attribute(
    const sai_attr_metadata_t *metadata,
    const AttributeGetter &getter,
    sai_attribute_t &attribute,
    AttributeStorage &storage,
    std::string &error)
{
    attribute = {};
    attribute.id = metadata->attrid;

    if (!can_fetch_value_type(metadata->attrvaluetype)) {
        error = "value type is intentionally skipped";
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (is_buffered_value_type(metadata->attrvaluetype) &&
        !bind_attribute_buffer(
            metadata->attrvaluetype,
            kInitialListCapacity,
            attribute,
            storage)) {
        error = "unable to allocate initial list buffer";
        return SAI_STATUS_NO_MEMORY;
    }

    sai_status_t status = getter(&attribute);

    for (unsigned int attempt = 0;
         status == SAI_STATUS_BUFFER_OVERFLOW && attempt < 4;
         ++attempt) {
        uint32_t required =
            get_buffer_count(metadata->attrvaluetype, attribute);
        const size_t current =
            current_buffer_capacity(metadata->attrvaluetype, storage);

        if (current == 0) {
            error = "BUFFER_OVERFLOW on a non-list value";
            return status;
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
            error =
                "reported list size " + std::to_string(required) +
                " exceeds safety limit";
            return SAI_STATUS_NO_MEMORY;
        }

        status = getter(&attribute);
    }

    return status;
}

static std::string
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

static const sai_attr_metadata_t *
find_attribute(const char *name)
{
    return sai_metadata_get_attr_metadata_by_attr_id_name(name);
}

static void
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

static std::vector<int32_t>
query_supported_object_types(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api)
{
    std::vector<int32_t> supported;
    const sai_attr_metadata_t *metadata =
        find_attribute("SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST");

    std::printf("\n=== Supported object types ===\n");

    if (metadata == nullptr) {
        std::printf("Metadata does not contain SUPPORTED_OBJECT_TYPE_LIST\n");
        return supported;
    }

    sai_attribute_t attribute{};
    AttributeStorage storage;
    std::string error;

    const sai_status_t status = fetch_attribute(
        metadata,
        [switch_api, switch_id](sai_attribute_t *value) {
            return switch_api->get_switch_attribute(
                switch_id,
                1,
                value);
        },
        attribute,
        storage,
        error);

    std::printf("status=%s", format_status(status).c_str());
    if (!error.empty()) {
        std::printf(" detail=%s", error.c_str());
    }
    std::printf("\n");

    if (status != SAI_STATUS_SUCCESS) {
        std::printf(
            "The adapter did not expose an authoritative object list; "
            "full scans will still try metadata-known objects.\n");
        return supported;
    }

    supported.assign(
        attribute.value.s32list.list,
        attribute.value.s32list.list + attribute.value.s32list.count);

    for (size_t index = 0; index < supported.size(); ++index) {
        const int32_t raw = supported[index];
        const sai_object_type_info_t *info =
            sai_metadata_get_object_type_info(
                static_cast<sai_object_type_t>(raw));

        if (info != nullptr) {
            std::printf(
                "  [%zu] %s (%d/0x%08" PRIx32 ")%s\n",
                index,
                info->objecttypename,
                raw,
                static_cast<uint32_t>(raw),
                format_object_tags(info).c_str());
        } else {
            std::printf(
                "  [%zu] %s (%d/0x%08" PRIx32 ")\n",
                index,
                classify_unknown_value(raw).c_str(),
                raw,
                static_cast<uint32_t>(raw));
        }
    }

    return supported;
}

static void
show_switch_attributes(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    const std::vector<const sai_attr_metadata_t *> &attributes,
    bool include_failures)
{
    std::map<sai_status_t, size_t> failures;
    size_t skipped = 0;

    for (const sai_attr_metadata_t *metadata : attributes) {
        if (metadata == nullptr) {
            ++skipped;
            continue;
        }

        sai_attribute_t attribute{};
        AttributeStorage storage;
        std::string error;

        const sai_status_t status = fetch_attribute(
            metadata,
            [switch_api, switch_id](sai_attribute_t *value) {
                return switch_api->get_switch_attribute(
                    switch_id,
                    1,
                    value);
            },
            attribute,
            storage,
            error);

        if (status == SAI_STATUS_SUCCESS) {
            std::printf(
                "%-68s value=%s%s\n",
                metadata->attridname,
                serialize_attribute(metadata, attribute).c_str(),
                format_attribute_tags(metadata).c_str());
            continue;
        }

        ++failures[status];
        if (include_failures) {
            std::printf(
                "%-68s status=%s",
                metadata->attridname,
                format_status(status).c_str());
            if (!error.empty()) {
                std::printf(" detail=%s", error.c_str());
            }
            std::printf("%s\n", format_attribute_tags(metadata).c_str());
        }
    }

    if (!failures.empty() || skipped != 0) {
        std::printf("  unavailable summary:");
        for (const auto &entry : failures) {
            std::printf(
                " %s=%zu",
                format_status(entry.first).c_str(),
                entry.second);
        }
        if (skipped != 0) {
            std::printf(" metadata_missing=%zu", skipped);
        }
        std::printf("\n");
    }
}

static std::vector<const sai_attr_metadata_t *>
metadata_for_names(const char *const *names, size_t count)
{
    std::vector<const sai_attr_metadata_t *> result;
    result.reserve(count);

    for (size_t index = 0; index < count; ++index) {
        result.push_back(find_attribute(names[index]));
    }

    return result;
}

static void
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

static void
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
        const sai_attr_metadata_t *metadata =
            info->attrmetadata[index];
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

struct EnumCapabilityResult
{
    sai_status_t status = SAI_STATUS_FAILURE;
    std::vector<int32_t> values;
    uint32_t required_count = 0;
};

static EnumCapabilityResult
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

        result.status =
            sai_query_attribute_enum_values_capability(
                switch_id,
                metadata->objecttype,
                metadata->attrid,
                &values);
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

static void
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
        std::printf(" count=%zu\n", result.values.size());
        for (size_t index = 0; index < result.values.size(); ++index) {
            std::printf(
                "%s  [%zu] %s\n",
                indent,
                index,
                format_enum_value(
                    metadata->enummetadata,
                    result.values[index]).c_str());
        }
    } else if (result.status == SAI_STATUS_BUFFER_OVERFLOW) {
        std::printf(" required_count=%u\n", result.required_count);
    } else {
        std::printf("\n");
    }
}

static sai_status_t
show_attribute_capability(
    sai_object_id_t switch_id,
    const sai_attr_metadata_t *metadata,
    bool show_enum,
    bool include_enum_failure,
    const char *indent)
{
    sai_attr_capability_t capability{};
    const sai_status_t status =
        sai_query_attribute_capability(
            switch_id,
            metadata->objecttype,
            metadata->attrid,
            &capability);

    std::printf(
        "%s%-66s status=%s",
        indent,
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

    if (show_enum &&
        (metadata->isenum || metadata->isenumlist) &&
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

static void
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

    for (const char *name : names) {
        const sai_attr_metadata_t *metadata = find_attribute(name);
        if (metadata == nullptr) {
            std::printf("%-66s metadata=missing\n", name);
            continue;
        }

        show_attribute_capability(
            switch_id,
            metadata,
            true,
            true,
            "");
    }
}

static void
show_all_attribute_capabilities(
    sai_object_id_t switch_id,
    const std::string &object_filter,
    bool include_unsupported)
{
    std::map<sai_status_t, size_t> statuses;
    size_t queried = 0;
    size_t matched_objects = 0;

    std::printf("\n=== Full attribute capability scan ===\n");

    for (size_t object_index = 1;
         sai_metadata_all_object_type_infos[object_index] != nullptr;
         ++object_index) {
        const sai_object_type_info_t *info =
            sai_metadata_all_object_type_infos[object_index];

        if (!matches_object_filter(info, object_filter)) {
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

            const sai_status_t status =
                sai_query_attribute_capability(
                    switch_id,
                    metadata->objecttype,
                    metadata->attrid,
                    &capability);

            ++queried;
            ++statuses[status];

            if (status != SAI_STATUS_SUCCESS &&
                !include_unsupported) {
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
            }

            std::printf(
                "%s\n",
                format_attribute_tags(metadata).c_str());

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

    if (matched_objects == 0) {
        std::printf(
            "No metadata object type matched filter '%s'\n",
            object_filter.c_str());
    }

    std::printf(
        "\nAttribute scan summary: objects=%zu attributes=%zu",
        matched_objects,
        queried);
    for (const auto &entry : statuses) {
        std::printf(
            " %s=%zu",
            format_status(entry.first).c_str(),
            entry.second);
    }
    std::printf("\n");
}

struct StatsCapabilityResult
{
    sai_status_t status = SAI_STATUS_FAILURE;
    std::vector<sai_stat_capability_t> values;
    uint32_t required_count = 0;
};

static StatsCapabilityResult
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

        result.status =
            sai_query_stats_capability(
                switch_id,
                info->objecttype,
                &list);
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

static void
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

static void
show_stats_capabilities(
    sai_object_id_t switch_id,
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
                print_stats_capability(
                    info,
                    query_stats_capability(switch_id, info));
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

        const StatsCapabilityResult result =
            query_stats_capability(switch_id, info);
        if (result.status == SAI_STATUS_SUCCESS ||
            include_unsupported) {
            print_stats_capability(info, result);
        }
    }
}

static void
show_generic_availability(
    sai_object_id_t switch_id,
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

    auto print_one = [switch_id](
                         const sai_object_type_info_t *info,
                         bool print_failure) {
        uint64_t count = 0;
        const sai_status_t status =
            sai_object_type_get_availability(
                switch_id,
                info->objecttype,
                0,
                nullptr,
                &count);

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
            all_not_implemented &=
                print_one(info, true) == SAI_STATUS_NOT_IMPLEMENTED;
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
        print_one(info, include_unsupported);
    }
}

static void
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

static bool
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
    std::string error;

    status = fetch_attribute(
        metadata,
        getter,
        attribute,
        storage,
        error);

    if (status != SAI_STATUS_SUCCESS) {
        return false;
    }

    objects.assign(
        attribute.value.objlist.list,
        attribute.value.objlist.list + attribute.value.objlist.count);
    return true;
}

static bool
is_stat_marker_name(const char *name)
{
    const std::string value(name == nullptr ? "" : name);
    return value.find("_CUSTOM_RANGE_") != std::string::npos ||
        value.find("_EXTENSIONS_RANGE_") != std::string::npos ||
        (value.size() >= 6 &&
         value.compare(value.size() - 6, 6, "_START") == 0) ||
        (value.size() >= 4 &&
         value.compare(value.size() - 4, 4, "_END") == 0);
}

static void
probe_stats_on_object(
    const sai_object_type_info_t *info,
    sai_object_id_t object_id,
    const StatsGetter &getter,
    bool include_failures)
{
    std::map<sai_status_t, size_t> failures;
    size_t success_count = 0;

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
        const sai_status_t status =
            getter(object_id, 1, &stat, &value);

        if (status == SAI_STATUS_SUCCESS) {
            ++success_count;
            std::printf(
                "  %-72s sample_value=%" PRIu64 "\n",
                format_enum_value(info->statenum, raw).c_str(),
                value);
        } else {
            ++failures[status];
            if (include_failures) {
                std::printf(
                    "  %-72s status=%s\n",
                    format_enum_value(info->statenum, raw).c_str(),
                    format_status(status).c_str());
            }
        }
    }

    std::printf("  probe summary: accepted=%zu", success_count);
    for (const auto &entry : failures) {
        std::printf(
            " %s=%zu",
            format_status(entry.first).c_str(),
            entry.second);
    }
    std::printf("\n");
}

static void
probe_live_stats(
    sai_object_id_t switch_id,
    const sai_switch_api_t *switch_api,
    bool include_failures)
{
    std::printf("\n=== Active read-only statistics probe ===\n");
    std::printf(
        "This fallback never uses READ_AND_CLEAR, but it performs one SAI "
        "read per metadata-known counter.\n");

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

    void *api_table = nullptr;
    status = sai_api_query(SAI_API_PORT, &api_table);
    if (status != SAI_STATUS_SUCCESS || api_table == nullptr) {
        std::printf(
            "sai_api_query(PORT) failed: %s\n",
            format_status(status).c_str());
        return;
    }
    const auto *port_api =
        static_cast<const sai_port_api_t *>(api_table);

    const sai_object_type_info_t *port_info =
        sai_metadata_get_object_type_info(SAI_OBJECT_TYPE_PORT);
    if (port_info != nullptr && port_info->statenum != nullptr) {
        probe_stats_on_object(
            port_info,
            ports.front(),
            [port_api](
                sai_object_id_t object_id,
                uint32_t count,
                const sai_stat_id_t *ids,
                uint64_t *values) {
                return port_api->get_port_stats(
                    object_id,
                    count,
                    ids,
                    values);
            },
            include_failures);
    }

    std::vector<sai_object_id_t> queues;
    const sai_attr_metadata_t *queue_list_metadata =
        find_attribute("SAI_PORT_ATTR_QOS_QUEUE_LIST");
    get_object_list(
        queue_list_metadata,
        [port_api, port_id = ports.front()](
            sai_attribute_t *attribute) {
            return port_api->get_port_attribute(
                port_id,
                1,
                attribute);
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
                sai_metadata_get_object_type_info(
                    SAI_OBJECT_TYPE_QUEUE);
            if (queue_info != nullptr &&
                queue_info->statenum != nullptr) {
                probe_stats_on_object(
                    queue_info,
                    queues.front(),
                    [queue_api](
                        sai_object_id_t object_id,
                        uint32_t count,
                        const sai_stat_id_t *ids,
                        uint64_t *values) {
                        return queue_api->get_queue_stats(
                            object_id,
                            count,
                            ids,
                            values);
                    },
                    include_failures);
            }
        }
    } else {
        std::printf(
            "Cannot obtain a sample queue from port 0x%" PRIx64 ": %s\n",
            static_cast<uint64_t>(ports.front()),
            format_status(status).c_str());
    }

    std::vector<sai_object_id_t> priority_groups;
    const sai_attr_metadata_t *ipg_list_metadata =
        find_attribute("SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST");
    get_object_list(
        ipg_list_metadata,
        [port_api, port_id = ports.front()](
            sai_attribute_t *attribute) {
            return port_api->get_port_attribute(
                port_id,
                1,
                attribute);
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
            if (ipg_info != nullptr &&
                ipg_info->statenum != nullptr) {
                probe_stats_on_object(
                    ipg_info,
                    priority_groups.front(),
                    [buffer_api](
                        sai_object_id_t object_id,
                        uint32_t count,
                        const sai_stat_id_t *ids,
                        uint64_t *values) {
                        return buffer_api->
                            get_ingress_priority_group_stats(
                                object_id,
                                count,
                                ids,
                                values);
                    },
                    include_failures);
            }
        }
    } else {
        std::printf(
            "Cannot obtain a sample ingress priority group from port "
            "0x%" PRIx64 ": %s\n",
            static_cast<uint64_t>(ports.front()),
            format_status(status).c_str());
    }
}

} // namespace

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

    errno = 0;
    char *end = nullptr;
    const uint64_t parsed =
        std::strtoull(options.switch_vid, &end, 0);

    if (errno != 0 ||
        end == options.switch_vid ||
        *end != '\0') {
        std::fprintf(
            stderr,
            "Invalid switch VID: %s\n",
            options.switch_vid);
        return 2;
    }

    const sai_object_id_t switch_id =
        static_cast<sai_object_id_t>(parsed);

    sai_service_method_table_t services{};
    services.profile_get_value = profile_get_value;
    services.profile_get_next_value = profile_get_next_value;

    /*
     * Because this executable links to libsairedis, this initializes the
     * Redis SAI client, not a second vendor SDK/hardware context.
     */
    sai_status_t status =
        sai_api_initialize(0, &services);

    if (status != SAI_STATUS_SUCCESS) {
        std::fprintf(
            stderr,
            "sai_api_initialize failed: %s\n",
            format_status(status).c_str());
        return 1;
    }

    std::printf(
        "Switch VID: 0x%" PRIx64 "\n",
        static_cast<uint64_t>(switch_id));
    std::printf(
        "WARNING: libsairedis uses a shared synchronous response queue. "
        "Run this tool only in a lab/maintenance window without another "
        "SAI Redis client issuing synchronous requests.\n");

    std::printf("\n=== Version context ===\n");
    std::printf(
        "Compiled SAI headers: %s\n",
        format_api_version(SAI_API_VERSION).c_str());
    std::printf(
        "Linked metadata:      %s\n",
        format_api_version(
            sai_metadata_query_api_version()).c_str());

    sai_api_version_t queried_version = 0;
    status = sai_query_api_version(&queried_version);
    std::printf(
        "libsairedis query:    status=%s",
        format_status(status).c_str());
    if (status == SAI_STATUS_SUCCESS) {
        std::printf(
            " version=%s",
            format_api_version(queried_version).c_str());
    }
    std::printf("\n");
    std::printf(
        "Important: libsairedis currently reports its client-header version "
        "here, not the remote vendor libsai version.\n");
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
    const auto *switch_api =
        static_cast<const sai_switch_api_t *>(api_table);

    query_supported_object_types(switch_id, switch_api);

    show_switch_summary(
        switch_id,
        switch_api,
        options.include_unsupported);

    if (options.all) {
        show_all_read_only_switch_attributes(
            switch_id,
            switch_api,
            options.include_unsupported);
    }

    if (options.all || !options.object_filter.empty()) {
        show_all_attribute_capabilities(
            switch_id,
            options.object_filter,
            options.include_unsupported);
    } else {
        show_focused_capabilities(switch_id);
    }

    show_stats_capabilities(
        switch_id,
        options.all,
        options.object_filter,
        options.include_unsupported);

    show_generic_availability(
        switch_id,
        options.all,
        options.object_filter,
        options.include_unsupported);

    show_legacy_resource_attributes(
        switch_id,
        switch_api,
        options.include_unsupported);

    if (options.probe_stats) {
        probe_live_stats(
            switch_id,
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
