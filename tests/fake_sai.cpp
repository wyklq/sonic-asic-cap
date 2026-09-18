/*
 * fake_sai.cpp - an adversarial fake SAI adapter for the integration test.
 *
 * It replaces libsai / libsairedis so sai_cap_query can be exercised end to
 * end without an ASIC. Behaviour is intentionally hostile:
 *   - only one switch VID is valid; all others return INVALID_OBJECT_ID;
 *   - the switch advertises only SWITCH and PORT as supported object types;
 *   - some attributes succeed, some return plain NOT_SUPPORTED, and some
 *     return vendor-style SAI_STATUS_ATTR_NOT_SUPPORTED_0|index range codes;
 *   - list attributes force the caller through BUFFER_OVERFLOW growth.
 */

#include <cstring>
#include <string>

extern "C" {
#include <sai.h>
#include <saimetadatatypes.h>
#include <saimetadatautils.h>
}

namespace {

constexpr sai_object_id_t kGoodSwitch = 0x21000000000000ULL;
/*
 * Second valid switch that reports SAI_SWITCH_TYPE_PHY. Some switch
 * attributes are conditional on TYPE == PHY, so this lets the integration
 * test exercise the "condition evaluated as met" path.
 */
constexpr sai_object_id_t kPhySwitch = 0x21000000000001ULL;
constexpr sai_object_id_t kPortA = 0x10000000000001ULL;
constexpr sai_object_id_t kQueueA = 0x15000000000001ULL;
constexpr sai_object_id_t kIpgA = 0x1a000000000001ULL;

sai_status_t
fake_get_switch_attribute(
    sai_object_id_t switch_id,
    uint32_t attr_count,
    sai_attribute_t *attr_list)
{
    if (switch_id != kGoodSwitch && switch_id != kPhySwitch) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }
    const bool phy = switch_id == kPhySwitch;
    if (attr_list == nullptr || attr_count == 0) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (uint32_t i = 0; i < attr_count; ++i) {
        sai_attribute_t &attr = attr_list[i];
        switch (attr.id) {
            case SAI_SWITCH_ATTR_TYPE:
                attr.value.s32 =
                    phy ? SAI_SWITCH_TYPE_PHY : SAI_SWITCH_TYPE_NPU;
                break;

            case SAI_SWITCH_ATTR_PORT_LIST:
                if (attr.value.objlist.count < 1) {
                    attr.value.objlist.count = 1;
                    return SAI_STATUS_BUFFER_OVERFLOW;
                }
                attr.value.objlist.count = 1;
                attr.value.objlist.list[0] = kPortA;
                break;

            case SAI_SWITCH_ATTR_SUPPORTED_OBJECT_TYPE_LIST:
                /*
                 * Includes NEXT_HOP so the resource-type discriminator path
                 * (NEXT_HOP_ATTR_TYPE is a resource-type enum) is exercised.
                 */
                if (attr.value.s32list.count < 3) {
                    attr.value.s32list.count = 3;
                    return SAI_STATUS_BUFFER_OVERFLOW;
                }
                attr.value.s32list.count = 3;
                attr.value.s32list.list[0] = SAI_OBJECT_TYPE_SWITCH;
                attr.value.s32list.list[1] = SAI_OBJECT_TYPE_PORT;
                attr.value.s32list.list[2] = SAI_OBJECT_TYPE_NEXT_HOP;
                break;

            case SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS:
                attr.value.u32 = 1;
                break;

            /* Vendor-style per-attribute range code. */
            case SAI_SWITCH_ATTR_FDB_TABLE_SIZE:
                return (sai_status_t)(
                    static_cast<uint32_t>(SAI_STATUS_ATTR_NOT_SUPPORTED_0) |
                    7u);

            default:
                return SAI_STATUS_NOT_SUPPORTED;
        }
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fake_port_stats(
    sai_object_id_t object_id,
    uint32_t number_of_counters,
    const sai_stat_id_t *counter_ids,
    uint64_t *counters);

sai_status_t
fake_port_stats_ext(
    sai_object_id_t object_id,
    uint32_t number_of_counters,
    const sai_stat_id_t *counter_ids,
    sai_stats_mode_t mode,
    uint64_t *counters)
{
    /*
     * Adversarial: BULK_READ is declared nowhere, but if asked, return
     * NOT_SUPPORTED so a false claim would be caught. READ behaves like
     * fake_port_stats.
     */
    if (mode != SAI_STATS_MODE_READ) {
        return SAI_STATUS_NOT_SUPPORTED;
    }
    return fake_port_stats(
        object_id, number_of_counters, counter_ids, counters);
}

sai_status_t
fake_switch_stats(
    sai_object_id_t,
    uint32_t number_of_counters,
    const sai_stat_id_t *,
    uint64_t *counters)
{
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        counters[i] = 0;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fake_set_switch_attribute(sai_object_id_t, const sai_attribute_t *)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
fake_get_port_attribute(
    sai_object_id_t port_id,
    uint32_t attr_count,
    sai_attribute_t *attr_list)
{
    if (port_id != kPortA) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }
    if (attr_list == nullptr || attr_count == 0) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (uint32_t i = 0; i < attr_count; ++i) {
        sai_attribute_t &attr = attr_list[i];
        switch (attr.id) {
            case SAI_PORT_ATTR_TYPE:
                attr.value.s32 = SAI_PORT_TYPE_LOGICAL;
                break;
            case SAI_PORT_ATTR_QOS_QUEUE_LIST:
                if (attr.value.objlist.count < 1) {
                    attr.value.objlist.count = 1;
                    return SAI_STATUS_BUFFER_OVERFLOW;
                }
                attr.value.objlist.count = 1;
                attr.value.objlist.list[0] = kQueueA;
                break;
            case SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST:
                if (attr.value.objlist.count < 1) {
                    attr.value.objlist.count = 1;
                    return SAI_STATUS_BUFFER_OVERFLOW;
                }
                attr.value.objlist.count = 1;
                attr.value.objlist.list[0] = kIpgA;
                break;
            default:
                return SAI_STATUS_NOT_SUPPORTED;
        }
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fake_port_stats(
    sai_object_id_t,
    uint32_t number_of_counters,
    const sai_stat_id_t *counter_ids,
    uint64_t *counters)
{
    /*
     * Deliberately fail one specific counter the capability query declares as
     * READ-capable, so the probe must report a CONTRADICTION. Any other
     * counter succeeds.
     */
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        if (counter_ids[i] == SAI_PORT_STAT_IF_IN_ERRORS) {
            return SAI_STATUS_NOT_SUPPORTED;
        }
        counters[i] = 0;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fake_queue_stats(
    sai_object_id_t,
    uint32_t number_of_counters,
    const sai_stat_id_t *,
    uint64_t *counters)
{
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        counters[i] = 0;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fake_ipg_stats(
    sai_object_id_t,
    uint32_t number_of_counters,
    const sai_stat_id_t *,
    uint64_t *counters)
{
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        counters[i] = 0;
    }
    return SAI_STATUS_SUCCESS;
}

sai_switch_api_t g_switch_api{};
sai_port_api_t g_port_api{};
sai_queue_api_t g_queue_api{};
sai_buffer_api_t g_buffer_api{};

} // namespace

extern "C" {

sai_status_t
sai_api_initialize(uint64_t, const sai_service_method_table_t *)
{
    std::memset(&g_switch_api, 0, sizeof(g_switch_api));
    std::memset(&g_port_api, 0, sizeof(g_port_api));
    std::memset(&g_queue_api, 0, sizeof(g_queue_api));
    std::memset(&g_buffer_api, 0, sizeof(g_buffer_api));

    g_switch_api.get_switch_attribute = fake_get_switch_attribute;
    g_switch_api.set_switch_attribute = fake_set_switch_attribute;
    g_switch_api.get_switch_stats = fake_switch_stats;
    g_port_api.get_port_attribute = fake_get_port_attribute;
    g_port_api.get_port_stats = fake_port_stats;
    g_port_api.get_port_stats_ext = fake_port_stats_ext;
    g_queue_api.get_queue_stats = fake_queue_stats;
    g_buffer_api.get_ingress_priority_group_stats = fake_ipg_stats;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_api_uninitialize(void)
{
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_api_query(sai_api_t api, void **api_method_table)
{
    if (api_method_table == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    switch (api) {
        case SAI_API_SWITCH:
            *api_method_table = &g_switch_api;
            return SAI_STATUS_SUCCESS;
        case SAI_API_PORT:
            *api_method_table = &g_port_api;
            return SAI_STATUS_SUCCESS;
        case SAI_API_QUEUE:
            *api_method_table = &g_queue_api;
            return SAI_STATUS_SUCCESS;
        case SAI_API_BUFFER:
            *api_method_table = &g_buffer_api;
            return SAI_STATUS_SUCCESS;
        default:
            return SAI_STATUS_NOT_SUPPORTED;
    }
}

sai_status_t
sai_query_api_version(sai_api_version_t *version)
{
    if (version == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *version = SAI_API_VERSION;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_object_type_get_availability(
    sai_object_id_t,
    sai_object_type_t,
    uint32_t attr_count,
    const sai_attribute_t *attr_list,
    uint64_t *count)
{
    if (count == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /*
     * Adversarial behaviour: the plain attr_count=0 query works, but a
     * discriminator query only works for the first enum value. This lets the
     * integration test tell the two paths apart.
     */
    if (attr_count == 0) {
        *count = 16;
        return SAI_STATUS_SUCCESS;
    }

    if (attr_list == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (attr_list[0].value.s32 == 0) {
        *count = 8;
        return SAI_STATUS_SUCCESS;
    }
    return SAI_STATUS_NOT_SUPPORTED;
}

sai_status_t
sai_query_attribute_capability(
    sai_object_id_t switch_id,
    sai_object_type_t,
    sai_attr_id_t,
    sai_attr_capability_t *capability)
{
    /*
     * Mirror libsairedis, which requires a valid SWITCH oid here and rejects
     * anything else. Validating this in the fake catches callers that pass an
     * object id instead of the switch id.
     */
    if (switch_id != kGoodSwitch && switch_id != kPhySwitch) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }
    if (capability == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    capability->create_implemented = true;
    capability->set_implemented = true;
    capability->get_implemented = true;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_query_attribute_enum_values_capability(
    sai_object_id_t,
    sai_object_type_t,
    sai_attr_id_t,
    sai_s32_list_t *values)
{
    if (values == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    values->count = 0;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_query_stats_capability(
    sai_object_id_t,
    sai_object_type_t object_type,
    sai_stat_capability_list_t *stats)
{
    if (stats == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /*
     * The fake declares every known stat of the object type as READ-capable.
     * Because fake_port_stats deliberately fails on one specific counter, the
     * tool must report exactly one CONTRADICTION for PORT. That is the
     * cross-validation behaviour this test exists to protect.
     */
    const sai_object_type_info_t *info =
        sai_metadata_get_object_type_info(object_type);
    if (info == nullptr || info->statenum == nullptr) {
        return SAI_STATUS_NOT_SUPPORTED;
    }

    const uint32_t needed =
        static_cast<uint32_t>(info->statenum->valuescount);
    if (stats->count < needed) {
        stats->count = needed;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    stats->count = needed;
    for (uint32_t i = 0; i < needed; ++i) {
        stats->list[i].stat_enum = info->statenum->values[i];
        stats->list[i].stat_modes = SAI_STATS_MODE_READ;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_query_stats_st_capability(
    sai_object_id_t,
    sai_object_type_t,
    sai_stat_st_capability_list_t *stats)
{
    /* The fake adapter does not implement stream telemetry. */
    if (stats == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_NOT_IMPLEMENTED;
}

} // extern "C"

/* Display-only stand-ins for libsaimeta serializers. */
std::string
sai_serialize_status(sai_status_t status)
{
    switch (status) {
        case SAI_STATUS_SUCCESS:
            return "SAI_STATUS_SUCCESS";
        case SAI_STATUS_NOT_SUPPORTED:
            return "SAI_STATUS_NOT_SUPPORTED";
        case SAI_STATUS_NOT_IMPLEMENTED:
            return "SAI_STATUS_NOT_IMPLEMENTED";
        case SAI_STATUS_BUFFER_OVERFLOW:
            return "SAI_STATUS_BUFFER_OVERFLOW";
        case SAI_STATUS_INVALID_OBJECT_ID:
            return "SAI_STATUS_INVALID_OBJECT_ID";
        default:
            return "SAI_STATUS_OTHER";
    }
}

std::string
sai_serialize_attr_value(
    const sai_attr_metadata_t &,
    const sai_attribute_t &attribute,
    bool)
{
    return std::string("<attr:") + std::to_string(attribute.id) + ">";
}
