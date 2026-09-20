/*
 * Integration tests for the P0 capability-hardening behaviour.
 *
 * Runs the real sai_cap_query binary against a fake SAI adapter (fake_sai.cpp)
 * linked with the generated SAI 1.17.5 metadata. No ASIC, redis, or
 * libsairedis is involved, but the tool's own logic runs unchanged.
 *
 * Build/run: make -f Makefile.integration integration
 */

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void
expect_contains(
    const std::string &haystack,
    const std::string &needle,
    const char *what)
{
    ++g_checks;
    if (haystack.find(needle) == std::string::npos) {
        ++g_failures;
        std::printf(
            "FAIL %-56s missing '%s'\n",
            what,
            needle.c_str());
    } else {
        std::printf("ok   %-56s (found)\n", what);
    }
}

void
expect_not_contains(
    const std::string &haystack,
    const std::string &needle,
    const char *what)
{
    ++g_checks;
    if (haystack.find(needle) != std::string::npos) {
        ++g_failures;
        std::printf(
            "FAIL %-56s unexpectedly contains '%s'\n",
            what,
            needle.c_str());
    } else {
        std::printf("ok   %-56s (absent)\n", what);
    }
}

void
expect_true(bool value, const char *what)
{
    ++g_checks;
    if (!value) {
        ++g_failures;
        std::printf("FAIL %-56s expected=true\n", what);
    } else {
        std::printf("ok   %-56s -> true\n", what);
    }
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <path-to-sai_cap_query>\n", argv[0]);
        return 2;
    }
    const std::string tool = argv[1];

    std::printf("integration tests (fake SAI adapter)\n");
    std::printf("------------------------------------\n");

    auto run = [&](const std::string &args) {
        const std::string command = tool + " " + args + " 2>&1";
        std::string output;
        FILE *pipe = popen(command.c_str(), "r");
        if (pipe == nullptr) {
            return output;
        }
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        const int status = pclose(pipe);
        output += "\n[exit=" + std::to_string(WEXITSTATUS(status)) + "]\n";
        return output;
    };

    /* Capture stdout only, so JSON purity can be asserted. */
    auto run_stdout_only = [&](const std::string &args) {
        const std::string command = tool + " " + args + " 2>/dev/null";
        std::string output;
        FILE *pipe = popen(command.c_str(), "r");
        if (pipe == nullptr) {
            return output;
        }
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        pclose(pipe);
        return output;
    };

    /* Run with one environment variable prefixed to the command. */
    auto run_env = [&](const std::string &env, const std::string &args) {
        const std::string command = env + " " + tool + " " + args + " 2>&1";
        std::string output;
        FILE *pipe = popen(command.c_str(), "r");
        if (pipe == nullptr) {
            return output;
        }
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        pclose(pipe);
        return output;
    };

    /*
     * Extract one top-level member of the pretty-printed JSON document so a
     * section can be examined without a full parser. A top-level member's
     * closing bracket is the first "\n  ]" / "\n  }" after its opening
     * bracket, because nested content is always indented deeper.
     */
    auto json_section = [](const std::string &json, const std::string &key) {
        const std::string marker = "\n  \"" + key + "\": ";
        const size_t start = json.find(marker);
        if (start == std::string::npos) {
            return std::string();
        }
        const size_t open = start + marker.size();
        if (open >= json.size()) {
            return std::string();
        }
        const char close = json[open] == '[' ? ']' : '}';
        const size_t end = json.find("\n  " + std::string(1, close), open);
        if (end == std::string::npos) {
            return json.substr(start);
        }
        return json.substr(start, end - start);
    };

    /* 1. A bad VID must fail loudly and must NOT produce a capability report. */
    {
        const std::string out = run("--object PORT 0x99999999999999");
        expect_contains(out, "FATAL: switch VID", "bad VID is rejected");
        expect_contains(out, "[exit=3]", "bad VID exit code is 3");
        expect_not_contains(
            out, "Full attribute capability scan",
            "bad VID does not run the capability scan");
    }

    /* 2. A good VID must validate. */
    {
        const std::string out = run("--object PORT 0x21000000000000");
        expect_contains(
            out, "Switch VID validation: OK",
            "good VID validates");
        expect_contains(
            out, "SAI_SWITCH_TYPE_NPU",
            "switch type is read back");
    }

    /* 3. Vendor range status must collapse into one normalized bucket. */
    {
        const std::string out = run("--all 0x21000000000000");
        expect_contains(
            out, "ATTR_NOT_SUPPORTED=",
            "range code normalized to ATTR_NOT_SUPPORTED");
        expect_not_contains(
            out, "ATTR_NOT_SUPPORTED_7",
            "normalized summary has no per-index bucket");
    }

    /* 4. The authoritative list must mark unsupported object types. */
    {
        const std::string out = run("--all 0x21000000000000");
        expect_contains(
            out, "verdict=asic_unsupported",
            "unsupported object types are marked");
        expect_contains(
            out, "SUPPORTED_OBJECT_TYPE_LIST",
            "the supported list is reported");
    }

    /* 5. --all must include the full attribute capability scan and report
     *    normalized failure buckets for the fake adapter's rejections. */
    {
        const std::string out =
            run("--all --include-unsupported 0x21000000000000");
        expect_contains(
            out, "Full attribute capability scan",
            "--all runs the full attribute scan");
        expect_contains(
            out, "[SAI_OBJECT_TYPE_SWITCH]",
            "switch object is scanned");
        expect_contains(
            out, "[SAI_OBJECT_TYPE_PORT]",
            "port object is scanned (in supported list)");
    }

    /* 6. The client/server transport must be reported honestly. */
    {
        const std::string out = run("0x21000000000000");
        expect_contains(
            out, "Transport: client",
            "defaults to client transport");
    }

    /* 7. --probe-stats must reach the fake port/queue/IPG counters. */
    {
        const std::string out = run("--probe-stats 0x21000000000000");
        expect_contains(
            out, "read probe on sample object",
            "probe-stats reaches a sample object");
        expect_contains(
            out, "probe summary: accepted=",
            "probe-stats reports accepted counters");
    }

    /* 8. P1: the probe must falsify a declared-but-unreadable counter. */
    {
        const std::string out = run("--probe-stats 0x21000000000000");
        expect_contains(
            out, "CONTRADICTION: declared READ-capable but probe failed",
            "probe cross-checks the declared stats capability");
        expect_contains(
            out, "SAI_PORT_STAT_IF_IN_ERRORS",
            "the contradicted counter is named");
        expect_contains(
            out, "contradictions=1",
            "exactly one contradiction is counted");
    }

    /* 9. P1: stream-telemetry capability section must be present and must
     *    treat NOT_IMPLEMENTED as a normal answer. */
    {
        const std::string out = run("0x21000000000000");
        expect_contains(
            out, "=== Stream-telemetry statistics capabilities ===",
            "stream-telemetry section is present");
    }

    /* 10. P1: discriminator-based availability must distinguish pools. */
    {
        const std::string out = run("0x21000000000000");
        expect_contains(
            out, "Resource availability by discriminator attribute",
            "discriminator availability section is present");
        expect_contains(
            out, "discriminator=SAI_NEXT_HOP_ATTR_TYPE",
            "a resource-type enum discriminator is probed");
        expect_contains(
            out, "Resource-type availability summary:",
            "discriminator section reports a summary");
    }

    /* 11. P1: declared stat_modes must be validated with real reads, and
     *     clear-capable modes must not run unless explicitly allowed. */
    {
        const std::string out = run("--probe-stats 0x21000000000000");
        expect_contains(
            out, "stat_modes validation",
            "stat_modes validation runs");
        expect_contains(
            out, "modes summary:",
            "stat_modes validation reports a summary");
        expect_contains(
            out, "pass --allow-clear",
            "clear-capable modes are not probed unless allowed");
    }

    /* 12. Next step: attribute capability claims are verified with real GETs. */
    {
        const std::string out = run("--verify-attributes 0x21000000000000");
        expect_contains(
            out, "=== Live attribute capability verification ===",
            "attribute verification section is present");
        expect_contains(
            out, "declared gettable but GET failed",
            "a false gettable claim is reported");
        expect_contains(
            out, "Attribute verification summary:",
            "attribute verification reports a summary");
        expect_contains(
            out, "contradicted attributes (",
            "contradicted attributes are listed");
        expect_contains(
            out, "more contradiction(s) not printed",
            "contradiction output is bounded");
    }

    /* 13. Attribute verification must be off by default (it costs a GET per
     *     attribute). */
    {
        const std::string out = run("0x21000000000000");
        expect_not_contains(
            out, "Live attribute capability verification",
            "attribute verification is opt-in");
    }

    /* 14. Conditional attributes must be evaluated, not blanket-exempted.
     *     The fake's second switch reports SAI_SWITCH_TYPE_PHY, which makes
     *     some switch attributes' conditions actually met; those must then be
     *     verified (and reported as contradictions, since the fake does not
     *     serve them) instead of being written off as unverifiable. */
    {
        const std::string npu = run("--verify-attributes 0x21000000000000");
        const std::string phy = run("--verify-attributes 0x21000000000001");

        expect_contains(
            npu, "conditional attributes:",
            "conditional attribute statistics are reported");
        expect_contains(
            npu, "condition_met=0",
            "NPU switch has no met conditional attributes");
        expect_contains(
            phy, "condition_met=2",
            "PHY switch evaluates two conditions as met");
        expect_contains(
            phy, "condition_unknown=24",
            "unevaluated conditions are counted as unknown");
        expect_contains(
            phy,
            "A contradiction is only asserted when the condition was "
            "evaluated as met",
            "the condition policy is stated in the report");

        /*
         * Met conditions must increase the contradiction count relative to
         * the NPU switch, proving conditional attributes are no longer being
         * skipped wholesale.
         */
        auto summary_value = [](const std::string &out) -> long {
            const std::string key = "contradictions=";
            const size_t at = out.find(key);
            if (at == std::string::npos) {
                return -1;
            }
            return std::strtol(out.c_str() + at + key.size(), nullptr, 10);
        };
        const long npu_contra = summary_value(npu);
        const long phy_contra = summary_value(phy);
        expect_true(
            npu_contra > 0 && phy_contra == npu_contra + 2,
            "met conditions add exactly two contradictions");
    }

    /* 15. JSON mode must emit exactly one parseable document on stdout, with
     *     the human-readable preamble moved to stderr. */
    {
        const std::string stdout_only = run_stdout_only(
            "--format json 0x21000000000000");
        const std::string merged = run(
            "--format json 0x21000000000000");

        expect_contains(stdout_only, "{\n  \"tool\": \"sai_cap_query\",",
            "stdout starts with the JSON document");
        expect_not_contains(stdout_only, "Switch VID validation: OK",
            "validation banner is not on stdout in json mode");
        expect_not_contains(stdout_only, "=== Version context ===",
            "version banner is not on stdout in json mode");
        expect_contains(stdout_only, "\"schema_version\": 1",
            "schema version is present");
        expect_contains(stdout_only, "\"supported_object_types\": {",
            "supported object types are present");
        expect_contains(merged, "Switch VID validation: OK",
            "validation is still reported on stderr");
    }

    /* 16. JSON mode must reflect the same verdicts as the text path. */
    {
        const std::string out = run_stdout_only(
            "--format json --all 0x21000000000000");
        expect_contains(out, "\"asic_supported\": true",
            "supported types are marked in json");
        expect_contains(out, "\"create_implemented\": true",
            "attribute capability fields are present");
        expect_contains(out, "\"in_local_metadata\": true",
            "object type provenance is present");
        expect_contains(out, "\"counters\": [",
            "stat counter lists are present");
        expect_contains(out, "\"stream_telemetry\": {",
            "stream telemetry is nested under stats");
        expect_contains(out, "\"result\": \"ok\"",
            "switch attribute outcomes are reported");
    }

    /* 17. A bad --format value must be rejected. */
    {
        const std::string out = run("--format xml 0x21000000000000");
        expect_contains(out, "Invalid --format", "bad format is rejected");
        expect_contains(out, "[exit=2]", "bad format exits 2");
    }

    /*
     * 18. JSON sweeps must follow the text report's cost model: without
     *     --all/--object the object-type sweeps are restricted to the focused
     *     type lists, and object types the adapter's
     *     SUPPORTED_OBJECT_TYPE_LIST excludes are never live-queried. The
     *     fake advertises only SWITCH, PORT and NEXT_HOP; QUEUE carries stats
     *     but is outside the attribute-focused list, while NEXT_HOP sits
     *     outside the statistics-focused list.
     */
    {
        const std::string default_out =
            run_stdout_only("--format json 0x21000000000000");
        const std::string all_out =
            run_stdout_only("--format json --all 0x21000000000000");

        const std::string default_stats =
            json_section(default_out, "statistics_capabilities");
        expect_contains(
            default_stats,
            "SAI_OBJECT_TYPE_QUEUE",
            "default stats sweep covers focused types");
        expect_not_contains(
            default_stats,
            "SAI_OBJECT_TYPE_NEXT_HOP",
            "default stats sweep skips non-focused types");

        const std::string all_stats =
            json_section(all_out, "statistics_capabilities");
        expect_contains(
            all_stats,
            "SAI_OBJECT_TYPE_PORT",
            "--all stats sweep covers advertised types");
        expect_not_contains(
            all_stats,
            "SAI_OBJECT_TYPE_QUEUE",
            "--all stats sweep skips unadvertised types");

        const std::string all_caps =
            json_section(all_out, "attribute_capabilities");
        expect_contains(
            all_caps, "\"queried\": true",
            "advertised types are live-queried");
        expect_contains(
            all_caps, "\"queried\": false",
            "unadvertised types are not live-queried");
        expect_contains(
            all_caps, "\"verdict\"", "skipped types carry a verdict");
        expect_contains(
            all_out,
            "\"create_implemented\": true",
            "queried capability fields are still present");

        const std::string default_caps =
            json_section(default_out, "attribute_capabilities");
        expect_not_contains(
            default_caps,
            "SAI_OBJECT_TYPE_NEXT_HOP",
            "default attribute sweep is restricted to focused types");
    }

    /*
     * 19. JSON mode must reject combinations it cannot honor instead of
     *     silently dropping them. --list-switches returns early from main
     *     with a human-readable line and never builds a document, so the
     *     combination is a usage error (exit 2). --include-unsupported only
     *     filters the text report, so it stays accepted but is announced on
     *     stderr rather than silently ignored.
     */
    {
        const std::string rejected =
            run("--list-switches --format json 0x21000000000000");
        expect_contains(
            rejected,
            "--list-switches cannot be combined with --format json",
            "list-switches plus json is rejected");
        expect_contains(
            rejected, "[exit=2]",
            "list-switches plus json exits 2");
        expect_not_contains(
            rejected, "\"schema_version\"",
            "rejected combination emits no JSON document");

        const std::string text = run("--list-switches 0x21000000000000");
        expect_contains(
            text, "=== Switch VID description ===",
            "list-switches still works in text mode");
        expect_contains(
            text, "supported_object_types=",
            "switch description reports the type count");
        expect_contains(
            text, "[exit=0]",
            "list-switches in text mode exits 0");

        const std::string merged =
            run("--format json --include-unsupported 0x21000000000000");
        expect_contains(
            merged,
            "--include-unsupported does not filter the JSON sweeps",
            "inert flag is reported on stderr");
        expect_contains(
            merged, "\"include_unsupported\": true",
            "inert flag is still echoed in the document");

        const std::string stdout_only =
            run_stdout_only(
                "--format json --include-unsupported 0x21000000000000");
        expect_contains(
            stdout_only, "\"schema_version\": 1",
            "inert flag still yields a JSON document");
        expect_not_contains(
            stdout_only, "WARNING: --include-unsupported",
            "warning stays on stderr, not in the document");
    }

    /*
     * 20. --debug must expose the transport decision and the exact profile
     *     answers libsairedis receives, must time the library calls, and
     *     must stay off stdout so JSON stays parseable. The fake adapter
     *     ignores the profile, so the dump is printed by the tool itself
     *     from the same source of truth the profile callback uses.
     */
    {
        const std::string merged = run("--debug 0x21000000000000");
        expect_contains(
            merged,
            "debug: transport=client",
            "debug prints the default transport");
        expect_contains(
            merged,
            "debug:   SAI_REDIS_ENABLE_CLIENT = true",
            "debug prints the profile answer libsairedis receives");
        expect_contains(
            merged,
            "debug:   SAI_REDIS_CONTEXT_CONFIG = (nullptr)",
            "absent configs are printed as nullptr");
        expect_contains(
            merged,
            "debug: sai_api_initialize took",
            "debug times the library calls");

        const std::string stdout_only =
            run_stdout_only("--debug --format json 0x21000000000000");
        expect_contains(
            stdout_only,
            "\"schema_version\": 1",
            "json still produced with --debug");
        expect_not_contains(
            stdout_only,
            "debug:",
            "debug output stays off stdout in json mode");

        const std::string server = run("--debug --server 0x21000000000000");
        expect_contains(
            server,
            "debug: transport=server",
            "debug prints the server transport");
        expect_contains(
            server,
            "debug:   SAI_REDIS_ENABLE_CLIENT = false",
            "server mode answers false");
    }

    /*
     * 21. SAI_CAP_ENABLE_CLIENT must override the profile answer exactly:
     *     "false" forces the server role, "unset" answers nullptr like the
     *     builds that predate client-mode support, and an unrecognized value
     *     must be ignored rather than half-honoured.
     */
    {
        const std::string forced =
            run_env("SAI_CAP_ENABLE_CLIENT=false", "--debug 0x21000000000000");
        expect_contains(
            forced,
            "debug:   SAI_REDIS_ENABLE_CLIENT = false",
            "false override forces the server role");

        const std::string unset =
            run_env(
                "SAI_CAP_ENABLE_CLIENT=unset", "--debug 0x21000000000000");
        expect_contains(
            unset,
            "debug:   SAI_REDIS_ENABLE_CLIENT = (nullptr)",
            "unset override answers nullptr (pre-client-mode behaviour)");

        const std::string bogus =
            run_env(
                "SAI_CAP_ENABLE_CLIENT=nonsense",
                "--debug 0x21000000000000");
        expect_contains(
            bogus,
            "debug:   SAI_REDIS_ENABLE_CLIENT = true",
            "unknown override keeps the default answer");
    }

    std::printf("------------------------------------\n");
    std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
