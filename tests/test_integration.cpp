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

    std::printf("------------------------------------\n");
    std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
