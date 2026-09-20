/*
 * Unit tests for zmq_endpoint.h.
 *
 * These tests exercise the endpoint facts the transport preflight decides
 * on. They need no ASIC, redis, libsairedis, or test framework, but they do
 * create real UNIX sockets under /tmp (with test-only names) because the
 * whole point is telling a live endpoint from a leftover socket file.
 *
 * Build/run:
 *     make -C tests test
 */

#include "../include/zmq_endpoint.h"

#include <cstdio>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void
expect_true(bool value, const char *what)
{
    ++g_checks;
    if (!value) {
        ++g_failures;
        std::printf("FAIL %-52s expected=true\n", what);
    } else {
        std::printf("ok   %-52s -> true\n", what);
    }
}

void
expect_false(bool value, const char *what)
{
    ++g_checks;
    if (value) {
        ++g_failures;
        std::printf("FAIL %-52s expected=false\n", what);
    } else {
        std::printf("ok   %-52s -> false\n", what);
    }
}

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

using zmqendpoint::EndpointState;
using zmqendpoint::endpoint_live;
using zmqendpoint::endpoint_owner;
using zmqendpoint::endpoint_state;
using zmqendpoint::endpoint_state_text;

/* Test-only paths: never the real /tmp/saiServer of a running switch. */
const char *const kLivePath = "/tmp/sai_cap_query_test_live";
const char *const kStalePath = "/tmp/sai_cap_query_test_stale";
const char *const kFilePath = "/tmp/sai_cap_query_test_plainfile";

/*
 * Bind a UNIX socket at path and keep it open, the way a sairedis server
 * keeps its endpoint. Returns the fd, or -1.
 */
int
bind_endpoint(const char *path)
{
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }

    sockaddr_un address{};

    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

    if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

} // namespace

int
main()
{
    std::printf("unit tests (zmq_endpoint.h)\n");
    std::printf("------------------------------------\n");

    /* 1. Missing path. */
    expect_true(
        endpoint_state(kLivePath) == EndpointState::Missing,
        "missing endpoint reports Missing");
    expect_false(endpoint_live(kLivePath), "missing endpoint is not live");
    expect_true(endpoint_owner(kLivePath).empty(), "missing endpoint has no owner");

    /* 2. Plain file where an endpoint is expected. */
    {
        FILE *file = std::fopen(kFilePath, "w");

        if (file != nullptr) {
            std::fprintf(file, "not a socket\n");
            std::fclose(file);
        }

        expect_true(
            endpoint_state(kFilePath) == EndpointState::Other,
            "plain file reports Other");
        expect_false(endpoint_live(kFilePath), "plain file is not live");
        expect_true(endpoint_owner(kFilePath).empty(), "plain file has no owner");

        std::remove(kFilePath);
    }

    /* 3. Live endpoint: socket file, listener, and a findable owner. */
    {
        const int fd = bind_endpoint(kLivePath);

        if (fd < 0) {
            std::printf("SKIP cannot bind %s\n", kLivePath);
        } else {
            expect_true(
                endpoint_state(kLivePath) == EndpointState::Socket,
                "live endpoint reports Socket");
            expect_true(endpoint_live(kLivePath), "live endpoint is live");

            const std::string owner = endpoint_owner(kLivePath);

            expect_true(
                owner.rfind("pid ", 0) == 0,
                "live endpoint names its owner pid");
            expect_true(
                owner.find("test_zmq_endpoint") != std::string::npos,
                "owner comm is the test process itself");

            /*
             * A bound-but-not-listening socket (a ZMQ_PULL ntf endpoint
             * style leftover) still answers connect, so this only checks
             * that the probe does not lie about the file state.
             */
            expect_true(
                endpoint_state(kLivePath) == EndpointState::Socket,
                "endpoint stays a socket while held");

            close(fd);

            /*
             * close() does not unlink the file, which is exactly how a
             * killed process leaves a stale endpoint behind.
             */
            expect_true(
                endpoint_state(kLivePath) == EndpointState::Socket,
                "closed endpoint file survives (no unlink on close)");
            expect_false(endpoint_live(kLivePath), "closed endpoint is not live");
            expect_true(
                endpoint_owner(kLivePath).empty(),
                "closed endpoint has no owner");

            std::remove(kLivePath);
        }
    }

    /* 4. Stale endpoint: the state a killed sairedis process leaves. */
    {
        const int fd = bind_endpoint(kStalePath);

        if (fd < 0) {
            std::printf("SKIP cannot bind %s\n", kStalePath);
        } else {
            close(fd);

            expect_true(
                endpoint_state(kStalePath) == EndpointState::Socket,
                "stale endpoint still looks like a socket");
            expect_false(endpoint_live(kStalePath), "stale endpoint is not live");
            expect_true(
                endpoint_owner(kStalePath).empty(), "stale endpoint has no owner");

            std::remove(kStalePath);
        }
    }

    /* 5. State text, used verbatim in the preflight messages. */
    expect_eq(
        endpoint_state_text(EndpointState::Missing),
        "missing",
        "Missing state text");
    expect_eq(
        endpoint_state_text(EndpointState::Socket),
        "socket",
        "Socket state text");
    expect_eq(
        endpoint_state_text(EndpointState::Other),
        "not a socket",
        "Other state text");

    /*
     * 6. The default pairs. These are the values the preflight and its
     *    messages are built around; a silent change here would make every
     *    diagnostic on a real switch wrong, so pin them down.
     */
    expect_eq(
        zmqendpoint::kDefaultClientEndpoints[0].main,
        "/tmp/saiServer",
        "client main default is the ClientConfig default");
    expect_eq(
        zmqendpoint::kDefaultClientEndpoints[0].ntf,
        "/tmp/saiServerNtf",
        "client ntf default is the ClientConfig default");
    expect_eq(
        zmqendpoint::kDefaultClientEndpoints[1].main,
        "/tmp/zmq_ep",
        "second client pair is the zmq-sync default");
    expect_eq(
        zmqendpoint::kDefaultClientEndpoints[1].ntf,
        "/tmp/zmq_ntf_ep",
        "second client pair ntf is the zmq-sync default");
    expect_eq(
        zmqendpoint::kDefaultServerEndpoints.main,
        "/tmp/saiServer",
        "server main default is the ServerConfig default");
    expect_eq(
        zmqendpoint::kDefaultServerEndpoints.ntf,
        "/tmp/saiServerNtf",
        "server ntf default is the ServerConfig default");

    std::printf("------------------------------------\n");
    std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);

    return g_failures == 0 ? 0 : 1;
}
