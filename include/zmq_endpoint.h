/*
 * zmq_endpoint.h - the ZMQ endpoint facts the transport preflight needs.
 *
 * libsairedis falls back to built-in ipc:// endpoints when no
 * *config.json is supplied. Two default pairs exist in the wild, depending
 * on which code path the linked libsairedis build takes:
 *
 *   ClientConfig / ServerConfig defaults (no client_config.json /
 *   server_config.json): ipc:///tmp/saiServer + ipc:///tmp/saiServerNtf
 *   (current sonic-sairedis; the context config is explicitly NOT used by
 *   the client path)
 *
 *   SAI_REDIS_COMMUNICATION_MODE_ZMQ_SYNC defaults (no context config):
 *   ipc:///tmp/zmq_ep + ipc:///tmp/zmq_ntf_ep
 *
 * Both are UNIX socket files: they live in the filesystem namespace of the
 * process that created them. When syncd runs in a docker container, the
 * sairedis server endpoints exist inside that container's namespaces and
 * are invisible to a tool running on the host or in another container,
 * unless the path is shared through a volume or the endpoint is published
 * out. A context-config-driven build can also use tcp:// endpoints
 * (context defaults 127.0.0.1:5555 / 5556), invisible across network
 * namespaces for the same reason.
 *
 * The two roles expect opposite things of the very same paths:
 *   - the client CONNECTS the main endpoint (the sairedis server inside
 *     syncd binds it) and BINDS the notification endpoint itself, so the
 *     main endpoint must already exist and be live, while the ntf endpoint
 *     must not;
 *   - the server BINDS the main endpoint and then forwards every call to
 *     syncd over the Redis channel, so it requires neither to exist --
 *     a missing endpoint is the normal case there.
 *
 * These helpers answer "what is at this path right now" so the tool can
 * report the mistake in milliseconds instead of letting libzmq discover it
 * the slow way. They are POSIX/Linux-only on purpose: the tool targets the
 * switch, where syncd and libsairedis run.
 */

#ifndef SAI_CAP_ZMQ_ENDPOINT_H
#define SAI_CAP_ZMQ_ENDPOINT_H

#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <dirent.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace zmqendpoint {

struct ZmqEndpoints
{
    const char *main;
    const char *ntf;
};

/*
 * The pairs a CLIENT role instance connects to when no client_config.json
 * is given (ClientConfig defaults first, then the ZMQ-sync mode defaults).
 */
constexpr ZmqEndpoints kDefaultClientEndpoints[] = {
    {"/tmp/saiServer", "/tmp/saiServerNtf"},
    {"/tmp/zmq_ep", "/tmp/zmq_ntf_ep"},
};

/* The pair a server-role instance binds when no server_config.json is
 * given (ServerConfig defaults). */
constexpr ZmqEndpoints kDefaultServerEndpoints = {
    "/tmp/saiServer",
    "/tmp/saiServerNtf"};

enum class EndpointState
{
    Missing,
    Socket,
    Other,
};

inline EndpointState
endpoint_state(const char *path)
{
    struct stat endpoint_stat{};

    if (stat(path, &endpoint_stat) != 0) {
        return EndpointState::Missing;
    }

    return S_ISSOCK(endpoint_stat.st_mode) ? EndpointState::Socket
                                           : EndpointState::Other;
}

inline const char *
endpoint_state_text(EndpointState state)
{
    switch (state) {
    case EndpointState::Missing:
        return "missing";
    case EndpointState::Socket:
        return "socket";
    case EndpointState::Other:
        return "not a socket";
    }

    return "unknown";
}

/*
 * True when something is listening on the UNIX socket at path right now.
 * zmq_connect to an ipc:// path succeeds lazily, so the filesystem state
 * alone cannot tell a live server from a leftover socket file: only a real
 * connect can, and that is exactly what a sairedis client is about to do.
 */
inline bool
endpoint_live(const char *path)
{
    const int probe = socket(AF_UNIX, SOCK_STREAM, 0);

    if (probe < 0) {
        return false;
    }

    sockaddr_un address{};

    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

    const bool live = connect(
                           probe,
                           reinterpret_cast<sockaddr *>(&address),
                           sizeof(address)) == 0;

    close(probe);

    return live;
}

/*
 * Which process holds the UNIX socket bound at path, formatted as
 * "pid <pid> (<comm>)" -- empty when nobody holds it or /proc is not
 * readable. The path is mapped to its socket inode through
 * /proc/net/unix, and that inode is then looked up among the file
 * descriptors of every process. Needs no privileges for the tool's own
 * processes; other users' processes simply stay unknown.
 */
inline std::string
endpoint_owner(const char *path)
{
    FILE *const unix_table = fopen("/proc/net/unix", "r");

    if (unix_table == nullptr) {
        return std::string();
    }

    unsigned long inode = 0;
    char line[1024];

    while (fgets(line, sizeof(line), unix_table) != nullptr) {
        /* columns: Num RefCount Protocol Flags Type St Inode Path */
        char *fields[8];
        size_t count = 0;
        char *cursor = line;

        while (count < 8) {
            while (*cursor == ' ' || *cursor == '\t') {
                ++cursor;
            }
            if (*cursor == '\0' || *cursor == '\n') {
                break;
            }
            fields[count++] = cursor;
            while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
                   *cursor != '\n') {
                ++cursor;
            }
            if (*cursor != '\0') {
                *cursor++ = '\0';
            }
        }

        if (count < 8 || strcmp(fields[7], path) != 0) {
            continue;
        }

        inode = strtoul(fields[6], nullptr, 10);

        break;
    }

    fclose(unix_table);

    if (inode == 0) {
        return std::string();
    }

    char target[64];

    snprintf(target, sizeof(target), "socket:[%lu]", inode);

    DIR *const proc = opendir("/proc");

    if (proc == nullptr) {
        return std::string();
    }

    std::string owner;

    const dirent *entry = nullptr;

    while (owner.empty() && (entry = readdir(proc)) != nullptr) {
        const char *name = entry->d_name;

        bool numeric = name[0] != '\0';

        for (const char *c = name; *c != '\0'; ++c) {
            if (!isdigit(static_cast<unsigned char>(*c))) {
                numeric = false;
                break;
            }
        }

        if (!numeric) {
            continue;
        }

        char fd_dir[64];

        snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", name);

        DIR *const fds = opendir(fd_dir);

        if (fds == nullptr) {
            continue;
        }

        const dirent *fd_entry = nullptr;

        while (owner.empty() && (fd_entry = readdir(fds)) != nullptr) {
            char fd_path[128];
            char link[128];

            snprintf(
                fd_path, sizeof(fd_path), "%s/%s", fd_dir, fd_entry->d_name);

            const ssize_t length = readlink(fd_path, link, sizeof(link) - 1);

            if (length < 0) {
                continue;
            }

            link[length] = '\0';

            if (strcmp(link, target) == 0) {
                char comm_path[64];
                char comm[128] = {0};

                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", name);

                FILE *const comm_file = fopen(comm_path, "r");

                if (comm_file != nullptr) {
                    if (fgets(comm, sizeof(comm), comm_file) != nullptr) {
                        const size_t comm_length = strlen(comm);

                        if (comm_length > 0 && comm[comm_length - 1] == '\n') {
                            comm[comm_length - 1] = '\0';
                        }
                    }
                    fclose(comm_file);
                }

                owner = "pid " + std::string(name) + " (" +
                        (comm[0] != '\0' ? comm : "?") + ")";
            }
        }

        closedir(fds);
    }

    closedir(proc);

    return owner;
}

} // namespace zmqendpoint

#endif /* SAI_CAP_ZMQ_ENDPOINT_H */
