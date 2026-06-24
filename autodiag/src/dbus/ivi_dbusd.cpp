#include <dbus/dbus.h>

#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ivi_dbus_iface.h"

namespace fs = std::filesystem;

static const fs::path kAssetBase = "/var/lib/ivi/assets";
static volatile sig_atomic_t g_running = 1;

static void on_signal(int) { g_running = 0; }

static bool is_under_base(const fs::path &base, const fs::path &target) {
    std::string b = base.lexically_normal().string();
    std::string t = target.lexically_normal().string();
    if (t.size() < b.size()) {
        return false;
    }
    if (t.compare(0, b.size(), b) != 0) {
        return false;
    }
    if (t.size() == b.size()) {
        return true;
    }
    return t[b.size()] == '/';
}

static bool resolve_safe_path(const std::string &rel, fs::path *out) {
    if (rel.empty()) {
        return false;
    }
    fs::path rp(rel);
    if (rp.is_absolute()) {
        return false;
    }

    std::error_code ec;
    fs::path base = fs::weakly_canonical(kAssetBase, ec);
    if (ec) {
        return false;
    }

    fs::path full = fs::weakly_canonical(base / rp, ec);
    if (ec) {
        return false;
    }

    if (!is_under_base(base, full)) {
        return false;
    }

    *out = full;
    return true;
}

static bool write_file_safe(const std::string &rel, const uint8_t *data, size_t len) {
    fs::path out_path;
    if (!resolve_safe_path(rel, &out_path)) {
        return false;
    }

    std::error_code ec;
    fs::create_directories(out_path.parent_path(), ec);

    std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
    if (!ofs.good()) {
        return false;
    }
    if (len > 0) {
        ofs.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(len));
    }
    ofs.close();
    return ofs.good();
}

static bool copy_file_safe(const std::string &src_rel, const std::string &dst_rel) {
    fs::path src;
    fs::path dst;
    std::error_code ec;

    if (!resolve_safe_path(src_rel, &src) || !resolve_safe_path(dst_rel, &dst)) {
        return false;
    }

    fs::create_directories(dst.parent_path(), ec);
    ec.clear();
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    return !ec;
}

static bool read_file_safe(const std::string &rel, std::vector<uint8_t> *out) {
    fs::path p;
    if (!resolve_safe_path(rel, &p)) {
        return false;
    }

    std::ifstream ifs(p, std::ios::binary);
    if (!ifs.good()) {
        return false;
    }

    out->assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

static bool list_dir_safe(const std::string &rel, std::vector<std::string> *out) {
    fs::path p;
    if (!resolve_safe_path(rel, &p)) {
        return false;
    }

    std::error_code ec;
    if (!fs::exists(p, ec) || !fs::is_directory(p, ec)) {
        return false;
    }

    out->clear();
    for (const auto &entry : fs::directory_iterator(p, ec)) {
        if (ec) {
            return false;
        }
        out->push_back(entry.path().filename().string());
        if (out->size() >= 256) {
            break;
        }
    }

    std::sort(out->begin(), out->end());
    return true;
}

static bool valid_test_id(const std::string &test_id) {
    if (test_id.empty() || test_id.size() > 32) {
        return false;
    }
    for (char c : test_id) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') {
            continue;
        }
        return false;
    }
    return true;
}

static std::string run_self_test(const std::string &test_id) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return "runner-error";
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "runner-error";
    }

    if (pid == 0) {
        char *const argv[] = {const_cast<char *>("/opt/ivi/bin/ivi_diag_runner"),
                              const_cast<char *>(test_id.c_str()), nullptr};
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    std::string output;
    char buf[256];
    while (true) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        output.append(buf, buf + n);
        if (output.size() > 2048) {
            break;
        }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return output.empty() ? "ok" : output;
    }

    return output.empty() ? "self-test failed" : output;
}

static std::string run_update(const std::string &b64_update) {
    if (b64_update.empty() || b64_update.size() > (256 * 1024)) {
        return "update-invalid-size";
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return "update-runner-error";
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "update-runner-error";
    }

    if (pid == 0) {
        char *const argv[] = {const_cast<char *>("/opt/ivi/bin/ivi_update_runner"),
                              const_cast<char *>(b64_update.c_str()), nullptr};
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    std::string output;
    char buf[256];
    while (true) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        output.append(buf, buf + n);
        if (output.size() > (64 * 1024)) {
            break;
        }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    std::string result;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        result = output.empty() ? "update-ok" : output;
    } else {
        result = output.empty() ? "update-failed" : output;
    }

    return result;
}

static DBusHandlerResult send_error(DBusConnection *conn, DBusMessage *msg,
                                    const char *name, const char *text) {
    DBusMessage *err = dbus_message_new_error(msg, name, text);
    if (err == nullptr) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_connection_send(conn, err, nullptr);
    dbus_connection_flush(conn);
    dbus_message_unref(err);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult send_string(DBusConnection *conn, DBusMessage *msg,
                                     const std::string &s) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply == nullptr) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    const char *ptr = s.c_str();
    if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr, DBUS_TYPE_INVALID)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_connection_send(conn, reply, nullptr);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult send_bool(DBusConnection *conn, DBusMessage *msg, bool value) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply == nullptr) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_bool_t v = value ? TRUE : FALSE;
    if (!dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &v, DBUS_TYPE_INVALID)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    dbus_connection_send(conn, reply, nullptr);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult send_bytes(DBusConnection *conn, DBusMessage *msg,
                                    const std::vector<uint8_t> &data) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply == nullptr) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    DBusMessageIter iter;
    DBusMessageIter array_iter;
    dbus_message_iter_init_append(reply, &iter);

    if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                          DBUS_TYPE_BYTE_AS_STRING, &array_iter)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if (!data.empty()) {
        const uint8_t *ptr = data.data();
        int n = static_cast<int>(data.size());
        if (!dbus_message_iter_append_fixed_array(&array_iter, DBUS_TYPE_BYTE, &ptr, n)) {
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_NEED_MEMORY;
        }
    }

    if (!dbus_message_iter_close_container(&iter, &array_iter)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    dbus_connection_send(conn, reply, nullptr);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult send_string_array(DBusConnection *conn, DBusMessage *msg,
                                           const std::vector<std::string> &items) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply == nullptr) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    DBusMessageIter iter;
    DBusMessageIter array_iter;
    dbus_message_iter_init_append(reply, &iter);

    if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                          DBUS_TYPE_STRING_AS_STRING, &array_iter)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    for (const auto &item : items) {
        const char *ptr = item.c_str();
        if (!dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &ptr)) {
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_NEED_MEMORY;
        }
    }

    if (!dbus_message_iter_close_container(&iter, &array_iter)) {
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    dbus_connection_send(conn, reply, nullptr);
    dbus_connection_flush(conn);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_method(DBusConnection *conn, DBusMessage *msg) {
    if (dbus_message_is_method_call(msg, "org.freedesktop.DBus.Introspectable",
                                    "Introspect")) {
        return send_string(conn, msg, kIntrospectionXml);
    }

    if (!dbus_message_has_path(msg, IVI_DBUS_PATH)) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "Ping")) {
        return send_string(conn, msg, "pong");
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "ReadFile")) {
        const char *rel = nullptr;
        DBusError err;
        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &rel, DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        std::vector<uint8_t> data;
        if (!read_file_safe(rel, &data)) {
            return send_error(conn, msg, DBUS_ERROR_FAILED, "read failed");
        }
        return send_bytes(conn, msg, data);
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "WriteFile")) {
        const char *rel = nullptr;
        uint8_t *bytes = nullptr;
        int len = 0;
        DBusError err;

        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &rel, DBUS_TYPE_ARRAY,
                                   DBUS_TYPE_BYTE, &bytes, &len, DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        bool ok = write_file_safe(rel, bytes, static_cast<size_t>(len));
        return send_bool(conn, msg, ok);
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "CopyFile")) {
        const char *src = nullptr;
        const char *dst = nullptr;
        DBusError err;

        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &src, DBUS_TYPE_STRING,
                                   &dst, DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        bool ok = copy_file_safe(src, dst);
        return send_bool(conn, msg, ok);
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "ListDir")) {
        const char *rel = nullptr;
        DBusError err;
        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &rel, DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        std::vector<std::string> out;
        if (!list_dir_safe(rel, &out)) {
            return send_error(conn, msg, DBUS_ERROR_FAILED, "list failed");
        }
        return send_string_array(conn, msg, out);
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "GetDeviceInfo")) {
        return send_string(conn, msg,
                           "model=ACME-IVI-1000;sw_version=2026.02;board=ref-x86_64");
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "RunSelfTest")) {
        const char *test_id = nullptr;
        DBusError err;

        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &test_id,
                                   DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        std::string tid = test_id ? test_id : "";
        if (!valid_test_id(tid)) {
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid test id");
        }

        return send_string(conn, msg, run_self_test(tid));
    }

    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "RunUpdate")) {
        const char *payload = nullptr;
        DBusError err;

        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &payload,
                                   DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        std::string update = payload ? payload : "";
        return send_string(conn, msg, run_update(update));
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult message_filter(DBusConnection *conn, DBusMessage *msg,
                                        void *) {
    if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    return handle_method(conn, msg);
}

static DBusConnection *connect_to_bus(DBusError *err) {
    DBusConnection *conn = dbus_bus_get_private(DBUS_BUS_STARTER, err);
    if (conn != nullptr) {
        return conn;
    }

    dbus_error_free(err);
    dbus_error_init(err);

    conn = dbus_connection_open_private(IVI_DBUS_ADDRESS, err);
    if (conn == nullptr) {
        return nullptr;
    }

    if (!dbus_bus_register(conn, err)) {
        dbus_connection_close(conn);
        dbus_connection_unref(conn);
        return nullptr;
    }

    return conn;
}

int main() {
    DBusError err;

    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);

    std::error_code ec;
    fs::create_directories(kAssetBase, ec);

    dbus_error_init(&err);
    DBusConnection *conn = connect_to_bus(&err);
    if (conn == nullptr) {
        std::cerr << "dbus connect failed: "
                  << (dbus_error_is_set(&err) ? err.message : "unknown") << std::endl;
        dbus_error_free(&err);
        return 1;
    }

    dbus_connection_set_exit_on_disconnect(conn, FALSE);

    int reply = dbus_bus_request_name(conn, IVI_DBUS_SERVICE,
                                      DBUS_NAME_FLAG_DO_NOT_QUEUE, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "dbus request name failed: " << err.message << std::endl;
        dbus_error_free(&err);
        dbus_connection_close(conn);
        dbus_connection_unref(conn);
        return 1;
    }
    if (reply != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        dbus_connection_close(conn);
        dbus_connection_unref(conn);
        return 0;
    }

    dbus_connection_add_filter(conn, message_filter, nullptr, nullptr);

    while (g_running && dbus_connection_get_is_connected(conn)) {
        dbus_connection_read_write_dispatch(conn, 1000);
        while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS) {
        }
    }

    dbus_connection_close(conn);
    dbus_connection_unref(conn);
    dbus_error_free(&err);
    return 0;
}
