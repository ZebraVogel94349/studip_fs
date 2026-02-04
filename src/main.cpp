#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <ctime>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <map>
#include <set>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <thread>
#include <list>
#include <optional>

struct Settings {
    std::size_t page_limit = 100;
    time_t tree_cache = 300;
    int request_delay = 100;
    long request_timeout = 30;
    double chunk_size_fraction = 0.2;
    std::size_t min_chunk_size = 256 * 1024;
    std::size_t max_chunk_size = 4 * 1024 * 1024;
    std::size_t max_cache_bytes = 800 * 1024 * 1024;
    std::string cookie_file_path = "/tmp/studcookies.txt";
    std::string studip_base_url = "https://studip.uni-hannover.de";
    std::string studip_jsonapi_prefix = "/jsonapi.php/v1/";
    std::string studip_jsonapi_url = "https://studip.uni-hannover.de/jsonapi.php/v1/";
    std::string sso_base_url = "https://sso.idm.uni-hannover.de";
    std::string studip_saml_post_url = "https://studip.uni-hannover.de/Shibboleth.sso/SAML2/POST";
    std::string shibboleth_login_url =
        "https://studip.uni-hannover.de/Shibboleth.sso/Login?"
        "target=https%3A%2F%2Fstudip.uni-hannover.de%2Fdispatch.php%2Flogin%3Fsso%3Dshib%26again%3Dyes%26cancel_login%3D1"
        "&entityID=https%3A%2F%2Fsso.idm.uni-hannover.de%2Fidp%2Fshibboleth";
    std::string username = "[YOUR USERNAME]";
    std::string password = "[YOUR PASSWORD]";
    std::string mount_point = "studip_fs";
};

static Settings settings;

const std::string ACTION_REGEX = R"(action\s*=\s*["']([^"']+)["'])";
const std::string CSRF_REGEX = R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])";
const std::string RELAY_STATE_REGEX = R"(name="RelayState"\s+value="([^"]+)\")";
const std::string SAML_RESPONSE_REGEX = R"(name="SAMLResponse"\s+value="([^"]+)\")";

struct file_entry {
    std::string name;
    std::uint64_t size;
    time_t created;
    time_t modified;
    std::string download_url;
};

enum folder_type{
    ROOT,
    SEMESTER,
    COURSE,
    PERSONAL,
    DEFAULT,
};

struct folder {
    std::string name;
    folder_type type;

    std::string initial_folders_url;
    std::string folders_url;
    std::string files_url;

    std::map<std::string, folder> subfolders;
    std::map<std::string, file_entry> files;

    time_t children_loaded = 0;
};

struct course {
    std::string title;
    std::string start_semester_url;
    std::string folders_url;
};

using lru_key = std::pair<std::string, std::size_t>;

struct cached_chunk {
    std::string data;
    std::list<lru_key>::iterator lru_it;
};

struct file_cache {
    std::string download_url;
    std::map<std::size_t, cached_chunk> chunks;
    std::set<std::size_t> downloading;
};

folder fs_root;
std::shared_mutex fs_mutex;
std::mutex cache_mutex;
std::condition_variable cache_cv;
std::mutex curl_mutex;
std::mutex login_mutex;
std::ofstream debug_out;
CURL* curl;
std::size_t cached_bytes = 0;
std::map<std::string, file_cache> file_caches;
std::list<lru_key> lru_list;

template <typename T>
static void apply_json_value(const nlohmann::json& j, const char* key, T& target) {
    if (!j.contains(key))
        return;
    try {
        target = j.at(key).get<T>();
    } catch (const std::exception& e) {
        std::cerr << std::string("Invalid config value for ") << key << ": " << e.what() << std::endl;
    }
}

static void apply_json_time_t(const nlohmann::json& j, const char* key, time_t& target) {
    if (!j.contains(key))
        return;
    try {
        long long value = j.at(key).get<long long>();
        target = static_cast<time_t>(value);
    } catch (const std::exception& e) {
        std::cerr << std::string("Invalid config value for ") << key << ": " << e.what() << std::endl;
    }
}

static std::optional<std::filesystem::path> find_config_path() {
    const char* env = std::getenv("STUDIP_FS_CONFIG");
    if (env && *env)
        return std::filesystem::path(env);

    std::filesystem::path local = "studip_fs.json";
    try {
        if (std::filesystem::exists(local))
            return local;
    } catch (const std::filesystem::filesystem_error&) {
    }

    std::filesystem::path config_path;
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) {
        config_path = std::filesystem::path(xdg) / "studip_fs" / "config.json";
    } else {
        const char* home = std::getenv("HOME");
        if (home && *home)
            config_path = std::filesystem::path(home) / ".config" / "studip_fs" / "config.json";
    }
    if (!config_path.empty()) {
        try {
            if (std::filesystem::exists(config_path))
                return config_path;
        } catch (const std::filesystem::filesystem_error&) {
        }
    }

    return std::nullopt;
}

static std::filesystem::path get_default_config_path() {
    const char* env = std::getenv("STUDIP_FS_CONFIG");
    if (env && *env)
        return std::filesystem::path(env);

    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg)
        return std::filesystem::path(xdg) / "studip_fs" / "config.json";

    const char* home = std::getenv("HOME");
    if (home && *home)
        return std::filesystem::path(home) / ".config" / "studip_fs" / "config.json";

    return "studip_fs.json";
}

static nlohmann::ordered_json build_default_config_json() {
    return {
        {"username", settings.username},
        {"password", settings.password},
        {"page_limit", settings.page_limit},
        {"tree_cache", static_cast<long long>(settings.tree_cache)},
        {"request_delay", settings.request_delay},
        {"request_timeout", settings.request_timeout},
        {"chunk_size_fraction", settings.chunk_size_fraction},
        {"min_chunk_size", settings.min_chunk_size},
        {"max_chunk_size", settings.max_chunk_size},
        {"max_cache_bytes", settings.max_cache_bytes},
        {"cookie_file_path", settings.cookie_file_path},
        {"studip_base_url", settings.studip_base_url},
        {"studip_jsonapi_prefix", settings.studip_jsonapi_prefix},
        {"studip_jsonapi_url", settings.studip_jsonapi_url},
        {"sso_base_url", settings.sso_base_url},
        {"studip_saml_post_url", settings.studip_saml_post_url},
        {"shibboleth_login_url", settings.shibboleth_login_url},
        {"mount_point", settings.mount_point}
    };
}

static bool write_default_config(const std::filesystem::path& path) {
    try {
        if (path.has_parent_path())
            std::filesystem::create_directories(path.parent_path());
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to create config directory: " << e.what() << std::endl;
        return false;
    }

    std::ofstream out(path);
    if (!out) {
        std::cerr << "Could not write default config file: " << path.string() << std::endl;
        return false;
    }

    out << build_default_config_json().dump(4) << std::endl;
    return static_cast<bool>(out);
}

static int load_settings() {
    std::optional<std::filesystem::path> config_path = find_config_path();
    if (!config_path) {
        std::filesystem::path create_path = get_default_config_path();
        if (write_default_config(create_path)) {
            std::cerr << "Could not find config file. Created default one at "
                      << create_path.string() << std::endl;
            std::cerr << "You can set STUDIP_FS_CONFIG to change the path of the config file." << std::endl;
            config_path = create_path;
        } else {
            std::cerr << "Error: Could not find config file and failed to create a default one." << std::endl;
            return 1;
        }
    }

    std::ifstream in(*config_path);
    if (!in) {
        std::cerr << "Could not open config file: " << config_path->string() << std::endl;
        return 1;
    }

    try {
        nlohmann::json j;
        in >> j;
        apply_json_value(j, "page_limit", settings.page_limit);
        apply_json_time_t(j, "tree_cache", settings.tree_cache);
        apply_json_value(j, "request_delay", settings.request_delay);
        apply_json_value(j, "request_timeout", settings.request_timeout);
        apply_json_value(j, "chunk_size_fraction", settings.chunk_size_fraction);
        apply_json_value(j, "min_chunk_size", settings.min_chunk_size);
        apply_json_value(j, "max_chunk_size", settings.max_chunk_size);
        apply_json_value(j, "max_cache_bytes", settings.max_cache_bytes);
        apply_json_value(j, "cookie_file_path", settings.cookie_file_path);
        apply_json_value(j, "studip_base_url", settings.studip_base_url);
        apply_json_value(j, "studip_jsonapi_prefix", settings.studip_jsonapi_prefix);
        apply_json_value(j, "studip_jsonapi_url", settings.studip_jsonapi_url);
        apply_json_value(j, "sso_base_url", settings.sso_base_url);
        apply_json_value(j, "studip_saml_post_url", settings.studip_saml_post_url);
        apply_json_value(j, "shibboleth_login_url", settings.shibboleth_login_url);
        apply_json_value(j, "username", settings.username);
        apply_json_value(j, "password", settings.password);
        apply_json_value(j, "mount_point", settings.mount_point);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse config file " << config_path->string() << ": " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

static std::size_t compute_cache_chunk_size_locked(file_cache& cache, const file_entry& file) {
    double scaled = static_cast<double>(file.size) * settings.chunk_size_fraction;
    double min_size = static_cast<double>(settings.min_chunk_size);
    double max_size = static_cast<double>(settings.max_chunk_size);
    scaled += 10.0;
    if (scaled < min_size)
        scaled = min_size;
    if (scaled > max_size)
        scaled = max_size;
    return static_cast<std::size_t>(scaled);
}

static std::size_t get_cache_chunk_size(const std::string& path, const file_entry& file) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    return compute_cache_chunk_size_locked(file_caches[path], file);
}

static int log_err(const std::string& msg) {
    debug_out << msg << std::endl;
    return 1;
}

size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int serial_curl_request(
    const std::string& url,
    void* writedata,
    long post = 0L,
    const char* postfields = nullptr,
    long postfieldsize = 0L,
    long* http_code = nullptr,
    const char* range = nullptr){

    std::lock_guard<std::mutex> lock(curl_mutex);
    std::this_thread::sleep_for(std::chrono::milliseconds(settings.request_delay));
    debug_out << "Request: " << url << std::endl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, writedata);
    curl_easy_setopt(curl, CURLOPT_POST, post);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postfieldsize);
    curl_easy_setopt(curl, CURLOPT_RANGE, range);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, range ? 0L : 1L);
    if(!post){
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK){
        return log_err("curl request failed: " + url + ": " + curl_easy_strerror(res));
    }
    if (http_code) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    }
    return 0;
}

static std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex << std::uppercase;

    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    return escaped.str();
}

int response_parse_first_match(const std::string& re_string, const std::string& response, std::string& matched_string){
    std::smatch match;
    matched_string = "";
    if (std::regex_search(response, match, std::regex(re_string)))
        matched_string = match[1];
    if (matched_string.empty()){
        return log_err("Failed parsing response: could not find " + re_string);
    }
    return 0;
}

static void replace_all(std::string& s, const std::string& from, const std::string& to) {
    for (std::string::size_type pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size())
        s.replace(pos, from.size(), to);
}

static void split_path(const char* path, std::string& parent_path, std::string& name) {
    std::string full(path);
    auto pos = full.find_last_of('/');
    parent_path = (pos == 0) ? "/" : full.substr(0, pos);
    name = full.substr(pos + 1);
}

int studip_login(){
    std::lock_guard<std::mutex> lock(login_mutex);

    try {
        if (std::filesystem::exists(settings.cookie_file_path))
            std::filesystem::remove(settings.cookie_file_path);
    } catch (const std::filesystem::filesystem_error& e) {
        return log_err(std::string("Could not delete" + settings.cookie_file_path + ": ") + e.what());
    }

    const std::string& initial_url = settings.shibboleth_login_url;
    std::string initial_response;

    if (serial_curl_request(initial_url, &initial_response)) {
        return log_err("First request for login failed.");
    }
    std::string action_path;
    if (response_parse_first_match(ACTION_REGEX, initial_response, action_path)){
        return log_err("Could not find action_path from first response.");
    }
    std::string csrf_token;
    if (response_parse_first_match(CSRF_REGEX, initial_response, csrf_token)){
        return log_err("Could not find csrf_token from first response.");
    }

    std::string post_url;
    post_url = settings.sso_base_url + action_path;
    std::string escaped_token = url_encode(csrf_token);

    std::ostringstream post_fields;
    post_fields
        << "csrf_token=" << escaped_token
        << "&shib_idp_ls_exception.shib_idp_session_ss="
        << "&shib_idp_ls_success.shib_idp_session_ss=false"
        << "&shib_idp_ls_value.shib_idp_session_ss="
        << "&shib_idp_ls_exception.shib_idp_persistent_ss="
        << "&shib_idp_ls_success.shib_idp_persistent_ss=false"
        << "&shib_idp_ls_value.shib_idp_persistent_ss="
        << "&shib_idp_ls_supported="
        << "&_eventId_proceed=";

    std::string login_page_response;
    if (serial_curl_request(post_url, &login_page_response, 1L, post_fields.str().c_str(), (long)post_fields.str().size())) {
        return log_err("Second request for login failed.");
    }

    if (response_parse_first_match(ACTION_REGEX, login_page_response, action_path)){
        return log_err("Could not find action_path from second response.");
    }
    if (response_parse_first_match(CSRF_REGEX, login_page_response, csrf_token)){
        return log_err("Could not find csrf_token from second response.");
    }

    post_url = settings.sso_base_url + action_path;

    escaped_token = url_encode(csrf_token);
    
    post_fields.str("");
    post_fields
        << "csrf_token=" << escaped_token
        << "&j_username=" << settings.username << "&j_password=" << settings.password << "&_eventId_proceed=";

    std::string logged_in_response;
    if (serial_curl_request(post_url, &logged_in_response, 1L, post_fields.str().c_str(), (long)post_fields.str().size())) {
        return log_err("Third request for login failed.");
    }

    std::string relay_state;
    std::string saml_response;
    if (response_parse_first_match(RELAY_STATE_REGEX, logged_in_response, relay_state)){
        return log_err("Could not find relay_state from third response.");
    }
    if (response_parse_first_match(SAML_RESPONSE_REGEX, logged_in_response, saml_response)){
        return log_err("Could not find saml_response from third response.");
    }
    replace_all(relay_state, "&#x3a;", "%3A");
    replace_all(saml_response, "+", "%2B");
    post_url = settings.studip_saml_post_url;
    post_fields.str("");
    post_fields
        << "RelayState=" << relay_state
        << "&SAMLResponse=" << saml_response;

    std::string studip_response;
    if (serial_curl_request(post_url, &studip_response, 1L, post_fields.str().c_str(), (long)post_fields.str().size())) {
        return log_err("Fourth request for login failed.");
    }
    return 0;
}

int make_api_request(const std::string& route, std::string& result, int max_tries){
    if (max_tries < 1){
        return log_err("Reached maximum tries for API request and failed.");
    }
    std::string api_url = settings.studip_jsonapi_url + route;

    long http_code = 0;
    if (serial_curl_request(api_url, &result, 0L, nullptr, 0L, &http_code)){
        return log_err("API request failed: " + api_url);
    }
    if (http_code == 401){
        log_err("API request failed because of missing authorization, trying to login...");
        if (studip_login()){
            return log_err("Login after unauthorized API request failed.");
        }
        return make_api_request(route, result, max_tries - 1);
    }
    return 0;
}

static std::string add_page_params(const std::string& route, std::size_t offset, std::size_t limit){
    return route + (route.find('?') == std::string::npos ? "?" : "&") +
        "page%5Boffset%5D=" + std::to_string(offset) +
        "&page%5Blimit%5D=" + std::to_string(limit);
}

static int for_each_paged_item(
    const std::string& route,
    const std::function<int(const nlohmann::json&)>& handle_item)
{
    std::size_t offset = 0;
    std::size_t limit = settings.page_limit;

    while (true) {
        std::string json;
        std::string page_route = add_page_params(route, offset, limit);
        if (make_api_request(page_route, json, 2))
            return 1;

        auto parsed = nlohmann::json::parse(json, nullptr, false);
        if (parsed.is_discarded() || !parsed.contains("data") || !parsed["data"].is_array())
            return 1;

        const auto& data = parsed["data"];
        for (const auto& item : data) {
            int rc = handle_item(item);
            if (rc)
                return rc == 2 ? 0 : 1;
        }

        std::size_t page_count = data.size();
        if (!parsed.contains("meta") || !parsed["meta"].contains("page")) {
            if (page_count < limit)
                return 0;
            offset += page_count;
            continue;
        }

        const auto& page = parsed["meta"]["page"];
        std::size_t total = page.value("total", offset + page_count);
        limit = page.value("limit", limit);
        if (limit == 0)
            return 0;

        if (offset + limit >= total)
            return 0;

        if (page_count == 0)
            return 0;

        offset += limit;
    }
}

std::string remove_jsonapi_prefix(std::string str){
    const std::string& prefix = settings.studip_jsonapi_prefix;
    if (str.rfind(prefix, 0) == 0)
        return str.substr(prefix.size());
    return str; 
}

int parse_json(const std::string& json, const std::string& field, std::string* result) {
    try {
        nlohmann::json parsed = nlohmann::json::parse(json);

        nlohmann::json::json_pointer ptr(field);

        if (!parsed.contains(ptr)){
            return log_err("Could not find field " + field + " in JSON");
        }
            
        const nlohmann::basic_json<> value = parsed.at(ptr);

        *result = value.is_string() ? value.get<std::string>() : value.dump();
        return 0;
    }
    catch (const nlohmann::json::parse_error& e) {
        return log_err(std::string("Could not parse JSON: ") + e.what());
    }
    return 1;
}

int find_courses_route(std::string& courses_route, std::string& personal_files_route){
    std::string users_me;
    if (make_api_request("users/me", users_me, 2)){
        return log_err("User info request failed.");
    }
    std::string courses_field;
    if (parse_json(users_me, "/data/relationships/courses/links/related", &courses_field)){
        return log_err("Failed to find courses because of JSON error.");
    }
    std::string personal_files_field;
    if (parse_json(users_me, "/data/relationships/folders/links/related", &personal_files_field)){
        return log_err("Failed to find personal files because of JSON error.");
    }
    courses_route = remove_jsonapi_prefix(courses_field);
    personal_files_route = remove_jsonapi_prefix(personal_files_field);
    return 0;
}

static time_t parse_iso8601(const std::string& s){
    std::tm tm{};
    std::istringstream ss(s.substr(0, 19));
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail())
        return 0;

    if (s.size() <= 19)
        return std::mktime(&tm);

    long offset_seconds = 0;
    char tz_sign = s[19];
    if (tz_sign == 'Z') {
        offset_seconds = 0;
    } else if (tz_sign == '+' || tz_sign == '-') {
        if (s.size() < 25)
            return std::mktime(&tm);
        int hours = std::stoi(s.substr(20, 2));
        int minutes = std::stoi(s.substr(23, 2));
        offset_seconds = (hours * 3600L) + (minutes * 60L);
        if (tz_sign == '-')
            offset_seconds = -offset_seconds;
    } else {
        return std::mktime(&tm);
    }

    time_t utc_time = timegm(&tm);

    if (utc_time == static_cast<time_t>(-1))
        return std::mktime(&tm);

    return utc_time - offset_seconds;
}

static int parse_folder_item(const nlohmann::json& item, folder& out) {
    try {
        out.name = item.at("attributes").at("name").get<std::string>();
        std::replace(out.name.begin(), out.name.end(), '/', '-');
        out.folders_url = remove_jsonapi_prefix(item.at("relationships").at("folders").at("links").at("related").get<std::string>());
        out.files_url = remove_jsonapi_prefix(item.at("relationships").at("file-refs").at("links").at("related").get<std::string>());
        out.children_loaded = 0;
        out.type = folder_type::DEFAULT;
        return 0;
    } catch (...) {
        return 1;
    }
}

static int parse_file_item(const nlohmann::json& item, file_entry& out) {
    try {
        const auto& a = item.at("attributes");
        out.name = a.at("name").get<std::string>();
        out.size = a.at("filesize").get<std::uint64_t>();
        out.created = parse_iso8601(a.at("mkdate").get<std::string>());
        out.modified = parse_iso8601(a.at("chdate").get<std::string>());
        out.download_url = item.at("meta").at("download-url").get<std::string>();
        std::replace(out.name.begin(), out.name.end(), '/', '-');
        return 0;
    } catch (...) {
        return 1;
    }
}

static int parse_course_item(const nlohmann::json& item, course& out) {
    try {
        out.title = item.at("attributes").at("title").get<std::string>();
        out.start_semester_url = remove_jsonapi_prefix(item.at("relationships").at("start-semester").at("links").at("related").get<std::string>());
        out.folders_url = remove_jsonapi_prefix(item.at("relationships").at("folders").at("links").at("related").get<std::string>());
        std::replace(out.title.begin(), out.title.end(), '/', '-');
        return 0;
    } catch (...) {
        return 1;
    }
}

int load_folder_children(folder& node) {
    node.subfolders.clear();
    node.files.clear();

    if (!node.folders_url.empty()) {
        int rc = for_each_paged_item(node.folders_url, [&](const nlohmann::json& item) {
            folder f;
            if (parse_folder_item(item, f))
                return 1;
            node.subfolders.emplace(f.name, std::move(f));
            return 0;
        });
        if (rc)
            return 1;
    }

    if (!node.files_url.empty()) {
        int rc = for_each_paged_item(node.files_url, [&](const nlohmann::json& item) {
            file_entry f;
            if (parse_file_item(item, f))
                return 1;
            node.files.emplace(f.name, std::move(f));
            return 0;
        });
        if (rc)
            return 1;
    }

    node.children_loaded = time(nullptr);
    return 0;
}

int list_courses(const std::string& route, std::vector<course>& courses, std::set<std::string>& semesters){
    std::map<std::pair<std::string, std::string>, int> seen;

    int rc = for_each_paged_item(route, [&](const nlohmann::json& item) {
        course c;
        if (parse_course_item(item, c)) {
            log_err("Course had invalid data.");
            return 0;
        }
        semesters.insert(c.start_semester_url);
        auto key = std::make_pair(c.start_semester_url, c.title);
        auto [pos, inserted] = seen.insert({key, 1});
        if (!inserted) {
            pos->second++;
            c.title += " (" + std::to_string(pos->second) + ")";
        }
        courses.push_back(c);
        return 0;
    });
    if (rc)
        return log_err("Request to list courses failed.");
    return 0;
}

static folder* find_folder_by_path(folder& root, const std::string& path){
    if (path == "/" || path.empty())
        return &root;

    std::string trimmed = path;
    if (trimmed.front() == '/')
        trimmed.erase(0, 1);

    std::stringstream ss(trimmed);
    std::string segment;

    folder* current = &root;

    while (std::getline(ss, segment, '/')) {
        if (segment.empty())
            continue;

        auto it = current->subfolders.find(segment);

        if (it == current->subfolders.end())
            return nullptr;

        current = &it->second;
    }

    return current;
}

static const file_entry* find_file_by_path(const char* path){
    std::string parent_path;
    std::string name;
    split_path(path, parent_path, name);

    folder* parent = find_folder_by_path(fs_root, parent_path);
    if (!parent)
        return nullptr;

    auto it = parent->files.find(name);
    if (it == parent->files.end())
        return nullptr;
    return &it->second;
}

int reload_fs_structure(const std::string& path){
    std::unique_lock<std::shared_mutex> lock(fs_mutex);

    folder* node = find_folder_by_path(fs_root, path);
    if (!node) {
        return 0;
    }
    if(std::time(nullptr) - settings.tree_cache < node->children_loaded){
        return 0;
    }

    if (path == "/" || node->type == folder_type::ROOT || node->type == folder_type::SEMESTER) {
        fs_root.name.clear();
        fs_root.folders_url.clear();
        fs_root.files_url.clear();
        fs_root.subfolders.clear();
        fs_root.files.clear();
        fs_root.type = folder_type::ROOT;
        
        std::string courses_route;
        std::string personal_files_route;
        if (find_courses_route(courses_route, personal_files_route)) {
            return 1;
        }

        std::vector<course> courses;
        std::set<std::string> semester_routes;
        if (list_courses(courses_route, courses, semester_routes)) {
            return 1;
        }

        folder personal_files;
        personal_files.name = "Personal Files";
        personal_files.initial_folders_url = personal_files_route;
        personal_files.files_url.clear();
        personal_files.subfolders.clear();
        personal_files.children_loaded = 0; 
        personal_files.type = folder_type::PERSONAL;
        fs_root.subfolders.emplace("Personal Files", personal_files);

        std::map<std::string, std::string> semester_titles;
        for (const auto& sem_route : semester_routes) {
            std::string semester_json;
            if (make_api_request(sem_route, semester_json, 2)) {
                return 1;
            }

            std::string title;
            if (parse_json(semester_json, "/data/attributes/title", &title)) {
                return 1;
            }

            std::replace(title.begin(), title.end(), '/', '-');
            semester_titles.emplace(sem_route, title);
        }

        std::map<std::string, folder*> semester_nodes;

        for (const auto& [route, title] : semester_titles) {
            folder sem;
            sem.name = title;
            sem.folders_url.clear();
            sem.files_url.clear();
            sem.type = folder_type::SEMESTER;
            sem.children_loaded = 0;

            auto [it, inserted] = fs_root.subfolders.emplace(sem.name, std::move(sem));
            semester_nodes[route] = &it->second;
        }
        
        for (const auto& c : courses) {
            auto it = semester_nodes.find(c.start_semester_url);
            if (it == semester_nodes.end())
                continue;

            folder course;
            course.name = c.title;
            course.type = folder_type::COURSE;
            course.initial_folders_url = c.folders_url;
            course.files_url.clear();
            course.children_loaded = 0;
            
            it->second->subfolders.emplace(course.name, std::move(course));
            it->second->children_loaded = std::time(nullptr);
        }
        fs_root.children_loaded = std::time(nullptr);
        return 0;
    }

    if (node->type == folder_type::COURSE || node->type == folder_type::PERSONAL) {
        node->subfolders.clear();
        node->files.clear();
        node->children_loaded = 0;

        if (node->initial_folders_url == "") {
            return load_folder_children(*node);
        }

        try {
            int rc = for_each_paged_item(node->initial_folders_url, [&](const nlohmann::json& item) {
                try {
                    if (item.at("attributes")
                            .at("folder-type")
                            .get<std::string>() != "RootFolder") {
                        return 0;
                    }

                    node->folders_url = remove_jsonapi_prefix(
                        item.at("relationships")
                            .at("folders")
                            .at("links")
                            .at("related")
                            .get<std::string>()
                    );

                    node->files_url = remove_jsonapi_prefix(
                        item.at("relationships")
                            .at("file-refs")
                            .at("links")
                            .at("related")
                            .get<std::string>()
                    );
                    return 2;
                }
                catch (...) {
                    return 1;
                }
            });
            if (rc)
                return 1;
        }
        catch (...) {
            return 1;
        }
    }

    return load_folder_children(*node);
}

static const file_entry* find_file_in_folder(
    const folder& dir,
    const std::string& name)
{
    auto it = dir.files.find(name);
    if (it == dir.files.end())
        return nullptr;
    return &it->second;
}

static int download_range(
    const std::string& url,
    std::uint64_t offset,
    std::size_t length,
    std::string& out,
    int max_tries)
{
    if (length == 0) {
        out.clear();
        return 0;
    }
    if (max_tries < 1){
        return log_err("Reached maximum tries for API request and failed.");
    }
    std::string range = std::to_string(offset) + "-" +
        std::to_string(offset + length - 1);
    long http_code = 0;
    if (serial_curl_request(url, &out, 0L, nullptr, 0L, &http_code, range.c_str()))
        return 1;
    if (http_code == 302){
        log_err("File download failed because of missing authorization, trying to login...");
        if (studip_login()){
            return log_err("Login after unauthorized API request failed.");
        }
        return download_range(url, offset, length, out, max_tries - 1);
    }
    if (http_code != 206 && http_code != 200)
        return log_err("Download request failed with status " + std::to_string(http_code));
    return 0;
}

static int evict_cache_locked(std::size_t needed_bytes) {
    while (cached_bytes + needed_bytes > settings.max_cache_bytes) {
        if (lru_list.empty())
            return 1;

        lru_key key = lru_list.back();
        lru_list.pop_back();

        auto cache_it = file_caches.find(key.first);
        if (cache_it == file_caches.end())
            continue;

        auto& chunks = cache_it->second.chunks;
        auto chunk_it = chunks.find(key.second);
        if (chunk_it == chunks.end())
            continue;

        cached_bytes -= chunk_it->second.data.size();
        chunks.erase(chunk_it);
        if (chunks.empty())
            file_caches.erase(cache_it);
    }
    return 0;
}

static int get_cached_chunk(
    const std::string& path,
    const file_entry& file,
    std::size_t chunk_index,
    std::string& out)
{
    std::size_t chunk_size = 0;
    {
        std::unique_lock<std::mutex> lock(cache_mutex);
        auto& cache = file_caches[path];
        while (true) {
            chunk_size = compute_cache_chunk_size_locked(cache, file);
            auto chunk_it = cache.chunks.find(chunk_index);
            if (chunk_it != cache.chunks.end()) {
                lru_list.splice(lru_list.begin(), lru_list, chunk_it->second.lru_it);
                chunk_it->second.lru_it = lru_list.begin();
                out = chunk_it->second.data;
                return 0;
            }
            if (cache.downloading.count(chunk_index) == 0) {
                cache.downloading.insert(chunk_index);
                break;
            }
            cache_cv.wait(lock);
        }
    }

    std::uint64_t start = static_cast<std::uint64_t>(chunk_index) * chunk_size;
    std::size_t length = std::min<std::size_t>(chunk_size, file.size - start);

    std::string data;
    std::string download_url = settings.studip_base_url + "/" + file.download_url;
    if (download_range(download_url, start, length, data, 2)) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto cache_it = file_caches.find(path);
        if (cache_it != file_caches.end()) {
            cache_it->second.downloading.erase(chunk_index);
        }
        cache_cv.notify_all();
        return 1;
    }

    {
        std::unique_lock<std::mutex> lock(cache_mutex);
        auto& cache = file_caches[path];
        std::size_t current_chunk_size = compute_cache_chunk_size_locked(cache, file);

        if(evict_cache_locked(data.size())){
            log_err("File cache is full!");
            cache.downloading.erase(chunk_index);
            cache_cv.notify_all();
            out = data;
            return 0;
        };

        cached_bytes += data.size();
        lru_list.emplace_front(path, chunk_index);
        cache.chunks.emplace(
            chunk_index,
            cached_chunk{data, lru_list.begin()});
        cache.downloading.erase(chunk_index);
        cache_cv.notify_all();
        out = data;
    }
    return 0;
}

static int fs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info*){
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode  = S_IFDIR | 0777;
        stbuf->st_nlink = 2;
        return 0;
    }

    std::string parent_path;
    std::string name;
    split_path(path, parent_path, name);

    std::shared_lock<std::shared_mutex> lock(fs_mutex);
    folder* parent = find_folder_by_path(fs_root, parent_path);
    if (!parent)
        return -ENOENT;

    auto sub_it = parent->subfolders.find(name);
    if (sub_it != parent->subfolders.end()) {
        stbuf->st_mode  = S_IFDIR | 0777;
        stbuf->st_nlink = 2;
        return 0;
    }

    const file_entry* file = find_file_in_folder(*parent, name);
    if (file) {
        stbuf->st_mode  = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size  = file->size;

        stbuf->st_ctime = file->created;
        stbuf->st_mtime = file->modified;
        stbuf->st_atime = stbuf->st_mtime;

        return 0;
    }

    return -ENOENT;
}

static int fs_open(const char* path, struct fuse_file_info* fi){
    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EACCES;

    std::string parent_path;
    std::string name;
    split_path(path, parent_path, name);
    if (reload_fs_structure(parent_path))
        return -EIO;

    std::shared_lock<std::shared_mutex> lock(fs_mutex);
    folder* parent = find_folder_by_path(fs_root, parent_path);
    if (!parent)
        return -ENOENT;

    const file_entry* file = find_file_in_folder(*parent, name);
    if (!file)
        return -ENOENT;

    return 0;
}

static int fs_read(
    const char* path,
    char* buf,
    size_t size,
    off_t offset,
    struct fuse_file_info*)
{
    if (size == 0)
        return 0;

    std::string parent_path;
    std::string name;
    split_path(path, parent_path, name);
    if (reload_fs_structure(parent_path))
        return -EIO;

    file_entry file;
    {
        std::shared_lock<std::shared_mutex> lock(fs_mutex);
        folder* parent = find_folder_by_path(fs_root, parent_path);
        if (!parent)
            return -ENOENT;

        const file_entry* found = find_file_in_folder(*parent, name);
        if (!found)
            return -ENOENT;
        file = *found;
    }

    if (offset >= static_cast<off_t>(file.size))
        return 0;

    std::size_t remaining = static_cast<std::size_t>(
        std::min<std::uint64_t>(file.size - static_cast<std::uint64_t>(offset), size));

    std::size_t chunk_size = get_cache_chunk_size(path, file);
    std::size_t total = 0;
    while (total < remaining) {
        std::uint64_t current_offset = static_cast<std::uint64_t>(offset) + total;
        std::size_t chunk_index = static_cast<std::size_t>(current_offset / chunk_size);
        std::size_t chunk_offset = static_cast<std::size_t>(current_offset % chunk_size);
        std::size_t to_copy = std::min(remaining - total, chunk_size - chunk_offset);

        std::string chunk_data;
        if (get_cached_chunk(path, file, chunk_index, chunk_data))
            return -EIO;

        if (chunk_offset >= chunk_data.size())
            break;

        std::size_t available = chunk_data.size() - chunk_offset;
        std::size_t copy_size = std::min(to_copy, available);
        memcpy(buf + total, chunk_data.data() + chunk_offset, copy_size);
        total += copy_size;
        if (copy_size < to_copy)
            break;
    }

    return static_cast<int>(total);
}

static int fs_readdir(
    const char* path,
    void* buf,
    fuse_fill_dir_t filler,
    off_t,
    struct fuse_file_info*,
    enum fuse_readdir_flags)
{
    if (reload_fs_structure(path))
        return -EIO;

    std::shared_lock<std::shared_mutex> lock(fs_mutex);
    folder* dir = find_folder_by_path(fs_root, path);
    if (!dir)
        return -ENOENT;

    filler(buf, ".",  nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    for (const auto& [name, sub] : dir->subfolders) {
        filler(buf, name.c_str(), nullptr, 0,
               (fuse_fill_dir_flags)0);
    }

    for (const auto& [name, file] : dir->files) {
        filler(buf, name.c_str(), nullptr, 0,
               (fuse_fill_dir_flags)0);
    }

    return 0;
}

static const struct fuse_operations fs_ops = {
    .getattr = fs_getattr,
    .open = fs_open,
    .read = fs_read,
    .readdir = fs_readdir,
};

int main() {
    debug_out.open("/tmp/studdebug_out.txt", std::ios_base::app);
    debug_out << std::endl << "-------------------------------------New Session-------------------------------------" << std::endl; 
    if(load_settings()){
        return 1;
    }
    if(settings.username == "[YOUR USERNAME]"){
        return 1;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, settings.cookie_file_path.c_str());
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, settings.cookie_file_path.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, settings.request_timeout);
    if(studip_login()){
        std::cerr << "Initial login failed! studip_fs terminated." << std::endl;
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    if (settings.mount_point.empty()) {
        std::cerr << "Mount point is empty. Set mount_point in the config file." << std::endl;
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    int fuse_argc = 4;
    char *fuse_argv[] = {
        (char*)"studip_fs",
        (char*)settings.mount_point.c_str(),
        (char*)"-o",
        (char*)"ro",
        nullptr
    };
    int ret = fuse_main(fuse_argc, fuse_argv, &fs_ops, nullptr);

    try {
        if (std::filesystem::exists(settings.cookie_file_path))
            std::filesystem::remove(settings.cookie_file_path);
    } catch (const std::filesystem::filesystem_error& e) {
        return log_err(std::string("Could not delete" + settings.cookie_file_path + ": ") + e.what());
    }

    debug_out.close();
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return ret;
}
