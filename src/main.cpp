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
#include <shared_mutex>
#include <thread>
#include "secrets/login.h"

const std::size_t PAGE_LIMIT = 100;
const time_t TREE_CACHE = 300;
const int REQUEST_DELAY = 100;

struct file_entry {
    std::string name;
    std::uint64_t size;
    time_t created;
    time_t modified;
    std::string download_url;
};

struct folder {
    std::string name;

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

folder fs_root;
std::shared_mutex fs_mutex;
std::mutex curl_mutex;
std::mutex login_mutex;
std::ofstream debug_out;
CURL* curl;

static int log_err(const std::string& msg) {
    debug_out << msg << std::endl;
    return 1;
}

size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int serial_curl_request(const std::string& url, void* writedata, long post = 0L, const char* postfields = nullptr, long postfieldsize = 0L, long* http_code = nullptr){
    std::lock_guard<std::mutex> lock(curl_mutex);
    std::this_thread::sleep_for(std::chrono::milliseconds(REQUEST_DELAY));
    debug_out << "Request: " << url << std::endl;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, writedata);
    curl_easy_setopt(curl, CURLOPT_POST, post);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postfieldsize);
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

int studip_login(const std::string& username, const std::string& password){
    std::lock_guard<std::mutex> lock(login_mutex);

    const std::filesystem::path cookieFile = "/tmp/studcookies.txt";
    try {
        if (std::filesystem::exists(cookieFile))
            std::filesystem::remove(cookieFile);
    } catch (const std::filesystem::filesystem_error& e) {
        return log_err(std::string("Could not delete studcookies.txt: ") + e.what());
    }

    const char* initial_url =
        "https://studip.uni-hannover.de/Shibboleth.sso/Login?"
        "target=https%3A%2F%2Fstudip.uni-hannover.de%2Fdispatch.php%2Flogin%3Fsso%3Dshib%26again%3Dyes%26cancel_login%3D1"
        "&entityID=https%3A%2F%2Fsso.idm.uni-hannover.de%2Fidp%2Fshibboleth";
    std::string initial_response;

    if (serial_curl_request(initial_url, &initial_response)) {
        return log_err("First request for login failed.");
    }
    std::string action_path;
    if (response_parse_first_match(R"(action\s*=\s*["']([^"']+)["'])", initial_response, action_path)){
        return log_err("Could not find action_path from first response.");
    }
    std::string csrf_token;
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", initial_response, csrf_token)){
        return log_err("Could not find csrf_token from first response.");
    }

    std::string post_url;
    post_url = "https://sso.idm.uni-hannover.de" + action_path;
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

    if (response_parse_first_match(R"(action\s*=\s*["']([^"']+)["'])", login_page_response, action_path)){
        return log_err("Could not find action_path from second response.");
    }
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", login_page_response, csrf_token)){
        return log_err("Could not find csrf_token from second response.");
    }

    post_url = "https://sso.idm.uni-hannover.de" + action_path;

    escaped_token = url_encode(csrf_token);
    
    post_fields.str("");
    post_fields
        << "csrf_token=" << escaped_token
        << "&j_username=" << USERNAME << "&j_password=" << PASSWORD << "&_eventId_proceed=";

    std::string logged_in_response;
    if (serial_curl_request(post_url, &logged_in_response, 1L, post_fields.str().c_str(), (long)post_fields.str().size())) {
        return log_err("Third request for login failed.");
    }

    std::string relay_state;
    std::string saml_response;
    if (response_parse_first_match(R"(name="RelayState"\s+value="([^"]+)\")", logged_in_response, relay_state)){
        return log_err("Could not find relay_state from third response.");
    }
    if (response_parse_first_match(R"(name="SAMLResponse"\s+value="([^"]+)\")", logged_in_response, saml_response)){
        return log_err("Could not find saml_response from third response.");
    }
    replace_all(relay_state, "&#x3a;", "%3A");
    replace_all(saml_response, "+", "%2B");
    post_url = "https://studip.uni-hannover.de/Shibboleth.sso/SAML2/POST";
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
    std::string api_url = "https://studip.uni-hannover.de/jsonapi.php/v1/" + route;

    long http_code = 0;
    if (serial_curl_request(api_url, &result, 0L, nullptr, 0L, &http_code)){
        return log_err("API request failed: " + api_url);
    }
    if (http_code == 401){
        debug_out << "API request failed because of missing authorization, trying to login..." << std::endl;
        if (studip_login(USERNAME, PASSWORD)){
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
    std::size_t limit = PAGE_LIMIT;

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
    const std::string prefix = "/jsonapi.php/v1/";
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

int find_courses_route(std::string& route){
    std::string users_me;
    if (make_api_request("users/me", users_me, 2)){
        return log_err("User info request failed.");
    }
    std::string courses_field;
    if (parse_json(users_me, "/data/relationships/courses/links/related", &courses_field)){
        debug_out << users_me;
        return log_err("Failed to find courses because of JSON error.");
    }
    route = remove_jsonapi_prefix(courses_field);
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
            debug_out << "Course had invalid data." << std::endl;
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
    if(std::time(nullptr) - TREE_CACHE < node->children_loaded){
        return 0;
    }

    if (path == "/" || (node->folders_url.empty() && node->files_url.empty())) {
        fs_root.name.clear();
        fs_root.folders_url.clear();
        fs_root.files_url.clear();
        fs_root.subfolders.clear();
        fs_root.files.clear();
        fs_root.children_loaded = std::time(nullptr);

        std::string courses_route;
        if (find_courses_route(courses_route)) {
            return 1;
        }

        std::vector<course> courses;
        std::set<std::string> semester_routes;
        if (list_courses(courses_route, courses, semester_routes)) {
            return 1;
        }

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

            course.folders_url = c.folders_url;
            course.files_url.clear();
            course.children_loaded = 0;

            it->second->subfolders.emplace(course.name, std::move(course));
            it->second->children_loaded = std::time(nullptr);
        }
        return 0;
    }

    if (!node->folders_url.empty() && node->files_url.empty()) {
        node->subfolders.clear();
        node->files.clear();
        node->children_loaded = 0;

        std::string root_folders_url;
        std::string root_files_url;

        try {
            int rc = for_each_paged_item(node->folders_url, [&](const nlohmann::json& item) {
                try {
                    if (item.at("attributes")
                            .at("folder-type")
                            .get<std::string>() != "RootFolder") {
                        return 0;
                    }

                    root_folders_url = remove_jsonapi_prefix(
                        item.at("relationships")
                            .at("folders")
                            .at("links")
                            .at("related")
                            .get<std::string>()
                    );

                    root_files_url = remove_jsonapi_prefix(
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

        if (!root_folders_url.empty()) {
            node->folders_url = root_folders_url;
            node->files_url   = root_files_url;
            int rc = load_folder_children(*node);
            return rc;
        }
        return 0;
    }

    int rc = load_folder_children(*node);
    return rc;
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

static int fs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info*){
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode  = S_IFDIR | 0555;
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
        stbuf->st_mode  = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        return 0;
    }

    const file_entry* file = find_file_in_folder(*parent, name);
    if (file) {
        stbuf->st_mode  = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size  = file->size;

        stbuf->st_ctime = file->created;
        stbuf->st_mtime = file->modified;
        stbuf->st_atime = stbuf->st_mtime;

        return 0;
    }

    return -ENOENT;
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
    .readdir = fs_readdir,
};

int main() {
    debug_out.open("/tmp/studdebug_out.txt", std::ios_base::app);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "/tmp/studcookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "/tmp/studcookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    if(studip_login(USERNAME, PASSWORD)){
        std::cerr << "Initial login failed! studip_fs terminated." << std::endl;
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    int fuse_argc = 2;
    char *fuse_argv[] = { (char*)"studip_fs", (char*)"test", nullptr };

    int ret = fuse_main(fuse_argc, fuse_argv, &fs_ops, nullptr);
    debug_out.close();
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return ret;
}
