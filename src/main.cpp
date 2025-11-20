#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <algorithm>
#include <iostream>
#include <ostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <string>
#include <regex>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <set>
#include <mutex>
#include "secrets/login.h"

#define MAX_RESULTS 300

static std::map<std::string, std::vector<std::string>> fs_structure;
static std::mutex reload_mutex;

static std::ofstream debug_out;

class course {
public:
    std::string title;
    std::string start_semester_url;
    std::string folders_url;
};


static size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int response_parse_first_match(const std::string& re_string, const std::string& response, std::string& matched_string){
    std::smatch match;
    matched_string = "";
    if (std::regex_search(response, match, std::regex(re_string)))
        matched_string = match[1];
    if (matched_string.empty()){
        debug_out << "Failed parsing response: could not find " << re_string << std::endl;
        return 1;
    }
    return 0;
}

int post(CURL*& curl, const std::string& url, const std::string& post_data, std::string& response){
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK){
        debug_out << "POST-Request failed " << url << std::endl;
        return 1;
    }
    return 0;
}

int initialize_curl(CURL*& curl){
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        debug_out << "Could not initialize curl." << std::endl; 
        return 1;
    }
    //set curl options
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "/tmp/studcookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "/tmp/studcookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    return 0;
}

int studip_login(CURL*& curl, const std::string& username, const std::string& password){

    //delete studcookies.txt if it exists
    const std::filesystem::path cookieFile = "/tmp/studcookies.txt";
    try {
        if (std::filesystem::exists(cookieFile))
            std::filesystem::remove(cookieFile);
    } catch (const std::filesystem::filesystem_error& e) {
        debug_out << "Could not delete studcookies.txt: " << e.what() << std::endl;
        return 1;
    }

    CURLcode res;
    
    //first request
    const char* initial_url =
        "https://studip.uni-hannover.de/Shibboleth.sso/Login?"
        "target=https%3A%2F%2Fstudip.uni-hannover.de%2Fdispatch.php%2Flogin%3Fsso%3Dshib%26again%3Dyes%26cancel_login%3D1"
        "&entityID=https%3A%2F%2Fsso.idm.uni-hannover.de%2Fidp%2Fshibboleth";
    std::string initial_response;

    curl_easy_setopt(curl, CURLOPT_URL, initial_url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &initial_response);
    curl_easy_setopt(curl, CURLOPT_POST, 0L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        debug_out << "First request for login failed: " << curl_easy_strerror(res) << "\n";
        return 1;
    }
    //parse first response
    std::string action_path;
    if (response_parse_first_match(R"(action\s*=\s*["']([^"']+)["'])", initial_response, action_path)){
        debug_out << "Could not find action_path from first response." << std::endl;
        return 1;
    }
    std::string csrf_token;
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", initial_response, csrf_token)){
        debug_out << "Could not find csrf_token from first response." << std::endl;
        return 1;
    }

    //second request
    std::string post_url;
    post_url = "https://sso.idm.uni-hannover.de" + action_path;
    char* escaped_token = curl_easy_escape(curl, csrf_token.c_str(), 0);

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
    curl_free(escaped_token);

    std::string login_page_response;
    post(curl, post_url, post_fields.str(), login_page_response);

    //parse second response
    if (response_parse_first_match(R"(action\s*=\s*["']([^"']+)["'])", login_page_response, action_path)){
        debug_out << "Could not find action_path from second response." << std::endl;
        return 1;
    }
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", login_page_response, csrf_token)){
        debug_out << "Could not find csrf_token from second response." << std::endl;
        return 1;
    }

    post_url = "https://sso.idm.uni-hannover.de" + action_path;

    escaped_token = curl_easy_escape(curl, csrf_token.c_str(), 0);
    
    //third request
    post_fields.str("");
    post_fields
        << "csrf_token=" << escaped_token
        << "&j_username=" << USERNAME << "&j_password=" << PASSWORD << "&_eventId_proceed=";
    curl_free(escaped_token);

    std::string logged_in_response;
    post(curl, post_url, post_fields.str(), logged_in_response);

    //parse third response
    std::string relay_state;
    std::string saml_response;
    if (response_parse_first_match(R"(name="RelayState"\s+value="([^"]+)\")", logged_in_response, relay_state)){
        debug_out << "Could not find relay_state from third response." << std::endl;
        return 1;
    }
    if (response_parse_first_match(R"(name="SAMLResponse"\s+value="([^"]+)\")", logged_in_response, saml_response)){
        debug_out << "Could not find saml_response from third response." << std::endl;
        return 1;
    }
    const std::string colon = "&#x3a;";
    std::string::size_type colon_pos = 0;
    while ((colon_pos = relay_state.find(colon, colon_pos)) != std::string::npos) {
        relay_state.replace(colon_pos, colon.length(), "%3A");
        colon_pos += 1;
    }
    const std::string plus = "+";
    std::string::size_type plus_pos = 0;
    while ((plus_pos = saml_response.find(plus, plus_pos)) != std::string::npos) {
        saml_response.replace(plus_pos, plus.length(), "%2B");
        plus_pos += 1;
    }
    //fourth request

    post_url = "https://studip.uni-hannover.de/Shibboleth.sso/SAML2/POST";
    post_fields.str("");
    post_fields
        << "RelayState=" << relay_state
        << "&SAMLResponse=" << saml_response;

    std::string studip_response;
    post(curl, post_url, post_fields.str(), studip_response);
    return 0;
}

int make_api_request(CURL*& curl, const std::string& route, std::string& result, int max_tries){
    if (max_tries < 1){
        debug_out << "Reached maximum tries for API request and failed.";
        return 1;
    }
    std::string api_url = "https://studip.uni-hannover.de/jsonapi.php/v1/" + route;
    curl_easy_setopt(curl, CURLOPT_POST, 0L);
    curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK){
        debug_out << "API request failed: " << curl_easy_strerror(res) << std::endl;
        return 1;
    }
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 401){
        debug_out << "API request failed because of missing authorization, trying to login..." << std::endl;
        if (studip_login(curl, USERNAME, PASSWORD)){
            debug_out << "Login after unauthorized API request failed." << std::endl;
            return 1;
        }
        make_api_request(curl, route, result, max_tries - 1);
    }
    return 0;
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
            debug_out << "Could not find field " << field << " in JSON" << std::endl;
            return 1;
        }
            
        const nlohmann::basic_json<> value = parsed.at(ptr);

        if (!value.is_string()) {
            *result = value.dump();
        }
        else {
            *result = value.get<std::string>();
        }
        return 0;
    }
    catch (const nlohmann::json::parse_error& e) {
        debug_out << "Could not parse JSON: " << e.what() << std::endl;
        return 1;
    }
    return 1;
}

int find_courses_route(CURL*& curl, std::string& route){
    std::string users_me;
    if (make_api_request(curl, "users/me", users_me, 2)){
        debug_out << "User info request failed." << std::endl;
        return 1;
    }
    std::string courses_field;
    if (parse_json(users_me, "/data/relationships/courses/links/related", &courses_field)){
        debug_out << "Failed to find courses because of JSON error." << std::endl;
        return 1;
    }
    std::ostringstream courses_route;
    courses_route << remove_jsonapi_prefix(courses_field) << "?page%5Boffset%5D=0&page%5Blimit%5D=" << MAX_RESULTS;
    route = courses_route.str();
    return 0;
}

int list_courses(CURL*& curl, const std::string& route, std::vector<course>& courses, std::set<std::string>& semesters){
    std::string courses_json;
    if (make_api_request(curl, route, courses_json, 2)){
        debug_out << "Request to list courses failed." << std::endl;
        return 1;
    }

    //keep track of title/semester-combinations to rename duplicates
    std::map<std::pair<std::string, std::string>, int> seen;

    try {
        nlohmann::json parsed = nlohmann::json::parse(courses_json);
        if (!parsed.contains("data")) {
            debug_out << "Courses response does not have data field" << std::endl;
            return 1;
        }
        const nlohmann::json& data = parsed["data"];

        for (auto it = data.begin(); it != data.end(); ++it) {
            const nlohmann::json& item = it.value();
            course c;

            //title
            try {
                c.title = item.at("attributes").at("title").get<std::string>();
            } catch (...) {
                c.title = "";
            }

            //start-semester
            try {
                c.start_semester_url = remove_jsonapi_prefix(item.at("relationships").at("start-semester").at("links").at("related").get<std::string>());
                semesters.insert(c.start_semester_url);
            } catch (...) {
                c.start_semester_url = "";
            }

            //folders
            try {
                c.folders_url = remove_jsonapi_prefix(item.at("relationships").at("folders").at("links").at("related").get<std::string>());
            } catch (...) {
                c.folders_url.clear();
            }

            if (c.title.empty() || c.start_semester_url.empty() || c.folders_url.empty()) {
                debug_out << "Course had invalid data." << std::endl;
                continue;
            }

            std::replace(c.title.begin(), c.title.end(), '/', '-');
            //detect duplicates and rename them
            auto key = std::make_pair(c.start_semester_url, c.title);
            auto [pos, inserted] = seen.insert({key, 1});
            if (!inserted) {
                pos->second++;
                c.title += " (" + std::to_string(pos->second) + ")";
            }
            courses.push_back(c);
        }
        return 0;
    }
    catch (const nlohmann::json::parse_error& e) {
        debug_out << "Could not parse courses JSON: " << e.what() << std::endl;
        return 1;
    }
}

int reload_fs_structure() {
    std::lock_guard<std::mutex> lock(reload_mutex);

    CURL* curl;
    if (initialize_curl(curl)){
        debug_out << "Curl initialization failed." << std::endl;
        return 1;
    }

    std::string courses_route;
    if (find_courses_route(curl, courses_route)){
        debug_out << "Could not find courses URL during reload." << std::endl;
        curl_easy_cleanup(curl);
        return 1;
    }
    std::vector<course> courses;
    std::set<std::string> semesters;
    if (list_courses(curl, courses_route, courses, semesters)){
        debug_out << "Could not parse courses during reload." << std::endl;
        curl_easy_cleanup(curl);
        return 1;
    }
    std::map<std::string, std::string> semesters_map;
    for (const std::string &semester_route : semesters){
        std::string semester_json;
        if (make_api_request(curl, semester_route, semester_json, 2)){
            debug_out << "Semester request failed during reload." << std::endl;
            curl_easy_cleanup(curl);
            return 1;
        }
        std::string semester_title;
        if (parse_json(semester_json, "/data/attributes/title", &semester_title)){
            debug_out << "Failed to find semester name during reload." << std::endl;
            curl_easy_cleanup(curl);
            return 1;
        }
        //remove '/' from folder names
        std::replace(semester_title.begin(), semester_title.end(), '/', '-');
        semesters_map.insert({semester_route, semester_title});
    }

    std::map<std::string, std::vector<std::string>> new_structure;
    for (const auto &c : courses) {
        std::string sem_title = semesters_map[c.start_semester_url];
        new_structure[sem_title].push_back(c.title);
    }
    fs_structure.swap(new_structure);

    curl_easy_cleanup(curl);
    return 0;
}

static int fs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        return 0;
    }

    std::string p(path + 1);
    if (fs_structure.contains(p)) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        return 0;
    }

    for (const auto &pair : fs_structure) {
        for (const auto &course : pair.second) {
            if (p == pair.first + "/" + course) {
                stbuf->st_mode = S_IFDIR | 0555;
                stbuf->st_nlink = 2;
                return 0;
            }
        }
    }

    return -ENOENT;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info *, enum fuse_readdir_flags) {
    if (reload_fs_structure()) {
        return -EIO;
    }

    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    std::string p(path + 1);
    if (strcmp(path, "/") == 0) {
        for (const auto &pair : fs_structure)
            filler(buf, pair.first.c_str(), nullptr, 0, (fuse_fill_dir_flags)0);
        return 0;
    }

    auto it = fs_structure.find(p);
    if (it != fs_structure.end()) {
        for (const auto &course : it->second){
            filler(buf, course.c_str(), nullptr, 0, (fuse_fill_dir_flags)0);
        }     
        return 0;
    }

    return -ENOENT;
}

static const struct fuse_operations fs_ops = {
    .getattr = fs_getattr,
    .readdir = fs_readdir,
};


int main() {
    CURL* curl;
    debug_out.open("/tmp/studdebug_out.txt", std::ios_base::app);
    if (initialize_curl(curl)){
        debug_out << "Curl initialization failed." << std::endl;
        return 1;
    }
    studip_login(curl, USERNAME, PASSWORD);

    curl_easy_cleanup(curl);

    int fuse_argc = 2;
    char *fuse_argv[] = { (char*)"studip_fs", (char*)"test", nullptr };

    int ret = fuse_main(fuse_argc, fuse_argv, &fs_ops, nullptr);

    debug_out.close();
    return ret;
}