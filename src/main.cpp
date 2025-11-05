#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <string>
#include <regex>
#include <curl/curl.h>
#include "secrets/login.h"

static size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int response_parse_first_match(std::string re_string, std::string response, std::string& matched_string){
    std::smatch match;
    matched_string = "";
    if (std::regex_search(response, match, std::regex(re_string)))
        matched_string = match[1];
    if(matched_string.empty()){
        std::cerr << "failed parsing response: could not find " << re_string << std::endl;
        return 1;
    }
    return 0;
}

int post(CURL*& curl, std::string url, std::string post_data, std::string& response){

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK){
        std::cerr << "POST-Request failed " << url << std::endl;
        return 1;
    }
    return 0;
}

int studip_login_init(CURL*& curl){
    //delete cookies.txt if it exists
    const std::filesystem::path cookieFile = "cookies.txt";
    try {
        if (std::filesystem::exists(cookieFile))
            std::filesystem::remove(cookieFile);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Could not delete cookies.txt: " << e.what() << std::endl;
        return 1;
    }
    //initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        std::cerr << "Could not initialize curl." << std::endl; 
        return 1;
    }
    //set curl options
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    return 0;
}

int studip_login(CURL*& curl, std::string username, std::string password){
    CURLcode res;
    
    if(studip_login_init(curl)){
        std::cerr << "Login initialization failed." << std::endl;
        return 1;
    }
    
    //first request
    const char* initial_url =
        "https://studip.uni-hannover.de/Shibboleth.sso/Login?"
        "target=https%3A%2F%2Fstudip.uni-hannover.de%2Fdispatch.php%2Flogin%3Fsso%3Dshib%26again%3Dyes%26cancel_login%3D1"
        "&entityID=https%3A%2F%2Fsso.idm.uni-hannover.de%2Fidp%2Fshibboleth";
    std::string initial_response;

    curl_easy_setopt(curl, CURLOPT_URL, initial_url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &initial_response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "First request for login failed: " << curl_easy_strerror(res) << "\n";
        return 1;
    }
    //parse first response
    std::string action_path;
    if (response_parse_first_match(R"(action\s*=\s*["']([^"']+)["'])", initial_response, action_path)){
        std::cerr << "Could not find action_path from first response." << std::endl;
        return 1;
    }
    std::string csrf_token;
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", initial_response, csrf_token)){
        std::cerr << "Could not find csrf_token from first response." << std::endl;
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
        std::cerr << "Could not find action_path from second response." << std::endl;
        return 1;
    }
    if (response_parse_first_match(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])", login_page_response, csrf_token)){
        std::cerr << "Could not find csrf_token from second response." << std::endl;
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
        std::cerr << "Could not find relay_state from third response." << std::endl;
        return 1;
    }
    if (response_parse_first_match(R"(name="SAMLResponse"\s+value="([^"]+)\")", logged_in_response, saml_response)){
        std::cerr << "Could not find saml_response from third response." << std::endl;
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
    std::cout << studip_response;
    return 0;
}

void cleanup(CURL*& curl){
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return;
}

int main() {
    CURL* curl;
    studip_login(curl, USERNAME, PASSWORD);
    cleanup(curl);
    return 0;
}
