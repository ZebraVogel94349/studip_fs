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

int main() {
    const std::filesystem::path cookieFile = "cookies.txt";

    try {
        if (std::filesystem::exists(cookieFile))
            std::filesystem::remove(cookieFile);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Fehler beim Löschen: " << e.what() << '\n';
    }

    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        std::cerr << "Fehler: curl konnte nicht initialisiert werden.\n";
        return 1;
    }

    // 1. Anfrage
    const char* initial_url =
        "https://studip.uni-hannover.de/Shibboleth.sso/Login?"
        "target=https%3A%2F%2Fstudip.uni-hannover.de%2Fdispatch.php%2Flogin%3Fsso%3Dshib%26again%3Dyes%26cancel_login%3D1"
        "&entityID=https%3A%2F%2Fsso.idm.uni-hannover.de%2Fidp%2Fshibboleth";

    std::string initial_response;

    curl_easy_setopt(curl, CURLOPT_URL, initial_url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &initial_response);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // automatische Dekompression

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "Fehler bei erster Anfrage: " << curl_easy_strerror(res) << "\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    // 1. Parsen
    std::smatch match;
    std::regex action_re(R"(action\s*=\s*["']([^"']+)["'])");
    std::regex token_re(R"(<input[^>]*name\s*=\s*["']csrf_token["'][^>]*value\s*=\s*["']([^"']+)["'])");

    std::string action_path;
    std::string csrf_token;

    if (std::regex_search(initial_response, match, action_re))
        action_path = match[1];
    if (std::regex_search(initial_response, match, token_re))
        csrf_token = match[1];

    if (action_path.empty() || csrf_token.empty()) {
        std::cerr << "Fehler: Formular konnte nicht korrekt geparst werden.\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    std::string post_url;
    post_url = "https://sso.idm.uni-hannover.de" + action_path;
    char* escaped_token = curl_easy_escape(curl, csrf_token.c_str(), 0);

    //2. Anfrage
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

    std::string post_data = post_fields.str();

    std::string login_page_response;

    curl_easy_setopt(curl, CURLOPT_URL, post_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &login_page_response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK){
        std::cerr << "Fehler bei zweiter Anfrage: " << curl_easy_strerror(res) << "\n";
        return 1;
    }

    //2. Parsen
    action_path = "";
    csrf_token = "";

    if (std::regex_search(login_page_response, match, action_re))
        action_path = match[1];
    if (std::regex_search(login_page_response, match, token_re))
        csrf_token = match[1];

    if (action_path.empty() || csrf_token.empty()) {
        std::cerr << "Fehler: Formular konnte nicht korrekt geparst werden.\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    post_url = "https://sso.idm.uni-hannover.de" + action_path;

    escaped_token = curl_easy_escape(curl, csrf_token.c_str(), 0);
    
    //3. Anfrage
    post_fields.str("");
    post_fields
        << "csrf_token=" << escaped_token
        << "&j_username=" << USERNAME << "&j_password=" << PASSWORD << "&_eventId_proceed=";
    curl_free(escaped_token);

    post_data = post_fields.str();

    std::string logged_in_response;

    curl_easy_setopt(curl, CURLOPT_URL, post_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &logged_in_response);

    res = curl_easy_perform(curl);

    //3. Parsen
    std::regex relay_re(R"(name="RelayState"\s+value="([^"]+)\")");
    std::regex saml_re(R"(name="SAMLResponse"\s+value="([^"]+)\")");

    std::string relay_state;
    std::string saml_response;
    
    if (std::regex_search(logged_in_response, match, relay_re))
        relay_state = match[1];
    if (std::regex_search(logged_in_response, match, saml_re))
        saml_response = match[1];

    if (relay_state.empty() || saml_response.empty()) {
        std::cerr << "Fehler: Formular konnte nicht korrekt geparst werden.\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
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
    //4. Anfrage

    post_url = "https://studip.uni-hannover.de/Shibboleth.sso/SAML2/POST";
    post_fields.str("");
    post_fields
        << "RelayState=" << relay_state
        << "&SAMLResponse=" << saml_response;

    post_data = post_fields.str();
    
    std::string studip_response;

    curl_easy_setopt(curl, CURLOPT_URL, post_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &studip_response);

    res = curl_easy_perform(curl);
    std::cout << studip_response;

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
