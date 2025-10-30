#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <regex>
#include <curl/curl.h>

static size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static size_t WriteToFile(void* contents, size_t size, size_t nmemb, void* userp) {
    std::ofstream* ofs = static_cast<std::ofstream*>(userp);
    ofs->write(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

int main() {
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        std::cerr << "Fehler: curl konnte nicht initialisiert werden.\n";
        return 1;
    }

    // 1. GET-Anfrage
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

    // Optional: Ausgabe des HTML-Codes zur Kontrolle
    // std::cout << initial_response << std::endl;

    // 2. Extraktion von Action und CSRF-Token
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
    if (action_path.rfind("http", 0) == 0)
        post_url = action_path;
    else
        post_url = "https://sso.idm.uni-hannover.de" + action_path;

    // 3. POST-Daten vorbereiten
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

    std::string post_data = post_fields.str();

    // 5. POST-Anfrage
    std::ofstream output_file("initial.html", std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Fehler: Datei initial.html konnte nicht geöffnet werden.\n";
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, post_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.size());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToFile);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_file);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // automatische Entkompression

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        std::cerr << "Fehler bei zweiter Anfrage: " << curl_easy_strerror(res) << "\n";
    else
        std::cout << "Ergebnis erfolgreich in initial.html gespeichert.\n";

    output_file.close();

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
