#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <ncrypt.h>       
#include <iostream>
#include <string>
#include <fstream>
#include <map>

#pragma comment(lib, "Cryptui.lib")
#pragma comment(lib, "ncrypt.lib") 
#pragma comment(lib, "crypt32.lib") // Added for CryptQueryObject and CertContext

std::wstring utf8_to_utf16(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string utf16_to_utf8(const std::wstring& str) {
    if (str.empty()) return "";
    auto utf8len = ::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), NULL, 0, NULL, NULL);
    if (utf8len == 0) return "";
    std::string utf8Str;
    utf8Str.resize(utf8len);
    ::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), &utf8Str[0], utf8Str.size(), NULL, NULL);
    return utf8Str;
}

struct NCryptHandleWrapper {
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;

    ~NCryptHandleWrapper() {
        if (hKey) ::NCryptFreeObject(hKey);
        if (hProv) ::NCryptFreeObject(hProv);
    }
};

std::map<std::string, std::wstring> readProperties(const std::wstring& filename) {
    std::map<std::string, std::wstring> props;
    std::ifstream file(utf16_to_utf8(filename));
    if (!file.is_open()) return props;

    std::string line;
    bool firstLine = true;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (firstLine) {
            if (line.size() >= 3 && (unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF) {
                line = line.substr(3);
            }
            firstLine = false;
        }
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            props[key] = utf8_to_utf16(value);
        }
    }
    return props;
}

bool token_logon(const std::wstring& providerName,
    const std::wstring& containerName,
    const std::wstring& tokenPin,
    NCryptHandleWrapper& handles) {

    SECURITY_STATUS status;

    status = ::NCryptOpenStorageProvider(&handles.hProv, providerName.c_str(), 0);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"NCryptOpenStorageProvider failed, error " << std::hex << std::showbase << status << L"\n";
        return false;
    }

    status = ::NCryptOpenKey(handles.hProv, &handles.hKey, containerName.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"NCryptOpenKey failed, error " << std::hex << std::showbase << status << L"\n";
        return false;
    }

    DWORD cbPinSize = (DWORD)((tokenPin.length() + 1) * sizeof(wchar_t));
    status = ::NCryptSetProperty(handles.hKey, NCRYPT_PIN_PROPERTY,
        (PBYTE)tokenPin.c_str(), cbPinSize, 0);

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"NCryptSetProperty (PIN) failed, error " << std::hex << std::showbase << status << L"\n";
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::wcerr << L"usage: etokensign.exe <properties file path> <path to file to sign>\n";
        return 1;
    }

    const std::wstring fileToSign = argv[2];
    std::map<std::string, std::wstring> props = readProperties(argv[1]);

    if (props.empty()) {
        std::wcerr << L"Could not open or read properties file.\n";
        return 1;
    }

    const std::wstring providerName = props["provider"];
    const std::wstring certFile = props["certFile"];
    const std::wstring containerName = props["containerName"];
    const std::wstring tokenPin = props["tokenPin"];
    const std::wstring timestampUrl = props["timestampUrl"];

    NCryptHandleWrapper cngHandles;
    if (!token_logon(providerName, containerName, tokenPin, cngHandles)) {
        std::wcerr << L"Failed to logon to the token and set the PIN.\n";
        return 1;
    }

    // 1. Load the standalone .cer file into memory
    PCCERT_CONTEXT pCertContext = NULL;
    if (!::CryptQueryObject(CERT_QUERY_OBJECT_FILE, certFile.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0,
        NULL, NULL, NULL, NULL, NULL, (const void**)&pCertContext)) {
        std::wcerr << L"Failed to load certificate file: " << certFile << L"\n";
        return 1;
    }

    // 2. Explicitly staple our unlocked CNG handle to the loaded certificate
    CERT_KEY_CONTEXT keyContext = {};
    keyContext.cbSize = sizeof(keyContext);
    keyContext.hNCryptKey = cngHandles.hKey;
    keyContext.dwKeySpec = CERT_NCRYPT_KEY_SPEC; // Tells Windows this is a modern CNG key

    if (!::CertSetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, 0, &keyContext)) {
        std::wcerr << L"Failed to bind CNG key to certificate context.\n";
        ::CertFreeCertificateContext(pCertContext);
        return 1;
    }

    CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO extInfo = {};
    extInfo.dwSize = sizeof(extInfo);
    extInfo.pszHashAlg = szOID_NIST_sha256;

    // 3. Pass the pre-paired certificate context instead of file paths
    CRYPTUI_WIZ_DIGITAL_SIGN_INFO signInfo = {};
    signInfo.dwSize = sizeof(signInfo);
    signInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
    signInfo.pwszFileName = fileToSign.c_str();

    // CRITICAL FIX: Use the loaded CERT context, bypassing the legacy lookup
    signInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
    signInfo.pSigningCertContext = pCertContext;

    signInfo.pwszTimestampURL = timestampUrl.c_str();
    signInfo.pSignExtInfo = &extInfo;

    // 4. Sign the file!
    if (!::CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, NULL, NULL, &signInfo, NULL)) {
        std::wcerr << L"CryptUIWizDigitalSign failed, error " << std::hex
            << std::showbase << ::GetLastError() << L"\n";
        ::CertFreeCertificateContext(pCertContext);
        return 1;
    }

    std::wcout << L"Successfully signed " << fileToSign << L"\n";

    // Clean up
    ::CertFreeCertificateContext(pCertContext);

    // Detach the key handle from our wrapper to prevent a double-free crash, 
    // since freeing the cert context often frees the attached handle automatically.
    cngHandles.hKey = NULL;

    return 0;
}