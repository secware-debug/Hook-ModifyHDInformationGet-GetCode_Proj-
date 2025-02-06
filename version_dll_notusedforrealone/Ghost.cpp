#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0601
#include "Ghost.h"

#ifdef DEBUG
#pragma comment(lib, "libcryptod.lib")
#pragma comment(lib, "libssld.lib")
#else
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#endif // DEBUG
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <openssl/aes.h>
#include <sstream>  // <-- Added for std::stringstream
#include <bitset>
#include <fstream>

#include <setupapi.h>
#include <devguid.h>
#include <initguid.h>
#include <winioctl.h>
#include <iomanip>
#include <setupapi.h>
#include "resource.h"

#pragma comment(lib, "iphlpapi.lib")   // Link against IP Helper API
#pragma comment(lib, "setupapi.lib")   // Link against Setup API
#pragma comment(lib, "Setupapi.lib")

void DebugLog(const std::string& message) {
    OutputDebugStringA(message.c_str());
}
// Function to get the MAC address using GetAdaptersAddresses API
std::string GetMACAddress() {
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    IP_ADAPTER_INFO adapterInfo[16];  // Allocate enough space for multiple adapters

    DWORD result = GetAdaptersInfo(adapterInfo, &outBufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {  // Buffer too small? Allocate dynamically
        std::vector<unsigned char> buffer(outBufLen);
        IP_ADAPTER_INFO* pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
        result = GetAdaptersInfo(pAdapterInfo, &outBufLen);
        if (result == NO_ERROR) {
            // Use the first adapter found
            std::ostringstream macStream;
            for (size_t i = 0; i < pAdapterInfo->AddressLength; i++) {
                if (i > 0) macStream << ":";
                macStream << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
            }
            return macStream.str();
        }
    }
    else if (result == NO_ERROR) {
        // Use the first adapter found
        std::ostringstream macStream;
        for (size_t i = 0; i < adapterInfo[0].AddressLength; i++) {
            if (i > 0) macStream << ":";
            macStream << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)adapterInfo[0].Address[i];
        }
        return macStream.str();
    }

    std::cerr << "Error: Unable to retrieve MAC address." << std::endl;
    return "";
}

std::vector<std::string> EnumeratePhysicalDrives() {
    std::vector<std::string> drives;
    GUID DiskGUID = GUID_DEVINTERFACE_DISK;
    HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&DiskGUID, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    if (hDeviceInfo == INVALID_HANDLE_VALUE) {
        std::ostringstream oss;
        oss << "Failed to get device info set. Error: " << GetLastError() << "\n";
        DebugLog(oss.str());
        return drives;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    // Iterate through all disk devices
    for (DWORD index = 0; SetupDiEnumDeviceInterfaces(hDeviceInfo, NULL, &DiskGUID, index, &deviceInterfaceData); ++index) {
        // Get the required buffer size
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            std::ostringstream oss;
            oss << "Failed to get required buffer size. Error: " << GetLastError() << "\n";
            DebugLog(oss.str());
            continue;
        }

        // Allocate space for the device interface detail
        auto deviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);
        if (!deviceInterfaceDetailData) {
            DebugLog("Failed to allocate memory for device interface detail.\n");
            continue;
        }
        deviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        // Get the device path
        if (SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &deviceInterfaceData, deviceInterfaceDetailData, requiredSize, NULL, NULL)) {
            // Add the device path to the list
            drives.push_back(deviceInterfaceDetailData->DevicePath);
            std::ostringstream oss;
            oss << "Found drive: " << deviceInterfaceDetailData->DevicePath << "\n";
            DebugLog(oss.str());
        }
        else {
            std::ostringstream oss;
            oss << "Failed to get device interface detail. Error: " << GetLastError() << "\n";
            DebugLog(oss.str());
        }

        free(deviceInterfaceDetailData);
    }

    // Clean up
    SetupDiDestroyDeviceInfoList(hDeviceInfo);
    return drives;
}

std::string GetDiskID() {
    std::vector<std::string> drives = EnumeratePhysicalDrives();
    DebugLog("Physical Drives Found:\n");
    for (const auto& drive : drives) {
        DebugLog(drive + "\n");
    }
    HANDLE hDevice = CreateFileA(drives[0].c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to open disk device." << std::endl;
        return "";
    }

    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER header = {};
    DWORD bytesReturned = 0;

    // First call to get required buffer size
    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
        &header, sizeof(header), &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        std::cerr << "Error: Failed to get storage descriptor size." << std::endl;
        return "";
    }

    std::vector<BYTE> buffer(header.Size);

    // Second call to get actual storage device descriptor
    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
        buffer.data(), (DWORD)buffer.size(), &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        std::cerr << "Error: Failed to get disk serial number." << std::endl;
        return "";
    }

    CloseHandle(hDevice);

    // Extract serial number from buffer
    STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    if (descriptor->SerialNumberOffset == 0) {
        std::cerr << "Error: No serial number found." << std::endl;
        return "";
    }

    // Convert serial number from raw bytes to string
    const char* serialNumber = reinterpret_cast<const char*>(buffer.data() + descriptor->SerialNumberOffset);
    return std::string(serialNumber);
}

// Function to deobfuscate the MAC Address
std::string DeobfuscateMAC(const std::string& obfuscated, const std::string& diskID) {
    if (obfuscated.size() != 16) {
        //  "Error: Invalid obfuscated MAC length";
        return "";
    }

    std::string reversedMAC;

    // Reverse XOR operation to extract original MAC characters
    for (size_t i = 0; i < 12; ++i) {
        reversedMAC += obfuscated[i] ^ (diskID[i % diskID.size()] & 0x5F);
    }

    // Reverse the string back to original order
    std::reverse(reversedMAC.begin(), reversedMAC.end());

    // Reconstruct original MAC by reinserting colons at appropriate positions
    std::string originalMAC;
    for (size_t i = 0; i < reversedMAC.size(); ++i) {
        if (i > 0 && i % 2 == 0) {
            originalMAC += ":";  // Insert colons after every two characters
        }
        originalMAC += reversedMAC[i];
    }

    return originalMAC;
}

// Function to decrypt AES-encrypted data with a given key
std::string DecryptAES(const std::vector<unsigned char>& encryptedData, const std::string& key) {
    AES_KEY aesKey;
    std::vector<unsigned char> decryptedData(AES_BLOCK_SIZE, 0);
    std::vector<unsigned char> keyBytes(16, 0);

    // Use first 16 bytes of key (AES-128)
    for (size_t i = 0; i < key.length() && i < 16; i++) {
        keyBytes[i] = key[i];
    }

    AES_set_decrypt_key(keyBytes.data(), 128, &aesKey);
    AES_decrypt(encryptedData.data(), decryptedData.data(), &aesKey);

    // Convert to string and trim trailing null characters
    std::string result(decryptedData.begin(), decryptedData.end());
    result.erase(std::find(result.begin(), result.end(), '\0'), result.end()); // Remove null padding

    return result;
}

std::string ObfuscateMAC(const std::string& mac, const std::string& diskID) {
    std::string cleanMAC;

    for (char c : mac) {
        if (c != ':') {
            cleanMAC += c;
        }
    }

    if (cleanMAC.size() != 12) {
        std::cerr << "Error: Invalid MAC address format after cleaning.\n";
        return "";
    }

    std::reverse(cleanMAC.begin(), cleanMAC.end());

    std::string obfuscatedMAC;
    for (size_t i = 0; i < cleanMAC.size(); ++i) {
        obfuscatedMAC += cleanMAC[i] ^ (diskID[i % diskID.size()] & 0x5F);
    }

    for (size_t i = 0; i < 4; ++i) {
        obfuscatedMAC += (cleanMAC[i] ^ 0xA5);
    }

    return obfuscatedMAC;
}

std::string ToHexString(const std::string& input) {
    std::ostringstream hexStream;
    for (unsigned char c : input) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return hexStream.str();
}

// Function to read binary data from a file into a vector
std::vector<unsigned char> ReadEncryptedFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return {}; // Return an empty vector if the file cannot be opened
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string fileContent = buffer.str();
    if (fileContent.length() != 32) {
        return {};
    }
    std::vector<unsigned char> byteVector;

    // Convert the string content to bytes
    for (size_t i = 0; i < fileContent.length(); i += 2) {
        if (i + 1 < fileContent.length()) {
            std::string byteString = fileContent.substr(i, 2);            
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            byteVector.push_back(byte);
        }
    }

    return byteVector; // Return the vector of bytes
}

std::string getDataPath() {

    std::string result = std::string("C:\\Windows\\System32\\getcode.key");
    return result;
}

void WriteAuthCodeToFile(HWND hwndDlg, const std::string& filePath) {
    char authCode[256]; // Buffer to store the text
    GetDlgItemText(hwndDlg, IDC_EDIT_AUTHCODE, authCode, sizeof(authCode));

    // Open the file in overwrite mode
    std::ofstream outFile(filePath, std::ios::binary | std::ios::trunc);
    if (outFile) {
        outFile.write(authCode, strlen(authCode)); // Write the content of authCode
        outFile.close(); // Close the file
    }
    else {
        // Handle error opening the file
        MessageBox(hwndDlg, "Error opening file for writing.", "Error", MB_OK | MB_ICONERROR);
    }
}

bool IsValid() {
    std::string macAddress = GetMACAddress();

    std::string diskID = GetDiskID();
    std::vector<unsigned char> encryptedData = ReadEncryptedFile(getDataPath());
    if (encryptedData.size() != 16) {
        return FALSE;
    }
    std::string decryptedMAC = DecryptAES(encryptedData, getDataPath());
    std::string originalMAC = DeobfuscateMAC(decryptedMAC, getDataPath());
    OutputDebugStringA(("Disk ID: " + diskID).c_str());
    //OutputDebugStringA(("Encrypted data: " + encryptedData).c_str());
    OutputDebugStringA(("Decrypted data: " + decryptedMAC).c_str());

    OutputDebugStringA(("MAC address from key file: " + originalMAC).c_str());
    OutputDebugStringA(("MAC address of this machine: " + macAddress).c_str());
    if (macAddress == originalMAC) {
        return TRUE;
    }
    else
        return FALSE;
}

LRESULT CALLBACK DialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG:
        //HWND wndHWID = GetDlgItem(hwndDlg, IDC_STATIC_HWID);
        OutputDebugStringA(GetDiskID().c_str());
        SetDlgItemText(hwndDlg, IDC_EDIT_HWID, ToHexString(ObfuscateMAC(GetMACAddress(), getDataPath())).c_str());
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            
            // Optional: Do something with the authCode
            //MessageBox(hwndDlg, authCode, "Auth Code1", MB_OK);
            WriteAuthCodeToFile(hwndDlg, getDataPath());
            if (IsValid()) {
                EndDialog(hwndDlg, IDOK);
            }
            else
                ExitProcess(0);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            // Handle Cancel button
            EndDialog(hwndDlg, IDCANCEL);
            ExitProcess(0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

void Validate(HMODULE hModule) {
    if (!IsValid()) {
        DialogBox(hModule, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DialogProc);
    }
    OutputDebugStringA("end of validation");
}