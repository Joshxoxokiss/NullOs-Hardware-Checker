#include "..\Headers\HardwareChecker.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "wbemuuid.lib")

// Helper function to read registry values
std::string ReadRegistryValue(const std::string& subKey, const std::string& valueName) {
    HKEY hKey;
    std::string result = "";
    
    // Convert std::string to wide string for Windows API
    std::wstring wSubKey(subKey.begin(), subKey.end());
    std::wstring wValueName(valueName.begin(), valueName.end());
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wSubKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dataType;
        DWORD dataSize = 0;
        
        // Get the size of the data
        if (RegQueryValueExW(hKey, wValueName.c_str(), NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS) {
            if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
                // Allocate buffer for the string
                wchar_t* buffer = new wchar_t[dataSize / sizeof(wchar_t) + 1];
                if (RegQueryValueExW(hKey, wValueName.c_str(), NULL, &dataType, (LPBYTE)buffer, &dataSize) == ERROR_SUCCESS) {
                    // Convert wide string back to std::string
                    buffer[dataSize / sizeof(wchar_t)] = L'\0';
                    char* mbBuffer = new char[dataSize + 1];
                    size_t convertedChars = 0;
                    wcstombs_s(&convertedChars, mbBuffer, dataSize + 1, buffer, _TRUNCATE);
                    result = std::string(mbBuffer);
                    delete[] mbBuffer;
                }
                delete[] buffer;
            } else if (dataType == REG_DWORD) {
                DWORD value;
                dataSize = sizeof(DWORD);
                if (RegQueryValueExW(hKey, wValueName.c_str(), NULL, &dataType, (LPBYTE)&value, &dataSize) == ERROR_SUCCESS) {
                    std::stringstream ss;
                    ss << value;
                    result = ss.str();
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    return result;
}

// Helper function to initialize COM
bool InitializeCOM() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return false;
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    return true;
}

// Helper function to get WMI service
IWbemLocator* GetWbemLocator() {
    IWbemLocator* pLoc = NULL;
    HRESULT hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hres)) {
        return NULL;
    }

    return pLoc;
}

// Helper function to connect to WMI namespace
IWbemServices* ConnectToWMI(IWbemLocator* pLoc) {
    IWbemServices* pSvc = NULL;
    HRESULT hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        return NULL;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        return NULL;
    }

    return pSvc;
}

// Helper function to execute WMI query
IEnumWbemClassObject* ExecuteWMIQuery(IWbemServices* pSvc, const wchar_t* query) {
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hres)) {
        return NULL;
    }

    return pEnumerator;
}

// Helper function to get string property from WMI object
std::string GetStringProperty(IWbemClassObject* pclsObj, const wchar_t* propertyName) {
    VARIANT vtProp;
    VariantInit(&vtProp);
    HRESULT hr = pclsObj->Get(propertyName, 0, &vtProp, 0, 0);
    
    std::string result = "";
    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
        _bstr_t bstrVal(vtProp.bstrVal);
        result = (char*)bstrVal;
    }
    
    VariantClear(&vtProp);
    return result;
}

// Helper function to get unsigned long long property from WMI object
std::string GetUint64Property(IWbemClassObject* pclsObj, const wchar_t* propertyName) {
    VARIANT vtProp;
    VariantInit(&vtProp);
    HRESULT hr = pclsObj->Get(propertyName, 0, &vtProp, 0, 0);
    
    std::string result = "";
    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
        result = _com_util::ConvertBSTRToString(vtProp.bstrVal);
    } else if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
        std::stringstream ss;
        ss << vtProp.lVal;
        result = ss.str();
    } else if (SUCCEEDED(hr) && vtProp.vt == VT_UI8) {
        std::stringstream ss;
        ss << vtProp.ullVal;
        result = ss.str();
    }
    
    VariantClear(&vtProp);
    return result;
}

std::vector<std::string> HardwareChecker::getDiskInfo() {
    std::vector<std::string> diskInfo;
    
    if (!InitializeCOM()) {
        return diskInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return diskInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return diskInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Model, SerialNumber FROM Win32_DiskDrive");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return diskInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string model = GetStringProperty(pclsObj, L"Model");
        std::string serial = GetStringProperty(pclsObj, L"SerialNumber");
        
        if (!model.empty() && !serial.empty()) {
            diskInfo.push_back(model);
            diskInfo.push_back(serial);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return diskInfo;
}

std::string HardwareChecker::getCpuInfo() {
    std::string cpuInfo = "";
    
    if (!InitializeCOM()) {
        return cpuInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return cpuInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return cpuInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT ProcessorId FROM Win32_Processor");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return cpuInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        cpuInfo = GetStringProperty(pclsObj, L"ProcessorId");
        
        pclsObj->Release();
        break; // Only get the first CPU
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return cpuInfo;
}

std::string HardwareChecker::getBiosInfo() {
    std::string biosInfo = "";
    
    if (!InitializeCOM()) {
        return biosInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return biosInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return biosInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT SerialNumber FROM Win32_BIOS");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return biosInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        biosInfo = GetStringProperty(pclsObj, L"SerialNumber");
        
        pclsObj->Release();
        break; // Only get the first BIOS
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return biosInfo;
}

std::string HardwareChecker::getMotherboardInfo() {
    std::string motherboardInfo = "";
    
    if (!InitializeCOM()) {
        return motherboardInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return motherboardInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return motherboardInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT SerialNumber FROM Win32_BaseBoard");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return motherboardInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        motherboardInfo = GetStringProperty(pclsObj, L"SerialNumber");
        
        pclsObj->Release();
        break; // Only get the first motherboard
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return motherboardInfo;
}

std::string HardwareChecker::getSmbiosUuid() {
    std::string uuid = "";
    
    if (!InitializeCOM()) {
        return uuid;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return uuid;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return uuid;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT UUID FROM Win32_ComputerSystemProduct");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return uuid;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        uuid = GetStringProperty(pclsObj, L"UUID");
        
        pclsObj->Release();
        break; // Only get the first UUID
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return uuid;
}

std::string HardwareChecker::getSystemManufacturer() {
    std::string manufacturer = "";
    
    if (!InitializeCOM()) {
        return manufacturer;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return manufacturer;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return manufacturer;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Manufacturer FROM Win32_ComputerSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return manufacturer;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        manufacturer = GetStringProperty(pclsObj, L"Manufacturer");
        
        pclsObj->Release();
        break;
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return manufacturer;
}

std::string HardwareChecker::getSystemModel() {
    std::string model = "";
    
    if (!InitializeCOM()) {
        return model;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return model;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return model;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Model FROM Win32_ComputerSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return model;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        model = GetStringProperty(pclsObj, L"Model");
        
        pclsObj->Release();
        break;
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return model;
}

std::string HardwareChecker::getTotalPhysicalMemory() {
    std::string memory = "";
    
    if (!InitializeCOM()) {
        return memory;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return memory;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return memory;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return memory;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        memory = GetUint64Property(pclsObj, L"TotalPhysicalMemory");
        
        pclsObj->Release();
        break;
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return memory;
}

std::vector<std::string> HardwareChecker::getGraphicsCards() {
    std::vector<std::string> graphicsCards;
    
    if (!InitializeCOM()) {
        return graphicsCards;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return graphicsCards;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return graphicsCards;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Name, AdapterRAM FROM Win32_VideoController");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return graphicsCards;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string name = GetStringProperty(pclsObj, L"Name");
        std::string ram = GetUint64Property(pclsObj, L"AdapterRAM");
        
        if (!name.empty()) {
            graphicsCards.push_back(name);
            graphicsCards.push_back(ram);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return graphicsCards;
}

std::string HardwareChecker::getOSVersion() {
    std::string osVersion = "";
    
    if (!InitializeCOM()) {
        return osVersion;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return osVersion;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return osVersion;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Caption, Version FROM Win32_OperatingSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return osVersion;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string caption = GetStringProperty(pclsObj, L"Caption");
        std::string version = GetStringProperty(pclsObj, L"Version");
        
        osVersion = caption + " " + version;
        
        pclsObj->Release();
        break;
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return osVersion;
}

std::vector<std::string> HardwareChecker::getInstalledPrinters() {
    std::vector<std::string> printers;
    
    if (!InitializeCOM()) {
        return printers;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return printers;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return printers;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Name, PortName FROM Win32_Printer");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return printers;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string name = GetStringProperty(pclsObj, L"Name");
        std::string port = GetStringProperty(pclsObj, L"PortName");
        
        if (!name.empty()) {
            printers.push_back(name);
            printers.push_back(port);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return printers;
}

std::vector<std::string> HardwareChecker::getSoundDevices() {
    std::vector<std::string> soundDevices;
    
    if (!InitializeCOM()) {
        return soundDevices;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return soundDevices;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return soundDevices;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Name, Manufacturer FROM Win32_SoundDevice");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return soundDevices;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string name = GetStringProperty(pclsObj, L"Name");
        std::string manufacturer = GetStringProperty(pclsObj, L"Manufacturer");
        
        if (!name.empty()) {
            soundDevices.push_back(name);
            soundDevices.push_back(manufacturer);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return soundDevices;
}

std::vector<std::string> HardwareChecker::getGPUInfo() {
    std::vector<std::string> gpuInfo;
    
    if (!InitializeCOM()) {
        return gpuInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return gpuInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return gpuInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT Name, AdapterCompatibility, DriverVersion FROM Win32_VideoController");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return gpuInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string name = GetStringProperty(pclsObj, L"Name");
        std::string compatibility = GetStringProperty(pclsObj, L"AdapterCompatibility");
        std::string driverVersion = GetStringProperty(pclsObj, L"DriverVersion");
        
        if (!name.empty()) {
            gpuInfo.push_back(name);
            gpuInfo.push_back(compatibility);
            gpuInfo.push_back(driverVersion);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return gpuInfo;
}

std::string HardwareChecker::getRAMInfo() {
    std::string ramInfo = "";
    
    if (!InitializeCOM()) {
        return ramInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return ramInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return ramInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return ramInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        ramInfo = GetUint64Property(pclsObj, L"TotalPhysicalMemory");
        
        pclsObj->Release();
        break;
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return ramInfo;
}

std::string HardwareChecker::getVRAMInfo() {
    std::string vramInfo = "";
    
    if (!InitializeCOM()) {
        return vramInfo;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return vramInfo;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return vramInfo;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT AdapterRAM FROM Win32_VideoController");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return vramInfo;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        vramInfo = GetUint64Property(pclsObj, L"AdapterRAM");
        
        pclsObj->Release();
        break; // Get VRAM of primary GPU
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return vramInfo;
}

std::string HardwareChecker::getWindowsDefenderStatus() {
    std::string defenderStatus = "Unknown";
    
    // Try to get Windows Defender status from registry
    std::string defenderEnabled = ReadRegistryValue(
        "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 
        "DisableRealtimeMonitoring"
    );
    
    if (!defenderEnabled.empty()) {
        if (defenderEnabled == "1") {
            return "Windows Defender Real-Time Protection Disabled";
        } else if (defenderEnabled == "0") {
            return "Windows Defender Real-Time Protection Enabled";
        }
    }
    
    // Try another registry location
    std::string defenderService = ReadRegistryValue(
        "SYSTEM\\CurrentControlSet\\Services\\WinDefend", 
        "Start"
    );
    
    if (!defenderService.empty()) {
        if (defenderService == "2") {
            return "Windows Defender Service Set to Automatic Start";
        } else if (defenderService == "3") {
            return "Windows Defender Service Set to Manual Start";
        } else if (defenderService == "4") {
            return "Windows Defender Service Disabled";
        }
    }
    
    // Try WMI as fallback
    if (!InitializeCOM()) {
        return defenderStatus;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return defenderStatus;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return defenderStatus;
    }
    
    // Try a more general query for antivirus products
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT displayName FROM AntiVirusProduct");
    
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "WMI Query Failed";
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    bool windowsDefenderFound = false;
    
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        
        std::string name = GetStringProperty(pclsObj, L"displayName");
        
        if (name.find("Windows Defender") != std::string::npos || 
            name.find("Microsoft Defender") != std::string::npos ||
            name.find("Defender") != std::string::npos) {
            
            windowsDefenderFound = true;
            defenderStatus = "Windows Defender Detected (" + name + ")";
            pclsObj->Release();
            break;
        }
        
        pclsObj->Release();
    }
    
    if (!windowsDefenderFound) {
        defenderStatus = "Windows Defender Not Detected in WMI";
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return defenderStatus;
}

std::string HardwareChecker::getSecureBootStatus() {
    std::string secureBootStatus = "Unknown";
    
    // Try to get Secure Boot status from registry
    std::string secureBoot = ReadRegistryValue(
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 
        "UEFISecureBootEnabled"
    );
    
    if (!secureBoot.empty()) {
        if (secureBoot == "1") {
            return "Secure Boot Enabled";
        } else if (secureBoot == "0") {
            return "Secure Boot Disabled";
        }
    }
    
    // Try another registry location
    std::string uefiSecureBoot = ReadRegistryValue(
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 
        "UEFISecureBootEnabled"
    );
    
    if (!uefiSecureBoot.empty()) {
        if (uefiSecureBoot == "1") {
            return "Secure Boot Enabled (Hardware Level)";
        } else if (uefiSecureBoot == "0") {
            return "Secure Boot Disabled (Hardware Level)";
        }
    }
    
    // Try WMI as fallback
    if (!InitializeCOM()) {
        return "Check BIOS settings for Secure Boot (COM Init Failed)";
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return "Check BIOS settings for Secure Boot (WMI Locator Failed)";
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return "Check BIOS settings for Secure Boot (WMI Service Failed)";
    }
    
    // Try firmware information
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT * FROM Win32_ComputerSystem");
    if (pEnumerator) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn > 0) {
            // Try to get firmware information
            std::string pcSystemType = GetStringProperty(pclsObj, L"PCSystemType");
            if (!pcSystemType.empty()) {
                secureBootStatus = "System Type: " + pcSystemType + " (Check BIOS for Secure Boot)";
            } else {
                secureBootStatus = "Check BIOS settings for Secure Boot";
            }
            pclsObj->Release();
        }
        pEnumerator->Release();
    }
    
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return secureBootStatus;
}

std::string HardwareChecker::getTPMStatus() {
    std::string tpmStatus = "Unknown";
    
    // Try to get TPM status from registry
    std::string tpmActivated = ReadRegistryValue(
        "SYSTEM\\CurrentControlSet\\Services\\TPM", 
        "Start"
    );
    
    if (!tpmActivated.empty()) {
        if (tpmActivated == "1") {
            tpmStatus = "TPM Service Started";
        } else if (tpmActivated == "2") {
            tpmStatus = "TPM Service Set to Automatic";
        } else if (tpmActivated == "3") {
            tpmStatus = "TPM Service Set to Manual";
        } else if (tpmActivated == "4") {
            tpmStatus = "TPM Service Disabled";
        }
    }
    
    // Check TPM hardware presence
    std::string tpmPresent = ReadRegistryValue(
        "SYSTEM\\CurrentControlSet\\Services\\TPM\\Properties", 
        "TPMPresent"
    );
    
    if (!tpmPresent.empty()) {
        if (tpmPresent == "1") {
            if (tpmStatus != "Unknown") {
                tpmStatus += ", TPM Hardware Present";
            } else {
                tpmStatus = "TPM Hardware Present";
            }
        } else {
            if (tpmStatus != "Unknown") {
                tpmStatus += ", TPM Hardware Not Present";
            } else {
                tpmStatus = "TPM Hardware Not Present";
            }
        }
    }
    
    // Try WMI as additional check
    if (!InitializeCOM()) {
        if (tpmStatus == "Unknown") {
            return "TPM Status Check Failed (COM Init Failed)";
        }
        return tpmStatus;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        if (tpmStatus == "Unknown") {
            return "TPM Status Check Failed (WMI Locator Failed)";
        }
        return tpmStatus;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        if (tpmStatus == "Unknown") {
            return "TPM Status Check Failed (WMI Service Failed)";
        }
        return tpmStatus;
    }
    
    // Check for TPM
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT * FROM Win32_Tpm");
    if (!pEnumerator) {
        // Try alternative class name
        pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT * FROM Win32_TPM");
    }
    
    if (pEnumerator) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn > 0) {
            if (tpmStatus != "Unknown") {
                tpmStatus += ", TPM Detected via WMI";
            } else {
                tpmStatus = "TPM Detected via WMI";
            }
            pclsObj->Release();
        } else {
            if (tpmStatus == "Unknown") {
                tpmStatus = "TPM Not Detected via WMI";
            }
        }
        pEnumerator->Release();
    } else {
        if (tpmStatus == "Unknown") {
            tpmStatus = "TPM WMI Class Not Available";
        }
    }
    
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    return tpmStatus;
}

std::string HardwareChecker::getBIOSMode() {
    std::string biosMode = "Unknown";
    
    if (!InitializeCOM()) {
        return biosMode;
    }
    
    IWbemLocator* pLoc = GetWbemLocator();
    if (!pLoc) {
        CoUninitialize();
        return biosMode;
    }
    
    IWbemServices* pSvc = ConnectToWMI(pLoc);
    if (!pSvc) {
        pLoc->Release();
        CoUninitialize();
        return biosMode;
    }
    
    IEnumWbemClassObject* pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT BootROMSupported, UEFIBoot FROM Win32_ComputerSystem");
    if (!pEnumerator) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return biosMode;
    }
    
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (uReturn > 0) {
        VARIANT vtProp;
        
        // Check UEFIBoot property
        VariantInit(&vtProp);
        hr = pclsObj->Get(L"UEFIBoot", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
            if (vtProp.boolVal == VARIANT_TRUE) {
                biosMode = "UEFI";
            } else {
                biosMode = "Legacy BIOS";
            }
        }
        VariantClear(&vtProp);
        
        // If UEFIBoot wasn't successful, try BootROMSupported
        if (biosMode == "Unknown") {
            VariantInit(&vtProp);
            hr = pclsObj->Get(L"BootROMSupported", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
                if (vtProp.boolVal == VARIANT_TRUE) {
                    biosMode = "Boot ROM Supported (Likely UEFI)";
                } else {
                    biosMode = "Boot ROM Not Supported (Legacy)";
                }
            }
            VariantClear(&vtProp);
        }
        
        pclsObj->Release();
    }
    
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    
    // If still unknown, try BIOS class
    if (biosMode == "Unknown") {
        if (!InitializeCOM()) {
            return biosMode;
        }
        
        pLoc = GetWbemLocator();
        if (!pLoc) {
            CoUninitialize();
            return biosMode;
        }
        
        pSvc = ConnectToWMI(pLoc);
        if (!pSvc) {
            pLoc->Release();
            CoUninitialize();
            return biosMode;
        }
        
        pEnumerator = ExecuteWMIQuery(pSvc, L"SELECT * FROM Win32_BIOS");
        if (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn > 0) {
                // Get BIOS version info which might indicate UEFI
                std::string smbiosBIOSVersion = GetStringProperty(pclsObj, L"SMBIOSBIOSVersion");
                if (smbiosBIOSVersion.find("UEFI") != std::string::npos) {
                    biosMode = "UEFI (Detected from Version String)";
                } else {
                    biosMode = "Likely Legacy BIOS";
                }
                pclsObj->Release();
            }
            pEnumerator->Release();
        }
        
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
    }
    
    return biosMode;

}
