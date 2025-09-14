#ifndef HARDWARECHECKER_HPP
#define HARDWARECHECKER_HPP

#include <string>
#include <vector>

class HardwareChecker {
public:
    static std::vector<std::string> getDiskInfo();
    static std::string getCpuInfo();
    static std::string getBiosInfo();
    static std::string getMotherboardInfo();
    static std::string getSmbiosUuid();
    // Removed getNetworkAdapterInfo()
    
    // Additional hardware information
    static std::string getSystemManufacturer();
    static std::string getSystemModel();
    static std::string getTotalPhysicalMemory();
    static std::vector<std::string> getGraphicsCards();
    static std::string getOSVersion();
    static std::vector<std::string> getInstalledPrinters();
    static std::vector<std::string> getSoundDevices();
    
    // New functions for GPU, RAM, VRAM, and Windows Defender
    static std::vector<std::string> getGPUInfo();
    static std::string getRAMInfo();
    static std::string getVRAMInfo();
    static std::string getWindowsDefenderStatus();
    
    // New functions for Secure BIOS and TPM
    static std::string getSecureBootStatus();
    static std::string getTPMStatus();
    static std::string getBIOSMode();
};

#endif // HARDWARECHECKER_HPP