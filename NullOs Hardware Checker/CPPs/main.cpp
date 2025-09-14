#include "..\Headers\HardwareChecker.hpp"
#include <iostream>

int main() {
    std::cout << "HWID Checker\n\n";

    std::vector<std::string> diskInfo = HardwareChecker::getDiskInfo();
    std::cout << "Disk Drives:\n";
    std::cout << "Model\t\tSerialNumber\n";
    for (size_t i = 0; i < diskInfo.size(); i += 2) {
        std::cout << diskInfo[i] << "\t" << diskInfo[i + 1] << "\n";
    }

    std::cout << "\nCPU Information:\n";
    std::cout << "Processor ID: " << HardwareChecker::getCpuInfo() << "\n\n";

    std::cout << "BIOS Information:\n";
    std::cout << "Serial Number: " << HardwareChecker::getBiosInfo() << "\n\n";

    std::cout << "Motherboard Information:\n";
    std::cout << "Serial Number: " << HardwareChecker::getMotherboardInfo() << "\n\n";

    std::cout << "System Information:\n";
    std::cout << "Manufacturer: " << HardwareChecker::getSystemManufacturer() << "\n";
    std::cout << "Model: " << HardwareChecker::getSystemModel() << "\n";
    std::cout << "Total Physical Memory: " << HardwareChecker::getTotalPhysicalMemory() << " bytes\n\n";

    std::cout << "SMBIOS UUID:\n";
    std::cout << "UUID: " << HardwareChecker::getSmbiosUuid() << "\n\n";

    std::vector<std::string> graphicsCards = HardwareChecker::getGraphicsCards();
    std::cout << "Graphics Cards:\n";
    std::cout << "Name\t\tAdapter RAM\n";
    for (size_t i = 0; i < graphicsCards.size(); i += 2) {
        std::cout << graphicsCards[i] << "\t" << graphicsCards[i + 1] << " bytes\n";
    }
    
    std::cout << "\nOperating System:\n";
    std::cout << "Version: " << HardwareChecker::getOSVersion() << "\n\n";

    std::vector<std::string> printers = HardwareChecker::getInstalledPrinters();
    std::cout << "\nInstalled Printers:\n";
    std::cout << "Name\t\tPort\n";
    for (size_t i = 0; i < printers.size(); i += 2) {
        std::cout << printers[i] << "\t" << printers[i + 1] << "\n";
    }

    std::vector<std::string> soundDevices = HardwareChecker::getSoundDevices();
    std::cout << "\nSound Devices:\n";
    std::cout << "Name\t\tManufacturer\n";
    for (size_t i = 0; i < soundDevices.size(); i += 2) {
        std::cout << soundDevices[i] << "\t" << soundDevices[i + 1] << "\n";
    }

    // GPU, RAM, VRAM, and Windows Defender information
    std::cout << "\n=== HARDWARE SPECIFICATIONS ===\n";
    
    std::vector<std::string> gpuInfo = HardwareChecker::getGPUInfo();
    std::cout << "\nGPU Information:\n";
    for (size_t i = 0; i < gpuInfo.size(); i += 3) {
        std::cout << "Name: " << gpuInfo[i] << "\n";
        std::cout << "Compatibility: " << gpuInfo[i + 1] << "\n";
        std::cout << "Driver Version: " << gpuInfo[i + 2] << "\n\n";
    }
    
    std::cout << "RAM Information:\n";
    std::cout << "Total Physical Memory: " << HardwareChecker::getRAMInfo() << " bytes\n\n";
    
    std::cout << "VRAM Information:\n";
    std::cout << "Adapter RAM: " << HardwareChecker::getVRAMInfo() << " bytes\n\n";
    
    std::cout << "Windows Defender Status:\n";
    std::cout << HardwareChecker::getWindowsDefenderStatus() << "\n\n";

    // Secure BIOS and TPM information
    std::cout << "\n=== BIOS AND SECURITY SETTINGS ===\n";
    
    std::cout << "Secure Boot Status:\n";
    std::cout << HardwareChecker::getSecureBootStatus() << "\n\n";
    
    std::cout << "TPM Status:\n";
    std::cout << HardwareChecker::getTPMStatus() << "\n\n";
    
    std::cout << "BIOS Mode:\n";
    std::cout << HardwareChecker::getBIOSMode() << "\n\n";

    std::cout << "\nPress any key to exit.";
    std::cin.get();

    return 0;
}