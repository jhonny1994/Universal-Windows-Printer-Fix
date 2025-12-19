# Universal Windows Printer Fix 🖨️

![Platform](https://img.shields.io/badge/platform-Windows_10_%2F_11-0078D6) ![License](https://img.shields.io/badge/license-MIT-green) ![Maintenance](https://img.shields.io/badge/maintenance-active-success)

**The ultimate automated solution for Windows network printing.** This project provides a production-grade automation tool designed to instantly resolve complex network printing issues on **Windows 11 (LTSC, 22H2, 24H2) and Windows 10**. It handles the entire stack—from RPC protocols and Firewall rules to Legacy SMB support—making printers "just work" in any environment.

---

## 🌟 Why This Tool?

Networking printing on modern Windows can be frustrating due to security changes (PrintNightmare), protocol shifts, and driver restrictions. This tool bridges the gap between modern security and legacy hardware.

* **🌍 Universal Compatibility:** Built with UTF-8 encoding and System SIDs. It works flawlessly on **any** language version of Windows (English, French, Arabic, Chinese, etc.).
* **🛡️ Smart Security:** Implements **Profile-Aware Protection**. Firewall ports (135/139/445) are opened *only* for Private/Trusted networks. They automatically close on Public Wi-Fi to keep you safe.
* **🚫 Compatibility Guards:** Automatically detects unsupported OS versions (Windows 7/8.1) and aborts execution to prevent system damage.
* **↩️ Automatic Backups:** Safety is default. A full registry backup of your printer subsystem is saved to your Desktop before any changes are made.
* **👴 Legacy Hardware Support:** Silently enables **SMB 1.0** for older printers (e.g., Canon LBP, HP LaserJet 1020) that refuse to work on Windows 11.
* **🧠 Intelligent IP Detection:** Filters out VPNs, VM adapters, and Loopbacks to instantly display the correct LAN IP address you need to connect.

---

## 🚀 Installation & Usage

### Option 1: Run via Terminal (Recommended)
Run one of the following commands in PowerShell (Admin) to launch the tool directly from memory without downloading files:

**Method A (Modern):**
```powershell
irm https://raw.githubusercontent.com/jhonny1994/Universal-Windows-Printer-Fix/main/FixPrinters.ps1 | iex
```

**Method B (Standard):**
```powershell
iwr -useb https://raw.githubusercontent.com/jhonny1994/Universal-Windows-Printer-Fix/main/FixPrinters.ps1 | iex
```

### Option 2: Manual Download
1.  **Download** the latest `FixPrinters.ps1` release.
2.  **Right-Click** the file and select **Run with PowerShell**.
3.  Select your mode:
    * **[1] HOST:** For the PC physically connected to the printer via USB.
    * **[2] CLIENT:** For the PC trying to print over Wi-Fi/LAN.
    * **[3] HYBRID:** If you are unsure (Safe default).
4.  Follow the prompts and **Reboot** when finished.

---

## 🔧 Technical Details

When executed, this tool automates a 7-step remediation process:

| Step | Operation | Technical Detail |
| :--- | :--- | :--- |
| **1** | **OS Check** | Verifies Kernel >= 10.0 (Win 10/11) and PowerShell >= 5.1. |
| **2** | **RPC Protocol** | Enforces `RpcUseNamedPipeProtocol` and `RpcProtocols = 0x7`. |
| **3** | **Error 0x709 Fix** | Adjusts `RpcAuthnLevelPrivacyEnabled` to permit remote connection handshakes. |
| **4** | **Firewall** | Creates a `Private-Only` rule allowing TCP 135, 139, 445. |
| **5** | **Discovery** | Restarts `FDResPub` & `SSDPSRV` services to make the PC visible in "Network". |
| **6** | **Deep Clean** | Removes stale credentials for local IP ranges (`192.168.x`, `10.x`, `172.x`) to force fresh auth. |
| **7** | **Legacy** | Checks and enables the `SMB1Protocol` feature via DISM. |

---

## ⚠️ Safety & Recovery

We believe in non-destructive automation.

* **Logs:** A full execution log is generated in `%TEMP%` for auditing.
* **Rollback:** If you need to revert changes, navigate to the `Printer_Fix_Backups` folder on your Desktop and run the `.reg` restore file.

---

## 👥 Authors & Contributors

* **jhonny1994** - *Original Core Logic*
* **Gemini AI** - *Enterprise Refactoring & Security Hardening*

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Disclaimer:** This tool modifies system configurations to enable functionality. While extensive safety measures (backups, profile locking) are included, use at your own risk in corporate environments.
