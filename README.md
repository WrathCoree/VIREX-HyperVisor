# VIREX-HYPERVISOR

A Stealth-Ready, EPT-Assisted, VMCS-Cloaked Hypervisor for Research and Enterprise Security Monitoring.

---

### **Legal Disclaimer**

This project has been developed for **strictly legal, ethical, and educational purposes.** Its goal is to research how virtualization hardware features, such as Intel VT-x and EPT, can be leveraged for **defensive** scenarios, including security analysis, rootkit detection, and system integrity monitoring in modern operating systems.

The use of this project or its associated code for any illegal activity, development of malware, circumvention of anti-cheat or anti-debug mechanisms, or any unauthorized breach of a system's security is **strictly prohibited and not the intended purpose.** The developer assumes no legal responsibility for any misuse of this code.

---

### **Core Philosophy: A Defense and Research-Oriented Hypervisor**

VIREX-HYPERVISOR provides a platform for understanding the advanced stealth and tampering techniques used by malware, with the objective of building better defensive systems against them. The philosophy is to "think like an attacker to build a better defense."

*   **Observation and Analysis:** It monitors system calls (`syscall`) and critical data structure access without patching, relying solely on EPT and hardware traps.
*   **Integrity Control:** It detects unauthorized modifications made to kernel code or driver objects.
*   **Research Platform:** It offers a controlled environment to study how virtualization can alter a system's behavior by manipulating timing (`RDTSC`) or CPU features (`CPUID`).

---

### **Key Features**

*   **SMP-Compliant VMX Launcher:** Securely initiates VMX operation on all processor cores.
*   **Extended Page Tables (EPT):** Provides full control over guest memory through hardware-assisted memory virtualization.
    *   **Memory Hiding:** Completely conceals the hypervisor's own memory from the guest operating system.
    *   **Patchless Hooking:** Leverages EPT violations and the Monitor Trap Flag (MTF) to monitor instructions without modifying any code.
*   **Advanced VM-Exit Handling:** Intercepts critical instructions such as `CPUID`, `MSR`, `CR` access, `RDTSC`, and `VMCALL`, routing them through a centralized handler.
*   **Dynamic Spoofing Manager:** Sets real-time spoofing rules for `CPUID` and `MSR` values based on commands from user-mode.
*   **INT3 Cloaking:** Creates "hidden" breakpoints, undetectable by memory scanners, using a combination of EPT and MTF.
*   **Security and Integrity Scans:**
    *   Detection of patches in the running kernel image (`ntoskrnl.exe`).
    *   Detection of IRP hooks in loaded driver objects.
*   **User-Mode Control Panel:** A simple C-based console application that communicates with the hypervisor via `IOCTL` to issue VMCALL commands.

---

### **Project Structure**

*   `/hypervisor`: Kernel-mode driver source code.
*   `/usermode`: User-mode control panel source code.
*   `/include`: Header files shared across the entire project.
*   `/docs`: Additional documents regarding the project's architecture and design.
