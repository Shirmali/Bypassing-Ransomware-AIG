
# 🛡️ AIG Shields Up: Cybersecurity – Technical: Bypassing Ransomware

## 📘 Overview
As part of the AIG Shields Up: Cybersecurity Virtual Experience Program offered by Forage, I engaged in a simulation that emulated a real-world ransomware incident. The scenario involved a server compromised through a vulnerability, leading to the encryption of critical files by ransomware. The objective was to recover these files without paying the ransom, thereby enhancing my skills in incident response and ethical hacking.

## 🎯 Objectives
- Analyze a simulated ransomware attack on a compromised server.
- Develop a Python script to brute-force the decryption key.
- Recover encrypted files without yielding to ransom demands.
- Document the incident response process and mitigation strategies.

## 🛠️ Tools and Technologies
- **Python 3**: Scripting language used to automate the brute-force attack.
- **zipfile Module**: Python module utilized to handle ZIP file operations.
- **rockyou.txt**: Common password list employed for brute-force attempts.
- **Kali Linux**: Operating system used for executing the script and analysis.

## 🧪 Methodology

### 1. Environment Setup
- Configured Kali Linux environment with necessary tools and dependencies.
- Ensured the presence of `rockyou.txt` wordlist and the encrypted ZIP file (`enc.zip`).

### 2. Script Development
- Wrote a Python script (`bruteforce.py`) to iterate through the password list.
- Utilized the `zipfile` module to attempt extraction with each password.
- Implemented exception handling to manage incorrect password attempts.

### 3. Execution and Analysis
- Ran the script in the Kali Linux terminal.
- Monitored output to identify the correct password upon successful extraction.
- Documented the findings and the effective password used for decryption.

## 📄 Sample Code Snippet

```python
import zipfile

def main():
    zip_file = zipfile.ZipFile("enc.zip")
    password_list = "rockyou.txt"

    with open(password_list, 'rb') as file:
        for line in file:
            password = line.strip()
            try:
                zip_file.extractall(pwd=password)
                print(f"[+] Password found: {password.decode()}")
                return
            except:
                pass

    print("[-] Password not found.")

if __name__ == "__main__":
    main()
```

## 🚨 Incident Response Process & Mitigation Strategies

### 📌 Incident Summary
An internal server was compromised by a ransomware variant that encrypted sensitive data stored in a ZIP archive. The attackers demanded payment in exchange for the decryption key. As a cybersecurity analyst, my role was to bypass the ransomware by ethically brute-forcing the encrypted file to recover the data and mitigate future risks.

### 🧭 Incident Response Lifecycle (Based on NIST Framework)

#### 1. Preparation
- Ensured tools like Kali Linux, Python, and common wordlists (`rockyou.txt`) were pre-installed.
- Reviewed standard procedures for handling encrypted ZIP archives and ransomware scenarios.
- Verified the system was isolated from the network to prevent lateral spread of ransomware.

#### 2. Identification
- Detected that files on the server were encrypted and inaccessible.
- Observed ransom note/filename pattern indicating ransomware infection.
- Verified the file extension and encryption method used.

#### 3. Containment
- Isolated the infected machine to prevent propagation.
- Ensured no outbound connections were being made to C2 servers.

#### 4. Eradication
- Removed any suspicious processes and ensured the malware itself was no longer active.
- Collected forensic evidence (e.g., encrypted file, logs) for analysis and reporting.

#### 5. Recovery
- Developed and executed a Python brute-force script to recover the encryption password.
- Successfully decrypted the archive and restored access to sensitive data.
- Verified system stability post-decryption.

#### 6. Lessons Learned
- Conducted a post-mortem analysis.
- Documented response steps, time taken, and effectiveness.
- Suggested policy enhancements and control improvements.

### 🛡️ Mitigation Strategies

#### 🔒 Short-Term Actions
- Deploy Endpoint Detection and Response (EDR).
- User Awareness Training on phishing and ransomware.
- Maintain regular offline and immutable backups.

#### 🧱 Long-Term Actions
- Regular patching and vulnerability management.
- Principle of Least Privilege across users and systems.
- Network segmentation to minimize lateral movement.
- Centralized logging and monitoring.

## 📁 Repository Structure

```
AIG-Bypassing-Ransomware/
├── bruteforce.py
├── enc.zip
├── rockyou.txt
└── README.md
```

## 📌 Conclusion
This simulation provided a hands-on experience in dealing with ransomware attacks, emphasizing the importance of quick thinking and technical skills in cybersecurity. By successfully decrypting the files without paying the ransom, I demonstrated the ability to apply ethical hacking techniques and Python scripting to real-world scenarios.
