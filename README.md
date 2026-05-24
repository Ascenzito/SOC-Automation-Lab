# SOC Automation Lab

## Objective

The SOC Automation Lab project aimed to build a fully automated Security Operations Centre (SOC) pipeline by integrating Wazuh (SIEM/XDR), TheHive (case management), and Shuffle (SOAR). A Windows 11 virtual machine running locally in VirtualBox acted as the monitored endpoint, with Wazuh and TheHive hosted on dedicated Ubuntu 22.04 virtual machines in Microsoft Azure. The goal was to simulate a real-world SOC workflow where a threat is detected, automatically enriched with threat intelligence, escalated into a case management system, and communicated to the analyst all without manual intervention. Mimikatz, a widely used credential dumping tool, was used as the simulated attack to trigger and validate the detection and response pipeline end to end.

### Skills Learned

- Deployed and configured Wazuh as a cloud-hosted SIEM and XDR platform on an Azure Ubuntu VM.
- Installed and configured TheHive as a security incident response and case management platform on a dedicated Azure Ubuntu VM.
- Integrated Shuffle as a SOAR platform to orchestrate automated workflows between Wazuh, TheHive, and VirusTotal.
- Installed and configured Sysmon on a Windows 11 endpoint to generate detailed telemetry for process creation, network connections, and file activity.
- Wrote a custom Wazuh detection rule to identify Mimikatz execution based on the original file name field in Sysmon event logs.
- Successfully triggered a Mimikatz alert and validated the end-to-end automated pipeline from detection through to case creation and analyst notification.
- Configured Shuffle workflows to automatically extract file hashes from Wazuh alerts and query VirusTotal for threat intelligence enrichment.
- Automated case creation in TheHive with enriched alert data including threat severity, affected system, and VirusTotal results.
- Set up automated email notifications to the SOC analyst with full alert context within 90 seconds of detection.
- Gained practical understanding of how SOAR platforms reduce mean time to respond (MTTR) by automating repetitive SOC tasks.
- Developed understanding of the full SOC alert lifecycle: detection → enrichment → case management → analyst notification → response.

### Tools Used

- **Microsoft Azure** — Cloud platform used to host the Wazuh and TheHive virtual machines.
- **Ubuntu Server 22.04 LTS** — Operating system for both the Wazuh (Paulo-Wazuh) and TheHive (Paulo-TheHive) Azure VMs.
- **Wazuh** — Open-source SIEM and XDR platform used for log ingestion, threat detection, and custom rule creation.
- **TheHive** — Open-source security incident response platform used for automated case creation and incident management.
- **Shuffle** — Open-source SOAR platform used to orchestrate the automated response workflow between all components.
- **Sysmon (System Monitor)** — Microsoft Sysinternals tool installed on the Windows 11 endpoint to generate detailed security telemetry.
- **Mimikatz** — Credential dumping tool used to simulate a real-world attack and validate the detection pipeline.
- **VirusTotal** — Online threat intelligence platform used by Shuffle to automatically enrich IOCs (file hashes) from alerts.
- **Windows 11** — Local endpoint VM running in VirtualBox, monitored by a Wazuh agent.
- **VirtualBox** — Hypervisor used to host the Windows 11 endpoint VM locally.
- **Cassandra** — Database backend used by TheHive for storing case and alert data.
- **Elasticsearch** — Search and analytics engine used by TheHive for indexing and querying case data.

---

## Steps

### Step 1 – Design the Lab Architecture

Before deploying any infrastructure, mapped out the data flow and component relationships for the lab:

1. A **Windows 11 VM** (local, VirtualBox) runs a Wazuh agent and Sysmon to generate endpoint telemetry.
2. The Wazuh agent forwards events to the **Wazuh Manager** (Paulo-Wazuh, Azure VM).
3. Wazuh detects a threat and sends the alert to **Shuffle**.
4. Shuffle extracts the IOC (file hash), queries **VirusTotal** for enrichment, and creates an alert in **TheHive** (Paulo-TheHive, Azure VM).
5. Shuffle sends an **email notification** to the SOC analyst with full context.

---

### Step 2 – Deploy the Wazuh VM in Azure

Created a new Ubuntu Server 22.04 LTS VM in Microsoft Azure with the following configuration:

- **VM Name:** Paulo-Wazuh
- **Resource Group:** RG-SOC-LAB
- **Region:** East US
- **Image:** Ubuntu Server 22.04 LTS - x64 Gen2
- **Size:** Standard_D2s_v3 (2 vCPUs, 8 GiB RAM)
- **Authentication:** Password
- **Inbound ports opened in NSG:** 22 (SSH), 443 (HTTPS dashboard), 1514 (agent events), 1515 (agent enrollment)

SSHed into the VM and installed Wazuh using the official installation script:

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Accessed the Wazuh dashboard via the VM's public IP on port 443 and confirmed the installation was successful.

---

### Step 3 – Deploy the TheHive VM in Azure

Created a second Ubuntu Server 22.04 LTS VM in Azure:

- **VM Name:** Paulo-TheHive
- **Resource Group:** RG-SOC-LAB
- **Region:** East US
- **Image:** Ubuntu Server 22.04 LTS - x64 Gen2
- **Size:** Standard_D2s_v3 (2 vCPUs, 8 GiB RAM)
- **Authentication:** Password
- **Inbound ports opened in NSG:** 22 (SSH), 9000 (TheHive web interface)

Installed the required dependencies and TheHive on the VM:

- **Java** — runtime environment for TheHive
- **Cassandra** — database backend, configured with the correct cluster name and listen/RPC addresses pointing to the VM's public IP
- **Elasticsearch** — indexing engine, configured with the correct cluster name and network host
- **TheHive** — installed and configured with ownership and storage settings pointing to the correct directories

Accessed TheHive via the VM's public IP on port 9000 and confirmed login with default credentials.

---

### Step 4 – Install and Configure Sysmon on the Windows 11 Endpoint

On the local Windows 11 VM in VirtualBox:

1. Downloaded **Sysmon** from Microsoft Sysinternals.
2. Downloaded the **SwiftOnSecurity Sysmon configuration file** for comprehensive event logging.
3. Installed Sysmon with the configuration file:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

4. Verified Sysmon was running by checking **Services** and confirming Sysmon events appeared in **Event Viewer** under `Applications and Services Logs > Microsoft > Windows > Sysmon`.

---

### Step 5 – Install the Wazuh Agent on the Windows 11 Endpoint

Downloaded and installed the Wazuh agent on the Windows 11 VM, pointing it to the Paulo-Wazuh server's public IP address. Configured the agent to include Sysmon logs by editing `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restarted the Wazuh agent and confirmed the Windows 11 endpoint appeared as an active agent in the Wazuh dashboard.

---

### Step 6 – Write a Custom Wazuh Detection Rule for Mimikatz

On the Wazuh manager, created a custom detection rule to identify Mimikatz execution by matching the original file name field in Sysmon process creation events (Event ID 1). This approach detects Mimikatz even if the executable is renamed:

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz Execution Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

Restarted the Wazuh manager to apply the new rule.

---

### Step 7 – Configure Shuffle Workflow

Set up a Shuffle workflow to automate the response pipeline:

1. **Wazuh webhook trigger** — Shuffle listens for incoming alerts from Wazuh.
2. **Hash extraction** — used a regex to parse the SHA256 file hash from the alert payload.
3. **VirusTotal app** — sent the extracted hash to VirusTotal and retrieved the detection results.
4. **TheHive app** — automatically created a new alert in TheHive with the enriched data including severity, description, source IP, and VirusTotal results.
5. **Email app** — sent an automated notification email to the SOC analyst with full alert context and links to the TheHive case and VirusTotal report.

Configured Wazuh to forward alerts to the Shuffle webhook by adding the integration block to `ossec.conf` on the Wazuh manager.

---

### Step 8 – Simulate the Attack and Validate the Pipeline

On the Windows 11 VM, disabled Windows Defender temporarily and executed Mimikatz:

```
mimikatz.exe
```

Validated the full pipeline end to end:

- Sysmon logged the process creation event (Event ID 1)
- Wazuh agent forwarded the event to the Wazuh manager
- Custom rule fired and generated a level 15 critical alert
- Wazuh forwarded the alert to Shuffle via webhook
- Shuffle extracted the SHA256 hash and queried VirusTotal
- Shuffle created a case in TheHive with enriched alert details
- Analyst received an automated email notification within 90 seconds of execution

---

## Key Takeaway

This lab demonstrated how a modern SOC can drastically reduce mean time to respond (MTTR) through automation. Without SOAR, a SOC analyst would need to manually look up threat intelligence, create a ticket, and notify the team — a process that can take 30-60 minutes per alert. With the automated pipeline built in this lab, the entire process from detection to analyst notification took under 90 seconds. This mirrors the workflows used in enterprise SOC environments and demonstrates practical experience with the full alert lifecycle: detection, enrichment, case management, and response.

> **Note:** All Azure resources (Paulo-Wazuh VM, Paulo-TheHive VM, and associated NSG/networking resources) were deallocated after the lab was completed to preserve free trial credits.
