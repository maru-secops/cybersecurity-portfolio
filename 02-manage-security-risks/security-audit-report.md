# Internal Security Audit & Compliance Assessment Report

**Course:** Google Cybersecurity Professional Certificate — Course 2 (*Play It Safe: Manage Security Risks*)  
**Framework Alignment:** NIST Cybersecurity Framework (CSF), PCI DSS, GDPR, SOC Type 1 & Type 2  
**Audit Subject:** Botium Toys (Fictional Retail & E-Commerce Case Study)  
**Assessor Role:** Entry-Level Security Analyst (`maru-secops`)

---

## 1. Executive Summary & Audit Scope

### Audit Scope

This internal security audit evaluates the overall security posture of **Botium Toys**, a growing U.S.-based toy retailer operating a single physical facility (main office, retail storefront, and warehouse) alongside an expanding international e-commerce presence serving customers in the United States and the European Union (E.U.). The assessment covers:

- On-premises IT infrastructure, internal networks, and internet connectivity
- Employee endpoints (desktops, laptops, smartphones, remote workstations, and peripherals)
- Core business systems (e-commerce, payment processing, accounting, database, inventory, and legacy end-of-life systems)
- Physical security mechanisms across offices, storefront, and warehouse facilities

### Audit Goals & Baseline Risk Rating

- **Goals:** Identify existing administrative, technical, and physical controls; evaluate adherence to regulatory compliance standards (**PCI DSS**, **GDPR**, **SOC 1/2**); and provide prioritized remediation recommendations aligned with the **NIST Cybersecurity Framework (CSF)**.
- **Inherent Risk Score: 8 / 10 (High Risk)** — Driven by unencrypted cardholder/PII storage, missing access controls (*least privilege* and *separation of duties*), absence of an Intrusion Detection System (IDS), and lack of backups or disaster recovery plans.

---

## 2. Controls Assessment Checklist

*Evaluation Question: Does Botium Toys currently have this control in place?*

| Security Control | Category | Control Type | In Place? | Audit Finding / Evidence |
| :--- | :--- | :--- | :---: | :--- |
| **Least Privilege** | Administrative | Preventative | **No** | All employees currently have broad access to internal data, including cardholder data and customer PII/SPII. |
| **Disaster Recovery Plans** | Administrative | Corrective | **No** | No documented disaster recovery or business continuity procedures are established. |
| **Password Policies** | Administrative | Preventative | **Yes** *(Weak)* | A nominal policy exists, but it lacks modern complexity standards (minimum length, alphanumeric, special characters). |
| **Separation of Duties** | Administrative | Preventative | **No** | Critical system and data privileges are not divided across roles. |
| **Firewall** | Technical | Preventative | **Yes** | Network firewall is active and blocks unauthorized traffic based on defined security rules. |
| **Intrusion Detection System (IDS)** | Technical | Detective | **No** | No IDS is deployed to monitor network traffic for anomalous or malicious activity. |
| **Backups** | Technical / Admin. | Corrective | **No** | No automated or regular backups of critical business and customer data exist. |
| **Antivirus (AV) Software** | Technical | Preventative | **Yes** | Antivirus software is installed on endpoints and monitored regularly by the IT department. |
| **Manual Monitoring & Maintenance (Legacy Systems)** | Administrative / Tech. | Preventative | **Yes** *(Ad-hoc)* | End-of-life legacy systems are monitored manually, but no formal maintenance schedule or intervention SOP exists. |
| **Encryption** | Technical | Preventative / Deterrent | **No** | Credit card data and sensitive customer PII/SPII are accepted, processed, transmitted, and stored locally without encryption. |
| **Password Management System** | Technical | Preventative | **No** | No centralized password manager is deployed to enforce complexity rules or streamline resets. |
| **Locks (Offices, Storefront, Warehouse)** | Physical | Preventative / Deterrent | **Yes** | Adequate physical door and facility locks are installed across all on-site areas. |
| **Closed-Circuit Television (CCTV)** | Physical | Preventative / Detective | **Yes** | Up-to-date CCTV surveillance covers the physical premises. |
| **Fire Detection & Prevention** | Physical | Detective / Preventative | **Yes** | Functioning fire alarm and suppression/prevention systems are active on site. |

---

## 3. Regulatory & Standards Compliance Checklist

*Evaluation Question: Does Botium Toys currently adhere to this compliance best practice?*

### A. Payment Card Industry Data Security Standard (PCI DSS)

| Compliance Best Practice | Adhered? | Audit Assessment |
| :--- | :---: | :--- |
| Only authorized users have access to customers' credit card information. | **No** | Unrestricted internal employee access exposes cardholder data. |
| Credit card information is stored, accepted, processed, and transmitted internally in a secure environment. | **No** | Lack of encryption, segmentation, least privilege, and IDS leaves payment environments exposed. |
| Implement data encryption procedures to better secure credit card transaction touchpoints and data. | **No** | Encryption is currently absent across local storage and payment workflows. |
| Adopt secure password management policies. | **No** | Nominal password policy lacks complexity enforcement and centralized management. |

### B. General Data Protection Regulation (GDPR)

| Compliance Best Practice | Adhered? | Audit Assessment |
| :--- | :---: | :--- |
| E.U. customers' data is kept private/secured. | **No** | Unencrypted local storage and lack of role-based access controls violate confidentiality safeguards. |
| There is a plan in place to notify E.U. customers within 72 hours if their data is compromised. | **Yes** | A 72-hour breach notification procedure is documented and established. |
| Ensure data is properly classified and inventoried. | **No** | Inadequate asset inventory and missing data classification prevent impact assessment. |
| Enforce privacy policies, procedures, and processes to properly document and maintain data. | **Yes** | Internal privacy policies and data maintenance procedures are established and enforced. |

### C. System and Organizations Controls (SOC Type 1 & Type 2)

| Compliance Best Practice | Adhered? | Audit Assessment |
| :--- | :---: | :--- |
| User access policies are established. | **No** | Neither *least privilege* nor *separation of duties* is enforced. |
| Sensitive data (PII/SPII) is confidential/private. | **No** | PII/SPII is stored unencrypted with broad internal read access. |
| Data integrity ensures the data is consistent, complete, accurate, and validated. | **Yes** | IT has integrated controls maintaining data integrity. |
| Data is available to individuals authorized to access it. | **Yes** | System and data availability is actively maintained by IT. |

---

## 4. Prioritized Recommendations for Stakeholder Communication

To lower Botium Toys' risk score from **8/10** to an acceptable baseline and achieve compliance with **PCI DSS**, **GDPR**, and **SOC 1/2**, the IT department should execute the following four-phase remediation roadmap:

1. **Enforce Access Controls & Data Encryption (Immediate — Priority 1):**
   - Implement Role-Based Access Control (RBAC) enforcing the **principle of least privilege** and **separation of duties** so only authorized personnel can view or process cardholder data and PII/SPII.
   - Deploy strong encryption (**AES-256** at rest and **TLS 1.2+** in transit) across all payment touchpoints and local databases.
2. **Strengthen Password Governance & Authentication (Short-Term — Priority 2):**
   - Update the password policy to require strong complexity (minimum 12+ characters, mixed case, numbers, special characters) paired with **Multi-Factor Authentication (MFA)**.
   - Deploy a centralized enterprise **password management system** to enforce policy compliance and eliminate manual password-reset bottlenecks.
3. **Deploy Network Detection & Business Continuity Safeguards (Short-Term — Priority 3):**
   - Install and configure an **Intrusion Detection System (IDS)** behind the existing firewall to detect anomalous traffic and potential breaches early.
   - Establish automated, encrypted **3-2-1 backups** and a documented, tested **Disaster Recovery (DR) plan** to guarantee operational resilience.
4. **Formalize Asset Classification & Legacy System Maintenance (Medium-Term — Priority 4):**
   - Conduct a complete hardware, software, and data inventory aligned with the **NIST CSF (*Identify* function)** to classify high-risk assets.
   - Establish a recurring maintenance schedule, compensating isolation controls, and a decommissioning roadmap for end-of-life legacy systems.
