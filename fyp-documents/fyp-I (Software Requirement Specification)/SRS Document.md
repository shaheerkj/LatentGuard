# LatentGuard: Adaptive Dual Layer Web Application Firewall (WAF) for Anomaly and Threat Detection

**COMSATS University, Islamabad Pakistan**

**By**

**Syed Shaheer Khalid** — CIIT/SP23-BCT-048/ISB  
**Javaria Maqbool** — CIIT/SP23-BCT-023/ISB

**Supervisor:** Dr. Farhana Jabeen

*Bachelor of Science in Cyber Security (2023–2027)*

> The candidate confirms that the work submitted is their own and appropriate credit has been given where reference has been made to the work of others.

<!-- IMAGE: image1.jpeg
A circular institutional logo for COMSATS University Islamabad. The logo features a central blue oval shape resembling a stylized eye or globe, rendered with vertical stripe detail suggesting a three-dimensional sphere. This central emblem is encircled by a thick purple/violet ring containing the text "COMSATS UNIVERSITY" along the top arc and "ISLAMABAD" along the bottom arc, both in white uppercase letters. The overall design uses a two-tone purple and blue color scheme on a white background, conveying an academic and professional identity. -->

---

## Abstract

The rapid evolution of sophisticated cyber threats, including zero-day exploits and evasion techniques, necessitates the development of more adaptive and intelligent web application firewalls (WAFs) to safeguard modern web applications effectively. Existing traditional WAFs, most notably ModSecurity — one of the most widely deployed open-source WAF engines — primarily rely on signature-based detection using static rule sets, such as the OWASP Core Rule Set (CRS). While ModSecurity excels at blocking well-known attacks like SQL injection and cross-site scripting (XSS), it suffers from high false positive rates that disrupt legitimate user traffic and operational efficiency. Moreover, it struggles significantly against novel, zero-day vulnerabilities and polymorphic attacks, as it cannot detect threats without pre-existing signatures, often leading to missed detections or requiring constant, labor-intensive manual tuning.

The proposed project builds directly upon ModSecurity's proven foundation, extending its capabilities with an intelligent AI layer rather than replacing it. By integrating ModSecurity as the core enforcement engine, this work introduces a hybrid, self-learning WAF that augments its rule-based pipeline with unsupervised deep learning for zero-day anomaly detection and automated, AI-assisted rule generation to minimize manual intervention and false positives. The primary objectives are to design a dual-layered architecture in which ModSecurity handles pre-filtering through both its existing CRS rules and newly AI-generated dynamic rules, while a deep fully connected autoencoder — trained exclusively on benign traffic — performs accurate anomaly scoring via reconstruction error for requests that pass initial filtering. This is further complemented by HDBSCAN-based density clustering to distinguish rare but legitimate behavior from true outliers, and a conservative consensus-based decision engine with full explainability. Critically, the project also establishes a closed-loop self-learning mechanism leveraging large language models (LLMs) to automatically generate and deploy new ModSecurity-compatible SecLang rules from confirmed attack patterns, subject to human review before deployment.

This project will deliver a next-generation WAF solution that retains the reliability and operational familiarity of ModSecurity while transcending its inherent limitations. The result is a system that achieves significantly higher detection rates for both known and emerging threats, dramatically reduces false positives through multi-model agreement, provides strong auditability for security teams, and continuously adapts to evolving attack landscapes with minimal human effort — ultimately enhancing overall web application security posture while maintaining high performance and usability.

---

## Contents

- Abstract
- Chapter 1: Introduction and Problem Definition
  - 1.1 Overview of the Project
  - 1.2 Vision Statement
  - 1.3 Problem Statement
  - 1.4 Problem Solution
  - 1.5 Objectives of the Proposed System
  - 1.6 Scope
    - 1.6.1 Limitations/Constraints
  - 1.7 Modules
  - 1.8 Related System Analysis/Literature Review
  - 1.9 Tools and Technologies
  - 1.10 Project Contribution
  - 1.11 Relevance to Course Modules
- Chapter 2: Requirement Analysis
  - 2.1 User Classes and Characteristics
  - 2.2 Operating Environment
  - 2.3 Design and Implementation Constraints
  - 2.4 Use Case Diagram
  - 2.5 Requirement Identifying Technique
  - 2.6 Derived Functional Requirements from Events
  - 2.7 Non-Functional Requirements
  - 2.8 External Interface Requirements

---

# Chapter 1: Introduction and Problem Definition

This chapter provides an overview of the project.

## 1.1 Overview of the Project

LatentGuard is an AI-augmented Web Application Firewall (WAF) designed to provide intelligent, adaptive, and low-false-positive protection for modern web applications and APIs operating in an increasingly hostile cyber threat landscape. The system targets the cybersecurity domain, serving web application owners, security administrators, and development teams who require reliable, automated defence against both well-known and emerging threats such as zero-day exploits, AI-generated polymorphic payloads, and advanced evasion techniques. The core problem lies in the critical limitations of existing WAF solutions — including industry-standard tools like ModSecurity, AWS WAF, and Cloudflare WAF — which rely on static, signature-based rule sets that fail to generalize beyond known attack patterns, generate high false-positive rates, and demand continuous manual maintenance. LatentGuard addresses this gap by introducing a self-learning, hybrid architecture that combines rule-based pre-filtering, unsupervised deep learning through a fully connected autoencoder, and HDBSCAN density-based clustering, augmented by a closed-loop LLM-assisted rule generation mechanism. The proposed solution eliminates the need for constant manual rule writing, continuously adapts to evolving threats, and provides full explainability and auditability — delivering a proactive and intelligent defense platform suitable for on-premise, cloud, and hybrid deployment environments.

## 1.2 Vision Statement

For organizations that need to protect their web applications and APIs from constantly evolving cyber threats, the Self-Learning Web Application Firewall is a security platform that monitors, analyzes, and filters incoming web traffic based on application behavior and threat intelligence. Unlike traditional rule-based WAFs that depend heavily on static signatures and manual tuning, our product continuously adapts to the unique traffic patterns of each application, enabling more accurate detection of attacks while reducing false positives and administrative effort.

## 1.3 Problem Statement

Existing Web Application Firewalls rely heavily on static signature rules or standalone anomaly detection, which leads to two persistent limitations: high false positive rates under application-specific traffic patterns and poor adaptability against previously unseen attacks. Pure rule-based systems cannot generalize beyond known signatures, while anomaly-only approaches often misclassify rare but legitimate requests due to lack of contextual validation. Furthermore, current WAF solutions do not provide a structured mechanism to convert newly observed attack behaviors into deployable defensive rules automatically. This creates a gap for a self-learning WAF framework that reduces false positives through multi-stage anomaly validation (reconstruction error plus density clustering) and continuously evolves its rule set by mining confirmed attack patterns and generating human-validated rules using large language models.

## 1.4 Problem Solution

Security administrators and development teams have long required a firewall solution capable of detecting not only well-known web attacks but also novel, previously unseen threats without the burden of constant manual rule maintenance. LatentGuard addresses this need by operating as an intelligent reverse proxy that learns the normal behaviour of application traffic and automatically identifies deviations that indicate malicious activity. By combining a rule-based filtering engine with a deep learning autoencoder and HDBSCAN density-based clustering, the system eliminates the core weakness of traditional WAFs — their inability to generalise beyond known attack signatures — while simultaneously reducing the high false-positive rates that disrupt legitimate user traffic and force organisations into unsafe, permissive configurations.

The self-learning mechanism further reduces the operational burden on security teams by automatically mining confirmed attack patterns and submitting AI-generated, ModSecurity-compatible rules for human review and deployment through a centralised dashboard. This closed-loop process means that each detected threat actively strengthens the system's future defences, allowing protection to improve continuously over time without increasing administrative overhead. Integration with live threat intelligence feeds additionally ensures that known malicious IP addresses and domains are blocked proactively, adding an external layer of awareness beyond what the system observes locally.

The system will accomplish the following specific objectives: detecting and blocking both known and unknown web attacks by learning normal application traffic behaviour; reducing false positives and unnecessary blocking through multi-stage behavioural and contextual analysis combining reconstruction error scoring and density clustering; continuously improving protection by automatically generating and updating security rules derived from observed attack patterns; integrating threat intelligence feeds to identify and block known malicious sources in real time; providing detailed logging and explainable security decisions to support auditing, compliance, and administrative trust; and supporting flexible deployment across on-premise, cloud, and hybrid environments through its reverse-proxy architecture.

## 1.5 Objectives of the Proposed System

- **BO-1:** To detect and block both known and unknown web attacks by learning the normal behavior of application traffic.
- **BO-2:** To reduce false positives and unnecessary blocking through behavioral and contextual analysis.
- **BO-3:** To continuously improve web application protection by generating and updating security rules from observed attack patterns.
- **BO-4:** To integrate threat intelligence feeds for identifying and blocking known malicious IPs and domains.
- **BO-5:** To provide detailed logging and explainable security decisions for auditing and analysis.
- **BO-6:** To support deployment in on-premise, cloud, and hybrid environments through a flexible reverse-proxy architecture.

## 1.6 Scope

The proposed AI-driven Web Application Firewall (WAF) is designed to protect web applications by intercepting and analyzing all incoming HTTP/HTTPS traffic through a reverse proxy. It normalizes requests into a structured format, enabling both rule-based and AI-based analysis. The system first applies a fast rule-based filtering layer that includes AI-generated rules, threat intelligence, and custom administrator-defined rules to block known malicious requests. Suspicious requests are further analyzed using an autoencoder-based anomaly detection model trained on normal traffic patterns. HDBSCAN clustering is applied on the latent representations to reduce false positives and reliably identify zero-day attacks. Confirmed malicious requests are used to generate new AI-enhanced WAF rules through pattern mining, which are then validated by administrators before deployment. The WAF continuously improves through a closed feedback loop that integrates detection, rule generation, and human validation. All traffic, decisions, and rules are logged in a MongoDB database for analysis and auditing. A web-based dashboard visualizes attack trends, rule effectiveness, and endpoint risk scores for operational monitoring. The project focuses on demonstrating AI-driven detection and adaptive rule generation within a single-instance WAF prototype.

### 1.6.1 Limitations/Constraints

- **LI-1:** The WAF prototype is deployment-agnostic, meaning it can be deployed on-prem or in cloud in front of backend servers.
- **LI-2:** Detection of zero-day attacks relies on patterns learned from historical traffic, so extremely novel attack techniques may not be immediately detected.
- **LI-3:** The AI-generated rules require human validation before deployment, which may introduce delays in automated response.
- **LI-4:** The system focuses on web application layer security (HTTP/HTTPS) and does not provide network-level protections like DDoS mitigation or firewalling for non-web traffic.
- **LI-5:** Threat intelligence integration depends on publicly available sources, which may not always provide complete or up-to-date information.
- **LI-6:** Some complex or encrypted payloads may affect feature extraction accuracy and anomaly detection performance.
- **LI-7:** The dashboard and analytics are limited to operational monitoring and academic evaluation and do not include advanced incident response automation.
- **LI-8:** The system assumes that backend applications are properly configured and secure; it does not prevent attacks that exploit backend misconfigurations outside of HTTP/HTTPS requests.

## 1.7 Modules

### Reverse Proxy Traffic Interception

- **FE-1:** Intercept all incoming HTTP/HTTPS requests using a Go-based/NGINX reverse proxy before they reach the protected application.
- **FE-2:** Terminate TLS sessions and extract request metadata including source IP, headers, method, URI, and body.
- **FE-3:** Forward captured requests into the internal processing pipeline while preserving routing to the backend server.

### Traffic Normalization and Feature Extraction

- **FE-1:** Parse and normalize request components (URL, parameters, headers, payloads) into a structured JSON format.
- **FE-2:** Decode encoded inputs and remove obfuscation artifacts to produce canonical representations.
- **FE-3:** Extract behavioral and content-based features (length, entropy, token counts, special character ratios) for ML analysis.

### Rule-Based Filtering Engine

- **FE-1:** Embed ModSecurity WAF as the core rule enforcement engine, applying the OWASP Core Rule Set (CRS) alongside administrator-defined and AI-generated rules to detect and block known malicious patterns.
- **FE-2:** Integrate threat intelligence feeds into ModSecurity's rule layer to automatically block requests originating from known malicious IPs and domains.
- **FE-3:** Perform fast pre-filter decisions through ModSecurity to allow, block, or escalate suspicious requests to the AI detection layer based on rule match confidence and severity scoring.

### AI-Based Anomaly Detection (Autoencoder)

- **FE-1:** Transform normalized request features into numerical vectors suitable for model inference.
- **FE-2:** Use a trained autoencoder to compute reconstruction error as an anomaly score.
- **FE-3:** Flag requests with high deviation from learned normal behavior for deeper validation.

### Latent-Space Clustering Validation (HDBSCAN)

- **FE-1:** Generate latent embeddings from the autoencoder for each analyzed request.
- **FE-2:** Apply HDBSCAN density clustering to group normal behavior and isolate outliers.
- **FE-3:** Differentiate rare legitimate requests from malicious anomalies to reduce false positives.

### Multi-Signal Consensus Decision Engine

- **FE-1:** Combine rule hits, anomaly scores, and clustering results into a unified decision score.
- **FE-2:** Apply consensus logic to classify requests as allow, block, or suspicious.
- **FE-3:** Attach explainable decision reasons for each classification outcome.

### Logging, Explainability, and Data Storage

- **FE-1:** Store normalized requests, features, model scores, rule matches, and final decisions in MongoDB.
- **FE-2:** Maintain explainability metadata describing why each request was allowed or blocked.
- **FE-3:** Provide structured datasets for analytics, auditing, and future model retraining.

### Attack Pattern Mining Engine

- **FE-1:** Collect and canonicalize confirmed malicious requests from blocked traffic logs.
- **FE-2:** Cluster similar attack payloads and extract frequent structural token patterns.
- **FE-3:** Generate reusable attack templates using pattern mining techniques such as **FP-Growth** and token frequency analysis.

### LLM-Assisted Rule Generation

- **FE-1:** Convert mined attack templates into structured prompts for rule synthesis.
- **FE-2:** Use a large language model to generate ModSecurity-compatible WAF rules and regex patterns.
- **FE-3:** Attach rule confidence scores and scope constraints based on observed attack clusters.

### Human-in-the-Loop Rule Validation

- **FE-1:** Present AI-generated rules and supporting evidence through the administrative dashboard.
- **FE-2:** Allow administrators to approve, modify, scope-limit, or reject generated rules.
- **FE-3:** Deploy only validated rules into the active rule engine to ensure operational safety.

### Continuous Learning and Model Fine-Tuning Loop

- **FE-1:** Collect application-specific benign traffic and filter out suspected attacks for clean training data.
- **FE-2:** Periodically fine-tune the anomaly detection model and recalculate anomaly thresholds and clusters.
- **FE-3:** Feed validated attack patterns and updated models back into the detection and rule layers to maintain a self-learning WAF.

## 1.8 Related System Analysis/Literature Review

Modern Web Application Firewalls such as Cloudflare WAF, AWS WAF, and ModSecurity are widely used to protect web applications against common attacks like SQL injection and cross-site scripting. These systems primarily rely on predefined rule sets, signatures, and manual tuning, which makes them effective for known threats but weak against zero-day and application-specific attacks. Some advanced WAFs include basic anomaly detection, but they still require extensive configuration and produce high false-positive rates in dynamic environments. Research-based intrusion detection systems have explored machine learning, but many depend on labeled attack data, which limits their ability to detect new and evolving threats.

The proposed project builds on these systems by introducing behavior-based anomaly detection and adaptive rule generation, allowing it to learn from real application traffic and continuously improve protection without relying solely on predefined attack signatures.

**Table 1 – Related System Analysis with Proposed Project Solution**

| Application Name | Weakness | Proposed Project Solution |
|---|---|---|
| Cloudflare WAF | Relies heavily on predefined rules and signatures; limited detection of zero-day attacks. | Uses behavior-based anomaly detection to identify unknown and previously unseen attacks. |
| AWS WAF | Requires manual rule configuration and tuning for each application. | Learns normal application behavior automatically, reducing manual configuration. |
| ModSecurity | High false positives due to generic OWASP rules. | Uses contextual and behavioral analysis to reduce false positives. |
| Traditional Signature-Based IDS/WAF | Cannot detect new or obfuscated attack patterns. | Detects attacks by identifying deviations from learned normal traffic patterns. |

## 1.9 Tools and Technologies

| Tools and Technologies | Version | Rationale |
|---|---|---|
| Go (Golang) | 1.21 | Implementing reverse proxy, traffic interception, and WAF core logic. |
| MongoDB | 6.2 | Storage of normalized traffic, AI features, rules, and logs for query and analysis. |
| Python | 3.11 | AI/ML model development (autoencoder, clustering, pattern mining). |
| TensorFlow / Keras | 2.x | Building and training autoencoder for anomaly detection. |
| HDBSCAN (Python library) | 0.8 | Latent-space clustering to reduce false positives and detect unknown attacks. |
| FP-Growth (MLxtend / Python) | Latest | Pattern mining for AI-enhanced rule generation. |
| Docker | 24.x | Containerization for reproducible environment and service deployment. |
| Nginx | 1.26 | Optional reverse proxy and load balancing during testing. |
| VS Code | 1.91 | Integrated development environment for code editing and debugging. |
| Git / GitHub | Latest | Version control and code repository management. |
| HTML / CSS / JavaScript | Latest | Dashboard front-end development for visualization and rule management. |
| Plotly / Chart.js | Latest | Visualization of traffic trends, anomalies, and analytics in dashboard. |
| RESTful APIs | N/A | Communication between dashboard, backend, and AI modules. |
| Postman | Latest | Testing and debugging APIs and request flows. |

## 1.10 Project Contribution

The proposed AI-driven Web Application Firewall introduces several technical and conceptual contributions that differentiate it from traditional and commercial WAF solutions:

- **AI-Powered Unknown Attack Detection:** Integrates an autoencoder-based anomaly detection model combined with HDBSCAN clustering to identify previously unseen attacks, providing enhanced security beyond signature-based WAFs.
- **Layered Security Architecture:** Combines fast rule-based filtering, threat intelligence, and unsupervised AI in a unified system, ensuring both immediate threat mitigation and adaptive protection.
- **AI-Enhanced Rule Generation:** Automatically mines attack patterns from confirmed malicious traffic to create new WAF rules, enabling continuous self-improvement and reducing manual rule-writing effort.
- **Human-in-the-Loop Validation:** Balances automation with administrative oversight, allowing safe deployment of AI-generated rules while maintaining operational trust.
- **Explainable AI Decisions:** Logs all features and reasoning behind allow/block decisions, providing transparency, auditability, and forensic value.
- **Traffic Normalization and Feature Extraction:** Standardizes requests into structured JSON and extracts behavioral/contextual features, enabling accurate machine learning analysis and efficient processing.
- **Dashboard Visualization and Analytics:** Provides real-time monitoring of attack trends, rule effectiveness, and endpoint risk scores, enhancing operational visibility and usability for administrators.
- **Continuous Learning Loop:** Implements a closed-loop system that integrates detection, pattern mining, rule generation, and validation, improving detection accuracy over time.

**Contribution Impact:** By combining AI, threat intelligence, rule-based filtering, and explainable decision-making, this project transforms a conventional WAF into an adaptive, self-learning, and transparent security solution. It improves detection of zero-day attacks, reduces reliance on manual rule creation, and enhances operational monitoring, offering a novel and practical approach to web application protection.

## 1.11 Relevance to Course Modules

- **Cybersecurity:** Applied knowledge of web security, threat modeling, penetration testing concepts, and zero-day attack detection.
- **Software Engineering:** Followed SDLC phases, requirement analysis, system design, and modular development for the WAF.
- **Database Systems:** Implemented MongoDB for storing normalized traffic, AI features, rules, and logs, enabling efficient queries and analytics.
- **Artificial Intelligence & Machine Learning:** Designed and trained autoencoder-based anomaly detection models and used clustering (HDBSCAN) for latent-space validation.
- **Web Technologies:** Developed a web-based dashboard for real-time visualization, rule management, and operational monitoring.
- **Networking & Cloud Security:** Applied reverse proxy architecture, TLS termination, and traffic interception to secure web applications.
- **DevSecOps & Automation:** Integrated continuous learning loop, automated AI-driven rule generation, and human-in-the-loop validation for adaptive security.

---

# Chapter 2: Requirement Analysis

This chapter details the requirements and analysis of it.

## 2.1 User Classes and Characteristics

| User Class | Description |
|---|---|
| **User Client** | The client that interacts with the backend application and the main system interaction with our system. |
| **Security Administrator** | The Security Administrator is responsible for deploying, configuring, and monitoring the LatentGuard WAF instance. They oversee rule management, review AI-generated rules before deployment, and configure threat intelligence feeds. Administrators access the web-based dashboard to monitor attack trends, endpoint risk scores, and rule effectiveness. They also tune anomaly detection thresholds and approve or reject rules proposed by the LLM rule generation module. There may be one or a small team of Security Administrators per deployment. |
| **Backend Application Owner** | The Backend Application Owner is a developer or DevOps engineer whose web application or API is protected by the LatentGuard WAF operating as a reverse proxy. They are responsible for registering their application with the WAF and defining custom security rules specific to their application's traffic patterns. They may interact with the system to review false positives affecting their service and request threshold adjustments. They typically have limited interaction with the AI or rule generation internals. |
| **ML/AI Engineer** | The ML/AI Engineer is responsible for training, evaluating, and maintaining the autoencoder anomaly detection model and the HDBSCAN clustering configuration. They manage the continuous learning loop, overseeing periodic model fine-tuning using updated benign traffic data and confirmed attack samples. They validate model performance metrics and adjust reconstruction error thresholds. This role requires familiarity with Python, TensorFlow/Keras, and the HDBSCAN library. |
| **Threat Intelligence Analyst** | The Threat Intelligence Analyst manages and maintains the threat intelligence feeds integrated into the rule-based filtering engine. They monitor external sources for newly identified malicious IPs and domains, update feed configurations, and review blocked requests attributed to threat intelligence hits. They may also review attack patterns mined by the FP-Growth engine to identify emerging threat categories. |
| **Auditor / Compliance Officer** | The Auditor or Compliance Officer requires read-only access to LatentGuard's logs, decision explainability records, and rule audit trails stored in MongoDB. They do not interact with live configuration or rule deployment. Their primary use case is reviewing historical allow/block decisions, verifying that human-in-the-loop validation was performed before rule deployment, and generating compliance reports. |
| **System Actor – Autoencoder Pipeline** | An automated internal component rather than a human user. The autoencoder model processes normalized traffic feature vectors and generates reconstruction error scores for each request escalated past the rule-based filtering layer. Its inputs and outputs are managed programmatically via internal API calls between the Go reverse proxy and the Python ML service. |

## 2.2 Operating Environment

- **OE-1:** LatentGuard shall operate on any Linux-based server environment (Ubuntu 20.04 LTS or later, Debian 11 or later) or Windows Server 2019 and later, deployed either on-premises or on cloud infrastructure (AWS, Azure, or GCP).
- **OE-2:** The reverse proxy core shall be compiled and executed using Go 1.21 or later, and the AI/ML service shall run on Python 3.11 or later with TensorFlow 2.x installed.
- **OE-3:** The system shall require a minimum of 4 CPU cores, 8 GB RAM, and 50 GB available disk storage for baseline operation; GPU acceleration (NVIDIA CUDA-compatible) is recommended for autoencoder training and fine-tuning workloads.
- **OE-4:** The system shall store all traffic logs, normalized request features, anomaly scores, and rule records in a MongoDB 6.2 or later instance, which may be hosted locally on the same server or as a remote managed database service.
- **OE-5:** The administrative dashboard shall be accessible through any modern web browser supporting ECMAScript 2020 or later, including Google Chrome (version 90+), Mozilla Firefox (version 88+), and Microsoft Edge (version 90+).
- **OE-6:** The LLM-assisted rule generation module shall communicate with an external LLM API endpoint over HTTPS; the deployment environment must provide outbound internet access on port 443 for this integration.
- **OE-7:** The system shall support deployment via Docker 24.x or later, with all services containerized and orchestrated using Docker Compose, enabling consistent operation across development, staging, and production environments.
- **OE-8:** The system shall function correctly when the protected backend application and the WAF are co-located on the same host or separated across a local network, provided network latency between the WAF and backend does not exceed 10ms under normal operating conditions.

## 2.3 Design and Implementation Constraints

- **CON-1:** The reverse proxy and WAF core logic shall be implemented in Go (Golang) 1.21 or later, as it provides native concurrency primitives and a built-in `httputil.ReverseProxy` package necessary for high-performance request interception.
- **CON-2:** The anomaly detection model, HDBSCAN clustering, and FP-Growth pattern mining modules shall be implemented in Python 3.11 or later, as the required ML libraries (TensorFlow, HDBSCAN, MLxtend) are only available in the Python ecosystem.
- **CON-3:** The autoencoder model shall be built and trained using TensorFlow 2.x with the Keras API, as the project's learning pipeline depends on its model serialization and incremental fine-tuning capabilities.
- **CON-4:** All traffic logs, normalized request features, anomaly scores, rule records, and explainability metadata shall be stored in MongoDB 6.2 or later, as its schema-flexible document model is required to accommodate variable-length HTTP request structures and evolving feature sets.
- **CON-5:** The rule-based filtering engine shall embed ModSecurity-compatible rule syntax for all generated and administrator-defined WAF rules, ensuring interoperability with the OWASP Core Rule Set and industry-standard rule formats.
- **CON-6:** The LLM-assisted rule generation module shall interface with an external LLM API over HTTPS, and all generated rules must be returned in ModSecurity-compatible format before they are presented for human review.
- **CON-7:** All system components shall be containerized using Docker 24.x or later, as consistent and reproducible deployment across development and evaluation environments is required for academic demonstration and testing.
- **CON-8:** Communication between the Go reverse proxy core and the Python ML service shall be conducted over a RESTful API interface, as the two components are implemented in different languages and must operate as loosely coupled services.
- **CON-9:** The administrative dashboard shall be built using standard HTML, CSS, and JavaScript without reliance on heavyweight front-end frameworks, in order to minimize external dependencies and simplify deployment within the prototype environment.
- **CON-10:** Training data for the autoencoder shall be sourced from the CSIC 2010 HTTP dataset and application-specific benign traffic logs, as labeled attack datasets are required to establish a verified normal traffic baseline for unsupervised model training.

## 2.4 Use Case Diagram

This section shows the actors and their interaction with the system using a comprehensive use case diagram.

<!-- IMAGE: image2.png
A UML Use Case Diagram for the LatentGuard WAF System, rendered on a dark/black background with white text and white oval use case nodes. The diagram shows four human actors on the left/bottom sides and two system actors on the right, all connected to use cases inside a large rectangle labeled "LatentGuard WAF System".

Actors depicted:
- "Web client" (top-left stick figure): connects to "Intercept & forward HTTP/S traffic", the topmost use case.
- "Security admin" (middle-left stick figure): connects to "Make allow/block decision", "Log decisions & explainability", "Review & approve AI-generated rules", and "Monitor dashboard & audit logs".
- "Auditor" (bottom-left stick figure): connects to "Review & approve AI-generated rules" and "Monitor dashboard & audit logs".
- "ML/AI engineer" (bottom stick figure): connects to "Monitor dashboard & audit logs" and "Fine-tune anomaly detection model".
- "Threat intel feed" (right side, labeled as an actor in a rectangle): connects to "Detect anomaly (autoencoder)".
- "LLM service (external)" (right side, labeled as an actor in a rectangle): connects to "Generate WAF rules via LLM".

Use case flow (connected via dashed «include» and «extend» arrows, top to bottom):
1. "Intercept & forward HTTP/S traffic" →«include»→ "Normalize traffic & extract features"
2. "Normalize traffic & extract features" →«include»→ "Apply rule-based filtering" and →«include»→ "Detect anomaly (autoencoder)"
3. "Detect anomaly (autoencoder)" →«include»→ "Validate cluster (HDBSCAN)"
4. "Validate cluster (HDBSCAN)" →«include»→ "Make allow/block decision"
5. "Apply rule-based filtering" →«include»→ "Make allow/block decision"
6. "Make allow/block decision" →«include»→ "Log decisions & explainability" and →«extend»→ "Mine attack patterns (FP-Growth)"
7. "Mine attack patterns (FP-Growth)" →«include»→ "Generate WAF rules via LLM"
8. "Generate WAF rules via LLM" →«include»→ "Review & approve AI-generated rules"
9. "Review & approve AI-generated rules" →«extend»→ "Fine-tune anomaly detection model"
10. "Monitor dashboard & audit logs" connects back to "Fine-tune anomaly detection model"

The caption at the bottom reads: "Figure A-2: Use Case Diagram of LatentGuard WAF System" -->

## 2.5 Requirement Identifying Technique

This section describes the technique used to identify and document the functional requirements of the system.

For this project, Mockup-Based Requirement Analysis[^1] is used. In this approach, user interface mockups are created using AI tools. These mockups visually represent how users will interact with the system. Functional requirements are then derived from each screen's elements and behaviors.

[^1]: Mockup-Based Requirement Analysis

### Mockup M1 – Login & Authentication Page

<!-- IMAGE: image3.png
A UI mockup of a login page for the "ModSecurity Enhanced – Security Operations Platform". The page has a clean white card-style layout centered on a light gray background. At the top of the card, the title "MODSECURITY ENHANCED" is displayed in bold dark uppercase letters, followed by the subtitle "Security Operations Platform" in smaller gray text. Below the title are two input fields: the first has an envelope icon and placeholder text "Email", and the second has a padlock icon and placeholder text "Password". Beneath the fields is a checkbox labeled "Remember Me". A prominent blue "SIGN IN" button spans the full width of the card below the checkbox. Under the button is a blue hyperlink reading "Forgot Password?". A horizontal divider separates this from a status indicator at the bottom of the card: a green filled circle followed by green text "All Services Operational", and below that, in small gray text, "Last ML Model Update: 2026-03-27 02:00 UTC". The design is minimal and professional with no imagery. -->

**Functional Requirements Derived from Mockup M1 – Login Page**

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **User Sign-In** | FR1.1: The system shall allow authenticated users to access the dashboard by providing valid email and password credentials. | Email must follow standard format. Password must be at least 8 characters with mixed case, numbers, and special characters. |
| **User Authentication** | FR1.2: The system shall validate credentials against stored records in the authentication database. | Accounts shall be locked for 15 minutes after 5 consecutive failed login attempts. |
| **Password Recovery** | FR1.3: The system shall allow users to initiate password recovery when requested. | Only registered users with verified email addresses can request password recovery. |
| **Remember Me Option** | FR1.4: The system shall allow users to stay signed in on the same device by selecting "Remember Me". | Session shall remain active for 30 days or until user explicitly logs out. |

### Mockup M2 – Dashboard Overview

<!-- IMAGE: image4.png
A UI mockup of the main dashboard for "ModSecurity Enhanced", displayed in a light/white theme. At the top is a blue navigation bar with the "ModSecurity Enhanced" logo (a white square outline icon) on the left, and navigation items on the right: "Alerts" (bell icon), "Analytics" (bar chart icon), "Settings" (gear icon), "Reports" (document icon), and "Profile" (person icon).

Below the nav bar, the main content area shows a personalized heading "Welcome back, Admin!" on the left and a "Last 24 Hours" dropdown button on the right.

Below the heading are two rows of metric summary cards arranged in a 3-column grid:

Top row:
- "Total Requests": value 1,247,892 with a green upward arrow "+8.2% vs day"
- "Blocked": value 12,431 with a red upward arrow "+3.1% vs day"
- "Allowed": value 1,235,461 with a green upward arrow "+8.4% vs day"

Bottom row:
- "M4 Autoencoder Anomaly Score": value 0.023 with a green downward arrow "↓ 0.5%"
- "M5 HDBSCAN Outliers": value 431 with a red upward arrow "↑ 12%"
- "Consensus Accuracy": value 96.7% with a green upward arrow "↑ 2.1%"

All cards are white with light gray borders and rounded corners. The layout is clean and professional. -->

**Functional Requirements:**

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **Navigation Menu** | FR2.1: The system shall provide access to key sections (Alerts, Analytics, Settings, Reports, Profile) through a top navigation bar. | Menu items shall be displayed based on user role (Admin, Analyst, Viewer). |
| **Personalized Welcome** | FR2.2: The system shall display a personalized welcome message showing the authenticated user's name. | User name shall be retrieved from the authenticated session. |
| **Request Metrics** | FR2.3: The system shall display total requests, blocked count, and allowed count with percentage change indicators. | Metrics shall update in real-time with data aggregated from the last 24 hours and compared to previous period. |
| **Traffic Timeline** | FR2.4: The system shall display a graphical timeline of traffic with anomaly score overlay. | Timeline shall refresh every 5 minutes with data from the logging database (M7). |
| **ML Model Status** | FR2.5: The system shall display real-time status and performance metrics for M4 (Autoencoder) and M5 (HDBSCAN) models. | Model status shall indicate current load, accuracy, and any degradation alerts. |
| **Recent Events Table** | FR2.6: The system shall display a list of recent security events including timestamp, source IP, decision, and anomaly score. | Events shall be sorted by most recent timestamp, showing maximum 10 rows per page. |
| **View All Link** | FR2.7: The system shall allow navigation to the complete logs view from the recent events section. | Clicking "View All" shall redirect to the Logs & Audit page with current filter context. |

<!-- IMAGE: image5.png
A two-panel UI mockup showing dashboard components for the ModSecurity Enhanced platform, displayed in a white/light theme.

Left panel – "Request Volume with Anomaly Overlay": A line chart occupying most of the panel. The X-axis shows time from 00:00 to 22:00 in 2-hour intervals. The Y-axis shows values from 0 to 10000. A single red line overlays a blue-shaded area chart. The red line represents anomaly spikes and rises steeply from around 2500 at midnight, dips slightly at 04:00, then climbs consistently through the day to peak near 9500 at 16:00 before declining to around 4800 by 22:00. The blue shaded area (representing normal traffic) follows a similar but smoother bell-curve shape. A legend in the top-right corner of the panel shows a blue dot labeled "Normal Traffic" and a red dot labeled "Anomaly Spikes".

Right panel – "ML Model Status": A vertical list of two model status entries, each with a label, percentage, blue progress bar, and a green "Active" status dot.
- M4 Autoencoder: 92% — blue progress bar approximately 92% full — green dot "Active"
- M5 HDBSCAN: 87% — blue progress bar approximately 87% full — green dot "Active" -->

<!-- IMAGE: image6.png
A UI mockup of the "Recent Security Events" table component, displayed in a light/white theme. The header reads "Recent Security Events" in bold on the left and a blue "View All →" hyperlink on the right.

The table has five columns: TIME, SOURCE IP, DECISION, ANOMALY SCORE, and SEVERITY. It shows five rows of data:

1. Time: 15:32:21 | Source IP: 192.168.1.45 | Decision: "BLOCK" (red badge) | Anomaly Score: 0.94 (red) | Severity: CRITICAL (red bold)
2. Time: 15:30:05 | Source IP: 10.0.0.123 | Decision: "ALLOW" (green badge) | Anomaly Score: 0.12 (green) | Severity: LOW (gray)
3. Time: 15:28:44 | Source IP: 203.0.113.56 | Decision: "BLOCK" (red badge) | Anomaly Score: 0.89 (red) | Severity: HIGH (orange-red bold)
4. Time: 15:25:12 | Source IP: 172.16.0.89 | Decision: "REVIEW" (yellow/amber badge) | Anomaly Score: 0.67 (amber) | Severity: MEDIUM (amber bold)
5. Time: 15:22:03 | Source IP: 45.33.22.11 | Decision: "BLOCK" (red badge) | Anomaly Score: 0.92 (red) | Severity: HIGH (orange-red bold)

Each decision badge is a pill-shaped colored label. Color coding is consistent: red for BLOCK/high scores, green for ALLOW/low scores, amber/yellow for REVIEW/medium scores. Rows are separated by light gray horizontal dividers. -->

### Mockup M3 – Anomaly Detection (M4 & M5)

<!-- IMAGE: image7.png
A full-page UI mockup for the "Anomaly Detection" screen, displayed in a purple/dark theme. The page title "Anomaly Detection" appears at the top in white text with a back arrow "← Back".

The page is divided into three main sections:

Section 1 – Two side-by-side model status cards:
Left card "Autoencoder (M4)": Has a green "Active" badge and a purple "92% Acc" badge in the header. Shows metadata fields: Model Version (v2.3.1), Last Trained (2026-03-26 02:00), Reconstruction Error (0.023), Anomaly Threshold (0.15), Anomalies (24h): 287, False Positive Rate: 1.2%. Two buttons at the bottom: "Retrain Model" (dark) and "Adjust Threshold" (dark outline).
Right card "HDBSCAN Clustering (M5)": Has a green "Active" badge. Shows: Min Cluster Size (5), Min Samples (3), Total Clusters (142), Outliers Detected (431), False Positive Rate (2.1%). Two buttons: "Re-cluster" and "Export Results".

Section 2 – "HDBSCAN Cluster Visualization" panel: A scatter plot on a white/light background with axes from 0 to 100 on both X and Y. Scattered purple/violet dots are clustered into two main groupings: one denser cluster around coordinates (70–90, 20–35) and another looser grouping around (110–160, 20–40) (note: axis shows 0–100 but some dots appear slightly beyond). A legend at the bottom shows four categories: blue circle = Normal Traffic, yellow triangle = Anomaly, red square = Outlier, hollow circle = Noise. Most dots appear as normal traffic (purple) with some variance.

Section 3 – "Autoencoder Reconstruction Error Trend" panel: A line chart with the title and an "Expand" button. The X-axis shows dates from 02/20 to 02/27. The Y-axis shows loss values from 0.00 to 0.08. Two overlapping lines (Training Loss and Validation Loss, labeled in a legend below) both start around 0.07–0.075 on 02/20 and decline gradually, nearly converging around 0.02–0.03 by 02/27, indicating successful model training convergence. -->

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **Autoencoder Status Display** | FR3.1: The system shall display current status, version, and performance metrics for the M4 Autoencoder model. | Status indicators shall show Active, Training, Degraded, or Offline states. |
| **Retrain Model Button** | FR3.2: The system shall allow administrators to initiate retraining of the autoencoder on new benign traffic data. | Retraining shall only be performed during scheduled maintenance windows or when model degradation exceeds 5%. |
| **Adjust Threshold Control** | FR3.3: The system shall allow administrators to modify the anomaly detection threshold for the autoencoder. | Threshold range shall be 0.01 to 0.50 with default 0.15. Changes shall be logged for audit. |
| **HDBSCAN Configuration** | FR3.4: The system shall display and allow modification of HDBSCAN clustering parameters (min cluster size, min samples). | Parameter changes shall trigger re-clustering of recent data. |
| **Cluster Visualization** | FR3.5: The system shall provide a 2D visualization of clusters with color-coded points representing normal traffic, anomalies, outliers, and noise. | Visualization shall update when re-clustering is performed. |
| **Error Trend Graph** | FR3.6: The system shall display a historical trend of autoencoder reconstruction error over the last 7 days. | Graph shall support drill-down to hourly granularity. |

### Mockup M4 – Consensus Engine (M6)

<!-- IMAGE: image8.png
A full-page UI mockup for the "Consensus Engine" screen, displayed in a white/light theme with a dark top navigation bar. The page title "Consensus Engine" appears at the top left with a back arrow.

The page contains two main sections:

Section 1 – "Consensus Configuration" panel (white card with a light orange/red flame icon):
- Consensus Mode: Three radio button options listed vertically: "Weighted Voting" (currently selected, filled circle), "Majority", and "Strict (All)".
- Model Weights: Three labeled horizontal slider controls, each spanning the full width with the current value shown on the right:
  - "M4 (Autoencoder)" — 40% (slider thumb positioned at ~40% from left)
  - "M5 (HDBSCAN)" — 30% (slider thumb positioned at ~30% from left)
  - "ModSecurity CRS" — 30% (slider thumb positioned at ~30% from left)
  - Below the sliders: green text "Sum: 100% ✓"
- Decision Threshold: A single labeled horizontal slider with value 0.65 (thumb at ~65%). Below it: small gray text "Block if consensus score ≥ threshold".
- Two action buttons spanning full width: a black "Save Configuration" button on the left and a gray "Reset to Defaults" outline button on the right.

Section 2 – "Recent Decisions" panel (white card):
- Header: "Recent Decisions" on the left and a "↺ Refresh" button on the right.
- Table with columns: Time, Request URI, M4, M5, CRS, Consensus, Final Decision.
- Four data rows:
  1. 15:32:21 | /api/login | M4: 0.94 | M5: 0.89 | CRS: 1.00 | Consensus: 0.94 | Final: "BLOCK" (red badge)
  2. 15:30:05 | /api/products | M4: 0.12 | M5: 0.08 | CRS: 0.00 | Consensus: 0.07 | Final: "ALLOW" (green badge)
  3. 15:28:44 | /admin/config | M4: 0.89 | M5: 0.76 | CRS: 0.95 | Consensus: 0.87 | Final: "BLOCK" (red badge)
  4. 15:25:12 | /api/data | M4: 0.67 | M5: 0.45 | CRS: 0.00 | Consensus: 0.42 | Final: "ALLOW" (green badge)
- Below the table: three action buttons: "Override Decision", "View Details", and "Export Decision Log". -->

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **Consensus Mode Selection** | FR4.1: The system shall support three consensus modes: Weighted Voting, Majority, and Strict (all models must agree). | Mode selection shall persist across system restarts and be logged for audit. |
| **Weight Configuration** | FR4.2: The system shall allow administrators to assign weight percentages to each detection model (M4, M5, ModSecurity CRS). | Sum of all weights must equal 100%. Weight changes shall require confirmation. |
| **Decision Threshold** | FR4.3: The system shall allow configuration of the decision threshold for block/allow determination. | Threshold shall be between 0.00 and 1.00. Default threshold is 0.65. |
| **Decisions Table** | FR4.4: The system shall display recent decisions with individual model scores and consensus result. | Table shall show last 50 decisions by default with pagination support. |
| **Override Decision** | FR4.5: The system shall allow administrators to manually override automated decisions. | Override shall be logged with administrator identity, reason, and timestamp. |
| **Export Logs** | FR4.6: The system shall allow exporting decision logs in CSV and JSON formats. | Export shall include all decision parameters and override history. |

### Mockup M5 – LLM Rule Generation & Human Review (M8, M9, M10)

<!-- IMAGE: image9.png
A UI mockup for the "Rule Generation & Review" page, displayed in a white/light theme. The page title is "Rule Generation & Review" in large bold black text at the top.

Below the title is the "Attack Pattern Mining" card. It features a magnifying glass emoji icon on the left, the section title "Attack Pattern Mining", and a gray dot with the text "Idle" indicating the mining process is currently inactive.

Inside the card are two sub-cards arranged side by side:
- Left sub-card "New Patterns Detected": displays the large blue number "7".
- Right sub-card "Last Scan": displays the date "2026-03-27 00:00" in teal/green text.

Below the sub-cards are three horizontal progress bars, each with a label on the left and a confidence percentage on the right:
1. "SQL Injection - time-based" — 94% — bar filled in green (~94%)
2. "Path traversal obfuscation" — 87% — bar filled in amber/orange (~87%)
3. "User-agent spoofing cluster" — 91% — bar filled in green (~91%)

At the bottom is a blue hyperlink "+ 4 more patterns ∨" indicating there are additional patterns that can be expanded. -->

<!-- IMAGE: image10.png
A small UI snippet showing two action buttons side by side on a white background:
- Left button: A filled blue button with a right-pointing play triangle icon followed by the text "Run Pattern Mining".
- Right button: A gray/white outline button with a gear/settings icon followed by the text "Configure Detection Parameters".
These are the primary action controls for the Attack Pattern Mining section. -->

<!-- IMAGE: image11.png
A UI mockup for the "LLM-Generated Rules" panel, displayed in a white/light theme. The panel header reads "LLM-Generated Rules" on the left with a robot emoji icon, and a blue "Generate" button on the top right.

The main body of the panel contains a dark-themed code block (dark navy/near-black background) displaying a generated ModSecurity rule in monospace font:

```
SecRule ARGS "@rx (?i)(sleep|benchmark|waitfor)\s*\(\s*\d+\s*\)"
    "id:100001,
    phase:2,
    deny,
    status:403,
    msg:'LLM-Gen: Time-based SQL Injection',
    severity:CRITICAL"
```

Below the code block are three metadata badges in a row:
- Green badge: "Confidence: 92%"
- Yellow/amber badge: "Expected FP Rate: 3%"
- Red badge: "CRITICAL"

Below the badges are four action buttons in a row:
- Green button with checkmark icon: "Accept"
- Blue button with edit/pencil icon: "Edit"
- Red button with X icon: "Reject"
- White/outline button with a screen icon: "Test in Sandbox" -->

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| Pattern Mining Status | FR5.1: The system shall display current status of attack pattern mining process (M8). | Status shall show Idle, Running, Completed, or Failed states. |
| New Patterns Display | FR5.2: The system shall list newly detected attack patterns with confidence scores. | Patterns with confidence below 70% shall be flagged for review only, not auto-processed. |
| Run Pattern Mining | FR5.3: The system shall allow manual initiation of attack pattern mining on recent blocked traffic. | Mining process shall analyze last 24 hours of blocked requests. |
| LLM Rule Generation | FR5.4: The system shall generate ModSecurity-compatible rules from validated attack patterns using LLM. | Generated rules shall follow ModSecurity CRS syntax standards. |
| Rule Preview | FR5.5: The system shall display generated rules with metadata including confidence score, expected false positive rate, and severity. | Rules must be reviewed by human before deployment. |
| Human Review Queue | FR5.6: The system shall maintain a queue of pending rules requiring human review. | Rules remain pending until explicitly accepted, edited, or rejected by an administrator. |
| Bulk Operations | FR5.7: The system shall allow bulk approval or rejection of multiple rules. | Bulk operations shall require confirmation with audit logging. |

<!-- IMAGE: image12.png
A UI mockup of the "Human Review Queue" panel, displayed in a white/light theme. The panel header reads "Human Review Queue" with a purple person/admin icon on the left and an orange badge on the right reading "Pending: 7".

The queue contains seven rule entries displayed as a vertical list, each on a separate row with a checkbox on the far left, rule details in the center, a severity badge, and three icon buttons on the far right (green checkmark = Accept, blue pencil = Edit, red X = Reject).

The seven rule entries are:
1. Rule #1: SQL Injection - Time Based — CRITICAL (red badge) — "Detects time-based blind SQL injection attempts"
2. Rule #2: Path Traversal - Encoded — HIGH (orange badge) — "Blocks encoded directory traversal attempts"
3. Rule #3: User-Agent Anomaly Block — MEDIUM (amber badge) — "Flags suspicious user-agent patterns"
4. Rule #4: API Rate Limit Bypass — HIGH (orange badge) — "Prevents rate limit circumvention techniques"
5. Rule #5: Session Fixation Attempt — CRITICAL (red badge) — "Blocks session fixation attack vectors"
6. Rule #6: Header Injection Pattern — MEDIUM (amber badge) — "Detects HTTP header injection attempts"
7. Rule #7: CSRF Token Validation — HIGH (orange badge) — "Enforces CSRF token validation"

At the bottom of the panel are three bulk-action buttons spanning the full width: "Approve Selected (0)" (green), "Reject Selected (0)" (pink/red), and "Bulk Edit (0)" (gray). -->

### Mockup M6 – Logging & Audit

<!-- IMAGE: image13.png
A UI mockup for the "Logs & Audit" page, displayed in a white/light theme. The page title is "Logs & Audit" in large bold black text at the top left, with a back arrow "‹" to its left.

Below the title is a filter/search bar row containing:
- A calendar icon dropdown labeled "Last 24h"
- A decision type dropdown labeled "All"
- A severity dropdown labeled "All"
- A wide search input with placeholder text "Search by IP, URI, or Request ID..."
- A blue "Apply" button on the far right

Below the filter bar is a data table with five columns: REQUEST ID, TIMESTAMP, SOURCE IP, DECISION, and REASON.

Five rows are displayed:
1. #a7f3b2 (expanded/open state, shown with a downward chevron ∨) | 15:32:21.452 | 192.168.1.45 | "BLOCK" (red badge) | Consensus
   - Expanded detail row shows:
     - "Method: POST   URI: /api/login"
     - "Anomaly Scores: M4=0.94, M5=0.89, CRS=1.00"
     - "Payload: {"username":"admin","password":"*****"}"
     - "Rule Triggered: LLM-GEN-100001 (Time-based SQL Injection)" (in red text)
2. #b8e4c3 (collapsed, rightward chevron ›) | 15:30:05.123 | 10.0.0.123 | "ALLOW" (green badge) | Consensus
3. #c9f5d4 (collapsed) | 15:28:44.987 | 203.0.113.56 | "BLOCK" (red badge) | M4 Only
4. #d0e6e5 (collapsed) | 15:25:12.456 | 172.16.0.89 | "REVIEW" (amber badge) | Consensus
5. #e1f7f6 (collapsed) | 15:22:03.789 | 45.33.22.11 | "BLOCK" (red badge) | LLM Rule

At the bottom of the table are three left-aligned buttons: "Export CSV", "Export JSON", "View Analytics", and right-aligned pagination info: "Page 1 of 47" with "Previous" and "Next" buttons. -->

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **Date Range Filter** | FR6.1: The system shall allow filtering logs by date range (preset and custom). | Log retention period shall be 90 days for detailed logs, 365 days for summarized metrics. |
| **Decision Filter** | FR6.2: The system shall allow filtering logs by decision type (Block, Allow, Review). | Filter options shall include ALL, BLOCK, ALLOW, and REVIEW. |
| **Search Functionality** | FR6.3: The system shall allow searching logs by IP address, URI, or request ID. | Search shall support partial matching and wildcard characters. |
| **Expandable Row Details** | FR6.4: The system shall allow expanding log entries to view full request details, anomaly scores, and triggered rules. | Expandable section shall show complete request/response details. |
| **Export Functionality** | FR6.5: The system shall allow exporting filtered logs in CSV and JSON formats. | Exports shall be limited to 100,000 rows per request with async notification. |
| **Pagination** | FR6.6: The system shall support pagination with configurable rows per page (default 25). | Page navigation shall maintain current filter settings. |

### Mockup M7 – Training Pipeline (Autoencoder Training)

<!-- IMAGE: image14.png
A UI mockup for the "Training Pipeline" page, displayed in a white/light theme. The page title is "Training Pipeline" in large bold black text at the top left, with a back arrow to its left.

Below is a card titled "Autoencoder Training (M4)" containing two main configuration sections:

Section 1 – "Training Data Source": Three radio button options listed vertically:
- "Last 7 days of benign traffic (recommended)" — currently selected (filled blue circle)
- "Custom date range:" — unselected, with two date input fields: "01/03/2026" to "27/03/2026" (grayed out)
- "Upload labeled benign dataset" — unselected

Section 2 – "Model Configuration": A two-column grid of labeled configuration fields:
Left column:
- "Input Features:" — text input showing "IP, URI, Method, Headers, Payload..." in monospace code style
- "Encoding Dimension:" — a stepper control showing "32" with minus (−) and plus (+) buttons
- "Hidden Layers:" — a stepper control showing "3" with minus (−) and plus (+) buttons

Right column:
- "Learning Rate:" — text input showing "0.001"
- "Epochs:" — a stepper control showing "100" with minus and plus buttons
- "Validation Split:" — text input showing "20%"
- "Batch Size:" — text input showing "64"

Below the configuration grid is a collapsed "Advanced Settings ∨" link in blue. -->

<!-- IMAGE: image15.png
A UI mockup showing the "Loss Curve" section of the Training Pipeline page, displayed in a white/light theme. The panel header reads "Loss Curve" in bold black text.

The main content is a line chart with a white/light background and subtle dashed grid lines. The legend at the top center shows two series: "Training Loss" (blue line with circle markers) and "Validation Loss" (gold/amber line with circle markers).

X-axis: labeled "Epochs", showing values from 0 to 45 in increments of approximately 1–2 (some labeled: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45).
Y-axis: labeled "Loss", showing values from 0.00 to 0.10 with gridlines at 0.00, 0.03, 0.05, 0.07, 0.10.

Both the Training Loss and Validation Loss curves start at approximately 0.075–0.08 at epoch 0 and decrease monotonically following an exponential decay curve. By epoch 45, both lines converge to approximately 0.029–0.030. The two lines are nearly identical throughout, indicating good generalization with no significant overfitting.

Below the chart are three buttons aligned to the left: a blue "Start Training" button, a white "Cancel" button, and a white "Use Baseline Model" button. -->

| Feature (derived from UI) | Functional Requirement (FR-ID: Statement) | Business Rule |
|---|---|---|
| **Data Source Selection** | FR7.1: The system shall allow selection of training data source from recent benign traffic, custom date range, or uploaded dataset. | Training data must be labeled as benign (no attacks) before use. |
| **Model Configuration** | FR7.2: The system shall allow configuration of autoencoder hyperparameters (encoding dimension, hidden layers, learning rate, epochs). | Configuration changes shall be validated for reasonable ranges. |
| **Training Progress Display** | FR7.3: The system shall display real-time training progress with loss values and estimated completion time. | Training shall support cancellation with automatic model rollback to previous version. |
| **Loss Curve Visualization** | FR7.4: The system shall display training and validation loss curves during and after training. | Loss curves shall be available for comparison across training runs. |
| **Model Deployment** | FR7.5: The system shall allow deployment of trained model as active inference engine after validation. | New model shall be validated against holdout test set before deployment. |
| **Baseline Model Fallback** | FR7.6: The system shall allow reverting to baseline pre-trained model if new model underperforms. | Baseline model shall be preserved as fallback option. |

Based on the system's components (M4, M5, M6, M7, M8, M9, M10), here are the main events that can happen:

**Events Identified for Enhanced ModSecurity WAF**

- **Traffic Received** – happens whenever someone sends an HTTP request to the server
- **M4 Anomaly Detection Complete** – triggers after the autoencoder finishes scoring the request
- **M5 Outlier Detection Complete** – triggers after HDBSCAN finishes analyzing the request
- **Consensus Decision Reached** – triggers when all models have voted and a final decision is made
- **Attack Pattern Detected** – happens when the pattern miner finds a new type of attack
- **LLM Rule Generated** – triggers when the LLM creates a new ModSecurity rule from an attack pattern
- **Rule Approved/Rejected** – happens when a human reviews and decides on a generated rule
- **Model Training Complete** – triggers when the autoencoder finishes retraining on new data
- **False Positive Detected** – happens when an admin marks a blocked request as actually being harmless
- **System Performance Degraded** – triggers when model accuracy drops below acceptable levels

**Event-Response Table**

**Table A-5: Event–Response Table for Enhanced ModSecurity WAF System**

| Event Name | What Triggers It | Where It Comes From | System State (Before) | What the System Does | System State (After) | What If Something Goes Wrong |
|---|---|---|---|---|---|---|
| Traffic Received | HTTP request arrives | External user/client | Waiting for request | Extracts request data, logs it, sends to M4 & M5 | Under analysis | Log error and return 400 if malformed |
| M4 Anomaly Detection Complete | Autoencoder finishes | M4 Module | Waiting for ML result | Calculate anomaly score, flags if above threshold | Score stored | Fallback to ModSecurity |
| M5 Outlier Detection Complete | Clustering completes | M5 Module | Waiting for result | Assigns outlier score and cluster | Score stored | Assign neutral score (0.5) |
| Consensus Decision Reached | All models respond | M6 Engine | Waiting for decision | Computes weighted score, allows/blocks request | Decision logged | Fallback to ModSecurity |
| Attack Pattern Detected | Pattern identified | M8 Module | Monitoring logs | Extracts and stores attack pattern | Ready for rule generation | Flag for manual review |
| LLM Rule Generated | Pattern processed | M9 Module | Waiting for rule | Generates rule and adds to review queue | Pending review | Mark for manual creation |
| Rule Approved/Rejected | Admin reviews | M10 Module | In review queue | Approve → deploy, Reject → archive | Rule active or archived | Rollback if deployment fails |
| Model Training Complete | Training finishes | M4 Module | Training in progress | Validates and deploys if improved | Model updated or unchanged | Revert to previous model |
| False Positive Detected | Admin flags request | M7 Module | Running normally | Updates dataset and adjusts model | Dataset updated | Skip if data issue |
| System Performance Degraded | Accuracy drops | Monitoring Module | Running normally | Alerts admin, switches to safe mode | Safe mode active | Disable ML if needed |

## 2.6 Derived Functional Requirements from Events

**Table A-6: Functional Requirements Derived from Event–Response Table**

| Where It Came From | Functional Requirement (What the System Must Do) | Business Rule (Why It Matters) |
|---|---|---|
| **Traffic Received** | FR-MOD-1: The system shall read and extract important info (IP, URI, method, headers, payload) from every incoming HTTP request. | If the request is badly formatted, reject it with a 400 error before wasting time on ML analysis. |
| **M4 Anomaly Detection Complete** | FR-M4-1: The system shall calculate a reconstruction error score using the autoencoder and flag anything above 0.15 as suspicious. | The 0.15 threshold can be adjusted by admins anywhere between 0.01 and 0.50. |
| **M5 Outlier Detection Complete** | FR-M5-1: The system shall assign outlier scores using HDBSCAN with settings that look for small clusters of unusual traffic. | Any request flagged as an outlier gets counted in the final decision. |
| **Consensus Decision Reached** | FR-M6-1: The system shall combine the scores from all models using weights (M4 40%, M5 30%, ModSecurity 30%) and block anything with a final score of 0.65 or higher. | Admins can change both the weights and the threshold if needed. |
| **Attack Pattern Detected** | FR-M8-1: The system shall scan blocked traffic once a day to find new attack patterns and give them confidence scores. | Only patterns with at least 70% confidence get automatically sent to the LLM for rule generation. |
| **LLM Rule Generated** | FR-M9-1: The system shall use the LLM to write ModSecurity rules from validated attack patterns, and check that the syntax is correct. | Any generated rule has to pass a syntax check before it even gets to the review queue. |
| **Rule Approved/Rejected** | FR-M10-1: The system shall keep a queue of rules waiting for a human to review, and won't deploy any rule without approval. | If a rule is sitting in the queue, it's not live yet. Period. |
| **Model Training Complete** | FR-M4-2: The system shall let admins retrain the autoencoder on normal traffic, and automatically validate new models before switching over. | The new model only gets deployed automatically if it has fewer false positives than the old one. |
| **False Positive Detected** | FR-M7-1: The system shall let admins mark blocked requests as false positives and automatically add them to the training dataset. | False positive records stay in the system for a whole year for auditing. |
| **System Performance Degraded** | FR-MON-1: The system shall keep an eye on model accuracy and send alerts if false positives go above 5% or detection accuracy drops below 90%. | Alerts go to the admin's email and also show up right on the dashboard. |

## 2.7 Non-Functional Requirements

This section specifies non-functional requirements (NFRs) other than constraints and external interface requirements. These requirements define the quality attributes of the system and are written in specific, quantitative, and verifiable terms.

### Reliability

Requirements about how often the software fails, measured in MTBF (mean time between failures), with clear definitions of failure and strategies for detection and correction.

| ID | Requirement | Measurement / Target |
|---|---|---|
| **REL-1** | The system shall process HTTP requests with 99.9% availability during normal operation. | MTBF: 30 days minimum between system failures |
| **REL-2** | The system shall automatically fail over to ModSecurity-only mode if AI/ML modules (M4, M5, M6) become unresponsive or return errors. | Failover within 5 seconds of detection |
| **REL-3** | The system shall log all failures including timestamp, module name, error type, and request context for post-mortem analysis. | 100% of failures logged with complete context |
| **REL-4** | The system shall maintain a heartbeat monitoring mechanism that checks the health of M4 (Autoencoder) and M5 (HDBSCAN) every 60 seconds. | Alert triggered after 3 consecutive missed heartbeats |
| **REL-5** | The system shall recover automatically from module failures within 30 seconds of service restoration. | Automatic recovery with no manual intervention |
| **REL-6** | The system shall preserve all in-flight requests during a failover event, ensuring no request is dropped without being processed. | Zero request loss during failover |

**Definition of Failure:**
- AI/ML module (M4/M5) returns an error or times out (>100ms response time)
- Consensus engine (M6) fails to produce a decision within 200ms
- Logging database (M7) becomes unavailable for writes
- ModSecurity rule engine crashes or stops processing

**Error Detection Strategy:**
- Heartbeat pings to all modules every 60 seconds
- Request timeout monitoring with thresholds
- Database connection pool health checks
- Log file tail monitoring for error patterns

**Correction Strategy:**
- Automatic failover to ModSecurity-only mode
- Automatic retry with exponential backoff for transient failures
- Queue-based buffering during database unavailability
- Automatic restart of failed modules with state recovery

### Usability

Usability requirements include learning ease, user-friendliness, error avoidance, error recovery, interaction efficiency, and accessibility.

- **USE-1:** The system shall allow administrators to see the complete breakdown of the decision process (M4, M5, ModSecurity scores) with a single click on any log entry.
- **USE-2:** The system shall allow administrators to see the metrics on the dashboard update in real time without requiring them to manually reload the page. (Auto-refresh every 30 seconds)
- **USE-3:** The system shall allow administrators to filter log data by date range, decision type, and risk level in 2 or fewer clicks.
- **USE-4:** The system shall highlight log decisions with visual indicators: BLOCK (red), ALLOW (green), REVIEW (yellow). (100% of decisions visually color-coded)
- **USE-5:** The system shall have a search feature that returns results in 3 seconds or less for queries on 30 days of log data.
- **USE-6:** The system shall have keyboard shortcuts: Ctrl+F to start searching, Ctrl+E to export data, Ctrl+R to refresh page.
- **USE-7:** The system shall have tooltips on hover explaining the data displayed in all metric cards and graph elements.
- **USE-8:** The system shall be accessible to users who are visually impaired by having screen reader compatibility and a minimum of 4.5:1 contrast ratio between background and foreground text. (WCAG 2.1 AA compliance)

**Ease of Learning:**
- Onboarding tutorial for first-time administrators
- Contextual help links in each section of the dashboard
- Sample queries and filters pre-filled as examples

**Error Avoidance:**
- Confirmation dialog box to confirm destructive operations
- Input validation with informative error messages
- Warning of unsaved changes before leaving page

**Error Recovery:**
- Undo override option in 5 minutes
- Backup export before executing destructive operations
- Auto-save of filter changes

### Performance

- **PER-1:** The system shall process 95% of HTTP requests in 150ms or less from arrival until final system decision (including ML processing). (95th percentile latency ≤ 150ms)
- **PER-2:** The M4 Autoencoder shall calculate reconstruction error per request in 50ms or less for 99% of requests. (99th percentile ≤ 50ms)
- **PER-3:** The M5 HDBSCAN clustering algorithm shall calculate outlier scores per request in 50ms or less for 99% of requests. (99th percentile ≤ 50ms)
- **PER-4:** The consensus engine (M6) shall calculate weighted decisions in 10ms or less after receiving scores from all models. (99th percentile ≤ 10ms)
- **PER-5:** The dashboard homepage shall completely load in 2 seconds or less from the time the user requests the page. (95% of page loads ≤ 2 seconds)
- **PER-6:** The logs query interface shall display filtered results in 3 seconds or less for queries over up to 100,000 records. (95% of queries ≤ 3 seconds)
- **PER-7:** The system shall support a minimum throughput of 5,000 requests per second on standard hardware configuration. (Sustained throughput ≥ 5,000 RPS)
- **PER-8:** The attack pattern mining process (M8) shall complete in 30 minutes or less to analyze 24 hours of blocked network traffic. (Daily mining ≤ 30 minutes)
- **PER-9:** The LLM rule generation (M9) shall generate rules in 10 seconds or less per pattern. (Per-pattern generation ≤ 10 seconds)
- **PER-10:** The autoencoder retraining (M7) shall complete in 2 hours or less on a dataset of 100,000 benign requests. (Training time ≤ 2 hours)

### Security

- **SEC-1:** The system shall require multi-factor authentication for all administrative accounts. (100% of admin accounts require MFA)
- **SEC-2:** The system shall encrypt all sensitive data in transit using TLS 1.2 or higher for all external communications. (All traffic encrypted with TLS 1.2+)
- **SEC-3:** The system shall hash and salt all user passwords using bcrypt with a work factor of at least 12. (Password storage uses bcrypt with cost=12)
- **SEC-4:** The system shall lock administrative accounts after 5 consecutive failed login attempts for a duration of 15 minutes. (Account lockout after 5 failures)
- **SEC-5:** The system shall log all administrative actions, including rule approvals, overrides, and configuration changes, with a timestamp and user identity. (100% of admin actions audited)
- **SEC-6:** The system shall restrict access to log data using role-based access control. (Minimum 3 roles: Admin, Analyst, Viewer)
- **SEC-7:** The system shall prevent SQL injection attacks using parameterized queries and input validation. (Compliant with OWASP Top 10)
- **SEC-8:** The system shall retain audit logs for a minimum of 365 days for security events and detailed request logs for a minimum of 90 days. (Log retention meets compliance requirements)
- **SEC-9:** The system shall encrypt all log data at rest using AES-256. (All log storage encrypted)
- **SEC-10:** The system shall trigger alerts for failed login attempts exceeding 10 within a window of 5 minutes from a single IP address. (Automated alerting on brute force attempts)

## 2.8 External Interface Requirements

This section provides information to ensure that the system will communicate properly with users and with external hardware or software elements.

### 2.8.1 User Interfaces Requirements

- **UI-1:** The system shall follow a consistent dark/light theme with the following color scheme: Background #0A0C10, Cards #1A1D24, Primary Blue #3B82F6, Success Green #10B981, Danger Red #EF4444, Warning Yellow #F59E0B.
- **UI-2:** The system shall display a top navigation bar on all authenticated pages with menu items: Alerts, Analytics, Settings, Reports, Profile.
- **UI-3:** The system shall use the Inter font family for all text elements, with Fira Code for code blocks and monospace content.
- **UI-4:** The system shall support screen resolutions from 1280×720 to 3840×2160 with responsive layouts that adapt to window size.
- **UI-5:** The system shall display a help button on every screen that links to contextual documentation.
- **UI-6:** The system shall use consistent button styling: primary buttons with blue background, secondary buttons with outline, destructive buttons with red background.
- **UI-7:** The system shall display status indicators using colored dots: green for Active, yellow for Degraded, red for Offline, gray for Idle.
- **UI-8:** The system shall support localization with text strings externalized for future translation to other languages.
- **UI-9:** The system shall provide screen reader compatible ARIA labels for all interactive elements.
- **UI-10:** The system shall display confirmation dialogs for destructive actions with clear description of consequences.

### 2.8.2 Software Interfaces

**SI-1: Backend Application (Protected Resource)**
- SI-1.1: The system shall forward allowed requests to the backend application using the original HTTP method and headers.
- SI-1.2: The system shall return 403 Forbidden responses for blocked requests without forwarding to the backend.

**SI-2: Authentication Service**
- SI-2.1: The system shall integrate with LDAP/Active Directory for administrator authentication.
- SI-2.2: The system shall support OAuth 2.0/OpenID Connect for SSO integration.

**SI-3: Logging Database (M7)**
- SI-3.1: The system shall store all request logs, decisions, and anomaly scores in PostgreSQL/MySQL database.
- SI-3.2: The system shall support time-series database (TimescaleDB/InfluxDB) for metric aggregation and analytics.

**SI-4: LLM Service (M9)**
- SI-4.1: The system shall communicate with OpenAI API or local LLM (Llama 2) for rule generation.
- SI-4.2: The system shall support API key authentication and rate limiting for external LLM services.

**SI-5: Alerting Service**
- SI-5.1: The system shall integrate with SMTP for email alerts to administrators.
- SI-5.2: The system shall support webhook integrations with PagerDuty, Slack, and Microsoft Teams.

**SI-6: SIEM Integration**
- SI-6.1: The system shall export logs in CEF (Common Event Format) and Syslog formats for SIEM integration.
- SI-6.2: The system shall support real-time log forwarding via syslog over TLS.

### 2.8.3 Hardware Interfaces

**HI-1: Server Hardware**
- HI-1.1: The system will run on servers that have at least 4 CPU cores, 16GB of RAM, and 100GB of storage as production hardware requirements.
- HI-1.2: The system will work on virtual machines like VMware and KVM and on containerized environments like Docker and Kubernetes.

**HI-2: Network Interface**
- HI-2.1: The system will use a network interface to receive traffic on ports 80 (HTTP) and 443 (HTTPS).
- HI-2.2: Administrators can configure the system to use additional ports if needed.

**HI-3: HSM / TPM**
- HI-3.1: The system can be set up to work with a Hardware Security Module (HSM) to store TLS keys securely.
- HI-3.2: The system will support TPM 2.0 to check the integrity of the system.

### 2.8.4 Communications Interfaces

**CI-1: Email Communications**
- CI-1.1: The system will send email notifications to administrators when there are security alerts, system degradation events, and rule review requests.
- CI-1.2: The system will send password recovery emails with tokens valid for 15 minutes only.

**CI-2: HTTP/HTTPS Protocols**
- CI-2.1: The system will accept connections from clients using HTTP/1.1 and HTTP/2.
- CI-2.2: The system will only allow HTTPS connections for the administrative web interface.
- CI-2.3: The system will use TLS 1.2 and TLS 1.3 with the latest cipher suites.

**CI-3: API Communications**
- CI-3.1: The system will have a RESTful API that other tools can use to integrate with it.
- CI-3.2: The system will authenticate API requests using API keys and configurable permissions.
- CI-3.3: The system will limit the number of API requests to prevent abuse, allowing 100 requests per minute per API key.

**CI-4: Database Communications**
- CI-4.1: The system will connect to the logging database using connections encrypted with TLS.
- CI-4.2: The system will maintain a connection pool with up to 50 simultaneous database connections.

**CI-5: Syslog Forwarding**
- CI-5.1: The system will forward logs to syslog servers using TCP with TLS encryption.
- CI-5.2: The system will support standard syslog formats RFC 3164 and RFC 5424.
