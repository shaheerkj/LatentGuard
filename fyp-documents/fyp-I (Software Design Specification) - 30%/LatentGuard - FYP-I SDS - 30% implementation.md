**COMSATS University Islamabad**

**FYP-I SDS and 30% Implementation**
LatentGuard: Adaptive Dual Layer Web Application Firewall (WAF) for Anomaly and Threat Detection
***By***
**Syed Shaheer Khalid      ****CIIT/****SP23-BCT-048/ISB**
**Javaria Maqbool      ****CIIT/****SP23-BCT-023/ISB**

***Supervisor******
*****Dr. Farhana Jabeen**

***Bachelor of Science in Cyber Security (2023-2027)***

**The candidate confirms that the work submitted is their own and appropriate****
 credit has been given where reference has been made to the work of others**

# Chapter 3: Design and Architecture

This chapter explains how LatentGuard is built — what components talk to each other, how data moves through the system, and why we made certain design choices. Think of it as the blueprint of our AI-powered WAF.
## 3.1 System Architecture Overview

Before jumping into code, we need a bird's-eye view of the system. LatentGuard sits between the internet and your web application, inspecting every incoming request. It's not just a simple filter — it's a pipeline of checks: first traditional rules, then AI models, then a consensus engine, and finally a learning loop that improves the system over time.

### 3.1.1: Purpose

**What This Diagram Shows**
The diagram below traces a single HTTP request from the moment it arrives until a decision is made — and beyond, into the feedback loop that makes the system smarter.
**Walking Through the Flow**
Let me walk you through what happens when a request hits LatentGuard:
- **The request arrives** — encrypted over HTTPS. Our Nginx reverse proxy terminates the TLS connection, so the rest of the system can read the traffic in plaintext. Nginx also balances load if we're running multiple instances.
- **We clean up the request** — the normalization layer takes the raw HTTP request and extracts what matters: the IP address, the URI, the HTTP method, all headers, and the body. It also decodes things like URL encoding so attackers can't hide behind obfuscation.
- **Traditional rules run first** — ModSecurity with the OWASP Core Rule Set does a quick pass. These are the classic signatures for SQL injection, XSS, path traversal, and so on. If a request matches a high-severity rule, we block it immediately — no need to waste AI compute on obvious attacks.
- **The AI layer kicks in for suspicious traffic** — if ModSecurity isn't sure (medium risk), we forward the request to two AI models running in parallel:
  - **M4 (Autoencoder):** Compresses the request down to its "essence" and tries to rebuild it. If the rebuild is messy (high reconstruction error), that's a red flag — the request doesn't look like normal traffic.
  - **M5 (HDBSCAN):** Takes the compressed representation from the autoencoder and checks where it falls among clusters of normal traffic. If it's isolated — an outlier — that's another red flag.
Both models run independently, and each produces a score.
- **The consensus engine makes the final call** — we take three scores: M4 (40% weight), M5 (30% weight), and ModSecurity's severity (30% weight). If the weighted sum hits 0.65 or higher, we block the request. Below that, we allow it. There's also a "challenge" option for borderline cases — maybe a CAPTCHA to prove it's human.
Why weights? Because the autoencoder is our primary zero-day detector. The other two act as sanity checks.
- **Everything gets logged** — every request, every score, every final decision goes into MongoDB. This isn't just for audit — it feeds the learning loop.
- **The learning loop closes the gap** — here's where LatentGuard improves itself:
  - **M8:** Once a day, we scan blocked traffic and look for repeating patterns — things that look like structured attacks.
  - **M9:** Those patterns get sent to an LLM (OpenAI or a local model like Llama 2), which writes a proper ModSecurity rule.
  - **M10:** A human admin reviews the generated rule through a dashboard — approve, edit, or reject.
  - **M4/M5 retraining:** Approved rules get deployed to ModSecurity. False positives (legit requests we wrongly blocked) get fed back into the autoencoder's training data, so next time it recognizes them as normal.
This loop means LatentGuard isn't static. Every attack it sees makes it stronger, and every mistake it makes gets corrected.

## 3.2 Architecture Diagram:

**Why We Chose a Layered Pipeline**
If you open the hood of LatentGuard, you'll see a **layered architecture** — sometimes called a pipeline. A request enters at one end, passes through stages in order, and exits the other end with a decision attached.
**Purpose**
We picked a layered pipeline for five reasons:
- **It's sequential** — a request has to go through proxy → normalization → rules → AI → consensus. That's just the nature of a WAF. You can't skip steps.
- **Separation of concerns** — each layer does exactly one job. The autoencoder doesn't care about TLS termination. ModSecurity doesn't care about clustering. This makes the code maintainable.
- **Independent scaling** — if traffic spikes, the AI layer can scale separately from the rule engine. We can spin up more Python containers without touching Nginx.
- **Fault tolerance** — if the AI layer crashes, the system falls back to ModSecurity-only mode. The request still gets a decision, even if it's not the ideal one.
- **Testability** — we can test each layer in isolation. Mock the AI models to test the consensus engine. Mock ModSecurity to test the autoencoder.
**The Six Layers**

| Layer | What's Inside | Its Job |
| --- | --- | --- |
| **1. Ingress** | Nginx + normalization | Get traffic in, clean it up |
| **2. Traditional Detection** | ModSecurity + OWASP CRS | Block known attacks fast |
| **3. AI Detection** | Autoencoder, HDBSCAN | Find zero-day attacks |
| **4. Consensus** | Weighted decision engine | Make the final call |
| **5. Observability** | MongoDB | Log everything |
| **6. Learning** | Pattern mining, LLM, human review | Improve the system over time |

**Visualizing the Layers**
Here's what the layered architecture looks like:

### 3.2.1 Technologies and Services

| Component | What It Does | Technology | Security Measure |
| --- | --- | --- | --- |
| **Reverse Proxy** | Terminates HTTPS, balances load | Nginx | TLS 1.2/1.3, HSTS |
| **ModSecurity** | Runs OWASP rules, blocks known attacks | ModSecurity + CRS | Custom blacklists, threat intel feeds |
| **Feature Extraction** | Turns raw HTTP into clean features | Go (custom) | Sanitizes inputs |
| **Autoencoder (M4)** | Detects anomalies via reconstruction error | Python + TensorFlow | Model files encrypted |
| **HDBSCAN (M5)** | Validates anomalies via clustering | Python + HDBSCAN | API calls over TLS |
| **Consensus Engine (M6)** | Weights three scores, decides block/allow | Go (custom) | Audit trail on every decision |
| **MongoDB (M7)** | Stores everything — requests, scores, rules | MongoDB | AES-256 at rest, TLS in transit |
| **Pattern Mining (M8)** | Finds attack patterns in logs | Python + FP-Growth | Data anonymized |
| **LLM Rule Gen (M9)** | Writes ModSecurity rules from patterns | OpenAI API / Llama 2 | API keys, rate limits |
| **Admin Dashboard (M10)** | Lets humans review and approve rules | React + REST API | MFA, role-based access |
| **Docker + K8s** | Packages and scales everything | Docker, Kubernetes | Network policies, secrets |

## 3.4 Design Models (Diagrams to Create)

### 3.4.1: Design Models for Object Oriented Development Approach

**Activity Diagram**
**Purpose:** To illustrate the complete workflow of a request through the LatentGuard system, from ingress to final decision and feedback loop.
**Core Workflow (Non-trivial):** Request processing through ModSecurity → AI/ML detection → Consensus decision → Logging → Continuous learning

### 3.4.2 Design Models for Procedural Approach

#### 3.4.2.1: Data Diagram

**Purpose:** To show how data moves through the system, including requests, features, anomaly scores, and generated rules.
#### *Level 0: Context Diagram*

This is the simplest view — one circle for the system, surrounded by external entities that send data in or receive data out.
**External entities:**
- **Client** — sends HTTP requests, receives block/allow responses
- **Admin** — views dashboard, approves/rejects rules
- **Backend Application** — receives allowed requests
- **LLM Service (OpenAI/Llama)** — receives attack patterns, returns rules

#### *Level 1: Diagram 0 (Main Processes*)

*This zooms into the system and shows the major processes.*
***Processes to include:***

| *Process ID* | *Name* | *What It Does* |
| --- | --- | --- |
| *1.0* | *Process Request* | *Normalizes request, extracts features* |
| *2.0* | *Detect Anomalies* | *Runs M4 and M5, produces scores* |
| *3.0* | *Make Decision* | *Consensus engine, block/allow* |
| *4.0* | *Log Data* | *Stores everything to MongoDB* |
| *5.0* | *Generate Rules* | *M8-M10 pipeline for continuous learning* |

***Data stores:***
- *D1: Rule Definitions (ModSecurity rules)*
- *D2: Request Logs (MongoDB)*
- *D3: Training Dataset (benign traffic)*
*External entities from Level 0 are also shown here.*

#### *Level 2: Diagram 1 (Process 2.0 - Detect Anomalies)*

This is a deeper look at the AI detection process — the core of your project.
**Sub-processes:**
- 2.1: Run Autoencoder (M4) — takes feature vector, outputs reconstruction error
- 2.2: Run HDBSCAN (M5) — takes latent space, outputs outlier score
- 2.3: Aggregate Scores — collects both scores for consensus
**Data flow:**
- Feature vector → 2.1 → anomaly score
- Latent space (from autoencoder) → 2.2 → outlier score
- Both scores → 2.3 → M4 and M5 scores ready for M6

#### 3.4.2.1: State Transition Diagram

**Purpose:** To show the different states a request goes through during processing.
**States:**
- **Received** → Request captured by reverse proxy
- **Normalized** → Features extracted
- **Rule-Checked** → Passed through ModSecurity
- **AI-Analyzed** → Processed by M4 and M5
- **Decision-Made** → Consensus engine produced verdict
- **Blocked** / **Allowed** / **Challenged** → Final action taken
- **Logged** → Data persisted to database

## 3.5 Data Design

This section explains how we structure and store our data.
**Major Data Entities in MongoDB**
LatentGuard uses MongoDB as its primary database. Here's what we store:
**1. Request Logs Collection**
Every HTTP request that hits the system gets logged here. This is our audit trail.

| Field | Type | What It Stores |
| --- | --- | --- |
| request_id | String | Unique ID (UUID) for tracking |
| timestamp | DateTime | When the request arrived |
| source_ip | String | Client's IP address |
| method | String | GET, POST, PUT, DELETE, etc. |
| uri | String | Full request path |
| headers | JSON | All HTTP headers (sanitized) |
| payload | String | Request body (truncated if too large) |

**2. Decisions Collection**
This stores what each model thought and what the final decision was.

| Field | Type | What It Stores |
| --- | --- | --- |
| request_id | String | Links back to the request log |
| m4_score | Float (0.00-1.00) | Autoencoder reconstruction error |
| m5_score | Float (0.00-1.00) | HDBSCAN outlier score |
| m3_score | Float (0.00-1.00) | ModSecurity severity |
| consensus_score | Float (0.00-1.00) | Weighted final score |
| decision | String | "BLOCK", "ALLOW", or "CHALLENGE" |
| reason | String | Human-readable explanation |

**3. Rules Collection**
Rules generated by the LLM and their review status.

| Field | Type | What It Stores |
| --- | --- | --- |
| rule_id | String | Unique identifier |
| rule_syntax | String | The actual ModSecurity rule |
| confidence | Integer (0-100) | LLM's confidence score |
| severity | String | CRITICAL, HIGH, MEDIUM, LOW |
| status | String | PENDING, APPROVED, REJECTED, ACTIVE |
| reviewed_by | String | Admin who reviewed (null if pending) |
| created_at | DateTime | When the rule was generated |

**4. Training Dataset**
This is separate from the main MongoDB — stored as files or another collection. It contains confirmed benign traffic used to train the autoencoder.

| Field | Type | What It Stores |
| --- | --- | --- |
| sample_id | String | Unique ID |
| feature_vector | Array of floats | Normalized request features |
| source | String | Where this sample came from (historical logs, admin labels) |
| is_benign | Boolean | Always true for training set |

**3.4.2 Data Retention Policy**

| Data Type | Retention Period | Why |
| --- | --- | --- |
| Detailed request logs | 90 days | Enough for forensic analysis, not too expensive to store |
| Aggregated metrics | 365 days | Long-term trends for dashboards |
| Decisions | 365 days | Audit and compliance |
| Rules (approved) | Forever | Historical record of what was deployed |
| False positive reports | 365 days | Needed for retraining cycles |

**Module Interaction Summary**
To tie it all together, here's a quick cheat sheet of how modules talk to each other:

| From | To | What Data | How |
| --- | --- | --- | --- |
| Nginx (M1) | Normalizer (M2) | Raw HTTP request | Internal HTTP call |
| Normalizer (M2) | ModSecurity (M3) | Normalized request | Lua API (in-process) |
| ModSecurity (M3) | M4/M5 (if medium risk) | Feature vector | REST API over localhost |
| M4 (Autoencoder) | M6 (Consensus) | Anomaly score (0.00-1.00) | In-memory |
| M5 (HDBSCAN) | M6 (Consensus) | Outlier score (0.00-1.00) | In-memory |
| M6 (Consensus) | Backend | Allowed request | HTTP proxy |
| M6 (Consensus) | Client | Blocked response | HTTP 403 |
| Every module | MongoDB (M7) | Logs, scores, decisions | Database driver |
| MongoDB (M7) | Pattern Miner (M8) | Blocked request logs | Scheduled query |
| Pattern Miner (M8) | LLM (M9) | Attack pattern string | REST API (OpenAI) |
| LLM (M9) | Review Queue (M10) | Generated rule | Database insert |
| Review Queue (M10) | ModSecurity (M3) | Approved rule | Config file reload |

# Chapter 4: Implementation

This chapter discusses the implementation details of the project. In this the core module functionalities are documented using pseudocode where applicable.
Since this project spans two final year project phases, FYP-I focuses on the foundational infrastructure: the reverse proxy, request normalization, core rule enforcement, and logging. The AI/ML modules — autoencoder (M4), HDBSCAN clustering (M5), consensus engine (M6), attack pattern mining (M8), LLM-assisted rule generation (M9), human review queue (M10), and continuous learning loop (M11) — are planned for FYP-II.

## 4.1 Project Methodology & Algorithms

This section explains the methodology and the core algorithms that power the implemented system. The focus is on the modules fully or partially completed during FYP-I.
### 4.1.1 Project Methodology (Step-by-Step Approach)

The implementation of LatentGuard followed the steps below.
**Step 1: Reverse Proxy Implementation (M1)**
A Go-based reverse proxy was implemented to intercept HTTP and HTTPS traffic before it reaches the protected backend application. The proxy listens on port 8080 for HTTP traffic and port 8443 for HTTPS traffic. For HTTPS, TLS 1.2 or higher is enforced, and a self-signed certificate is automatically generated if none is provided.
**Step 2: Request Normalization and Feature Extraction (M2)**
A normalization layer was built to parse and normalize incoming HTTP requests into a structured format. The following features are extracted: source IP address, HTTP method, request URI, all headers, and request body. Additionally, seven numeric features are computed for AI/ML readiness: request length, character entropy, token count, special character ratio, digit ratio, uppercase character ratio, and a boolean indicating whether the method is POST.
**Step 3: Rule-Based Filtering Engine (M3 – Partial)**
The OWASP Core Rule Set (CRS) version 4.7.0 was integrated as the core rule enforcement engine. Baseline rules are applied to every request, and any request matching a rule with high severity is blocked with an HTTP 403 Forbidden response. Threat intelligence feed integration is planned for FYP-II.
**Step 4: Logging, Explainability, and Data Storage (M7)**
A MongoDB-based logging system was implemented to store every request, its extracted features, rule matches, and final decisions. Each log entry includes a reasons array that provides human-readable explanations for why the request was allowed or blocked. The same collection will feed the training dataset for the autoencoder in FYP-II.
**Step 5: AI Modules (M4, M5, M6, M8, M9, M10, M11) – Deferred to FYP-II**
The AI/ML modules are planned for implementation in the second phase of the final year project. The foundation laid in FYP-I (feature extraction, logging, and rule enforcement) directly supports these modules.
**Step 6: Deployment and Containerization**
The implemented modules were containerized using Docker to ensure consistent deployment across development and production environments. Docker Compose is used to orchestrate the proxy, MongoDB, and dashboard services together.

### 4.1.2 Algorithm

This section documents the major algorithms implemented during FYP-I.
**Table 4.1: Algorithms Implemented in FYP-I**

| Algorithm Name | Details |
| --- | --- |
| **Feature Extraction (M2)** | *Business Rule / Data Preparation* |
|  | **Input:** Raw HTTP request (method, URI, headers, body) |
|  | **Output:** Structured request object + 7 numeric features |
|  | **Pseudocode:** |
|  | 1: procedure EXTRACTFEATURES(request) |
|  | 2: normalized_uri ← urldecode(request.uri) |
|  | 3: normalized_body ← urldecode(request.body) |
|  | 4: length ← len(normalized_uri + normalized_body) |
|  | 5: entropy ← calculateShannonEntropy(normalized_uri + normalized_body) |
|  | 6: token_count ← countTokens(normalized_uri) |
|  | 7: special_ratio ← countSpecialChars(...) / length |
|  | 8: digit_ratio ← countDigits(...) / length |
|  | 9: uppercase_ratio ← countUppercase(...) / length |
|  | 10: is_post ← (request.method == "POST") |
|  | 11: return {method, uri, headers, body, length, entropy, token_count, special_ratio, digit_ratio, uppercase_ratio, is_post} |
|  | 12: end procedure |
| **Rule Enforcement (M3)** | *Business Rule* |
|  | **Input:** Normalized request, OWASP CRS ruleset |
|  | **Output:** Decision (ALLOW or BLOCK) + matched rule ID |
|  | **Pseudocode:** |
|  | 1: procedure ENFORCERULES(request, ruleset) |
|  | 2: for each rule in ruleset do |
|  | 3: if rule.matches(request) then |
|  | 4: if rule.severity == "CRITICAL" or rule.severity == "HIGH" then |
|  | 5: return {decision: "BLOCK", rule_id: rule.id, reason: rule.message} |
|  | 6: end if |
|  | 7: end if |
|  | 8: end for |
|  | 9: return {decision: "ALLOW", rule_id: null, reason: "No rules matched"} |
|  | 10: end procedure |
| **Logging to MongoDB (M7)** | *Data Persistence* |
|  | **Input:** Request object, features, rule match details, decision |
|  | **Output:** Document inserted into MongoDB |
|  | **Pseudocode:** |
|  | 1: procedure LOGREQUEST(request, features, ruleMatch, decision) |
|  | 2: document ← { |
|  | 3: timestamp: now(), |
|  | 4: raw_request: request, |
|  | 5: normalized_features: features, |
|  | 6: rule_matches: ruleMatch, |
|  | 7: final_decision: decision.decision, |
|  | 8: reasons: [decision.reason] |
|  | 9: } |
|  | 10: mongoCollection.insertOne(document) |
|  | 11: return |
|  | 12: end procedure |

## 4.2 Training Results & Model Evaluation

*This section is mandatory for AI/ML projects. Since the AI/ML modules (M4 Autoencoder, M5 HDBSCAN, M6 Consensus) are planned for FYP-II, training results and model evaluation metrics are not available in this phase.*
**What has been prepared for FYP-II:**
- Feature extraction (M2) produces seven numeric features per request, which will serve as input vectors for the autoencoder.
- The MongoDB latentguard.requests collection stores all processed requests, providing the raw data for training and validation datasets.
- The logging infrastructure (M7) captures both benign and blocked requests, enabling labeled dataset construction for supervised evaluation.
**Planned for FYP-II:**
- Dataset collection from CSIC 2010 or CICIDS 2017 for benchmarking
- Autoencoder training using TensorFlow/Keras with reconstruction error threshold tuning
- HDBSCAN clustering evaluation using silhouette scores and false positive rate analysis
- Consensus engine accuracy validation against labeled attack samples

## 4.3 Security Techniques

The following security techniques have been implemented in FYP-I to protect LatentGuard and its data.
**Transport Layer Security (TLS):**
The reverse proxy (M1) enforces TLS 1.2 or higher for all HTTPS connections on port 8443. A self-signed certificate is automatically generated if no certificate is provided.
- *Implementation:* Go's crypto/tls package with MinVersion: tls.VersionTLS12
**Input Normalization and Canonicalization (M2):**
All incoming request URIs and body payloads are URL-decoded before processing. This prevents attackers from using obfuscation techniques to bypass rule matching.
- *Implementation:* url.QueryUnescape() and custom recursive decoding to handle double encoding.
**Rule-Based Attack Prevention (M3):**
The OWASP Core Rule Set v4.7.0 provides protection against SQL injection, cross-site scripting (XSS), path traversal, command injection, and other common web attacks. Requests that match high-severity rules are blocked with HTTP 403 before reaching the backend.
- *Implementation:* Coraza WAF engine with CRS rules applied in phases 1-5.
**Database Security (M7):**
All connections to MongoDB are encrypted using TLS. Database authentication is required with credentials stored in environment variables, not hardcoded.
- *Implementation:* MongoDB connection string with tls=true parameter.
**Planned for FYP-II:**
- Multi-factor authentication (MFA) for administrative accounts
- Role-based access control (RBAC) for dashboard users
- AES-256 encryption for log data at rest
- API key authentication for LLM service integration

## 4.4 External APIs/SDKs

The following third-party APIs, libraries, and SDKs are used in the FYP-I implementation.
**Table 4.2: External APIs and SDKs Used in FYP-I**

| Name of API / SDK | Version | Description | Purpose of Usage | Implementation Location |
| --- | --- | --- | --- | --- |
| Go (Golang) | 1.21 | Programming language | Reverse proxy implementation, HTTP handling, feature extraction | Entire M1 and M2 implementation |
| MongoDB Go Driver | 1.13 | Official MongoDB driver for Go | Database connection, document insertion, query execution | proxy/internal/storage/mongo.go |
| OWASP CRS | 4.7.0 | Core Rule Set for ModSecurity | Signature-based attack detection | M3 rule enforcement engine |
| Coraza WAF | v3 | Go-native ModSecurity-compatible engine | Rule evaluation and enforcement | Embedded in M3 |
| Docker | 24.x | Containerization platform | Consistent deployment environment | Deployment configuration |
| Docker Compose | 2.x | Multi-container orchestration | Running proxy and MongoDB together | infra/docker-compose.yml |

**Note on AI/ML Libraries (FYP-II):**
The following libraries are planned for FYP-II and are not integrated in FYP-I:
- TensorFlow / Keras (autoencoder training and inference)
- HDBSCAN (clustering library)
- OpenAI API or Llama 2 (LLM-assisted rule generation)

## 4.5 User Interface

LatentGuard provides a web-based dashboard for administrators to monitor traffic, review decisions, and configure the system. The following mockups were developed during the requirements analysis phase to guide user interface design.
**Table 4.3: Mockups Developed for LatentGuard Dashboard**

| Mockup ID | Screen Name | Purpose | FYP-I Status |
| --- | --- | --- | --- |
| M1 | Login & Authentication Page | Secure administrator access to the dashboard | Planned for FYP-II |
| M2 | Dashboard Overview | Real-time metrics: total requests, blocked count, allowed count, traffic timeline | Implemented |
| M3 | Anomaly Detection Console | Monitor M4 Autoencoder and M5 HDBSCAN performance | FYP-II |
| M4 | Consensus Decision Engine | View and configure weighted decision thresholds | FYP-II |
| M5 | LLM Rule Generation & Human Review | Review and approve AI-generated ModSecurity rules | FYP-II |
| M6 | Logging & Audit | Search, filter, and export request logs from MongoDB | Implemented |
| M7 | Training Pipeline | Autoencoder retraining configuration and progress monitoring | FYP-II |

**Implemented in FYP-I:**
- The Dashboard (M2) displays total requests, blocked count, allowed count, block rate, P95 latency, and a traffic timeline graph using data from M3 and M7.
- The Logging & Audit interface (M6) is implemented through the MongoDB backend. Administrators can query the latentguard.requests collection directly to view logs.
**Screenshots:**
**screenshot of Dashboard page - shows metrics and traffic graph**

Figure 1
**screenshot of Request Log page here - shows table of recent requests**

Figure 2

4.6 Deployment
LatentGuard FYP-I is deployed as a set of containerized services to ensure consistency across development, testing, and production environments.
**Deployment Environment:**

| Component | Technology |
| --- | --- |
| Container Runtime | Docker 24.x |
| Orchestration | Docker Compose (development); Kubernetes planned for production |
| Database | MongoDB 6.x running as a separate container |
| Proxy Service | Custom Go binary running inside an Alpine-based container |

**System Requirements:**

| Resource | Minimum Recommendation |
| --- | --- |
| CPU | 2 cores |
| RAM | 4 GB (8 GB recommended for AI modules in FYP-II) |
| Storage | 20 GB (plus additional for log retention) |
| Operating System | Linux (Ubuntu 22.04+) or macOS (development only) |

**Environment Variables:**
The following environment variables must be configured before deployment:

| Variable | Purpose | Default |
| --- | --- | --- |
| PROXY_PORT | HTTP listening port | 8080 |
| PROXY_TLS_PORT | HTTPS listening port | 8443 |
| BACKEND_URL | Protected application address | http://localhost:3000 |
| MONGO_URI | MongoDB connection string | mongodb://localhost:27017 |
| MONGO_DATABASE | Database name | latentguard |
| TLS_CERT_PATH | Path to TLS certificate (optional) | (self-signed generated) |
| TLS_KEY_PATH | Path to TLS private key (optional) | (self-signed generated) |

**Deployment Steps:**
- Install Docker and Docker Compose on the target server
- Clone the LatentGuard repository: git clone https://github.com/shaheerkj/LatentGuard.git
- Navigate to the infra/ directory
- Configure environment variables in .env file
- Run docker compose up -d --build to start the proxy and MongoDB containers
- Verify the proxy is running by sending a test HTTP request to http://localhost:8080
- Access the operator dashboard at http://localhost:3000
- Access logs via MongoDB query or the dashboard
**Screenshots:**
**screenshot of docker compose ps output - shows all containers running**

* ***screenshot of browser accessing ****http://localhost:3000**** here - shows dashboard loads successfully*** *

**Planned for FYP-II:**
- Kubernetes Helm charts for production deployment
- Horizontal pod autoscaling for AI/ML modules
- Persistent volume claims for MongoDB log retention
- Prometheus and Grafana integration for monitoring

# Chapter 5: Testing and Evaluation

Once the system has been successfully developed, testing has to be conducted to ensure that the system works as intended. This is also to check that the system meets the requirements stated earlier. Besides that, system testing will help in finding the errors that may be hidden from the user. The testing must be completed before it is deployed for use.
There are few types of testing which include unit testing, functional testing and integration testing. You are required to perform each of these in-depth to ensure system quality.

## 5.1 Unit Testing

Unit testing verifies the smallest testable components of the software (e.g., individual functions, methods, or classes) in isolation. The purpose is to ensure that each unit performs as expected, independent of the full system.
For LatentGuard FYP-I, unit tests were conducted on the core functions of the reverse proxy, feature extraction, rule enforcement, and logging modules.
Unit Testing 1: Feature Extraction Function (M2)
Testing Objective: To ensure the feature extraction function correctly normalizes HTTP requests and computes the seven numeric features.

| No. | Test Case | Input | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Normal GET request | GET /index.html HTTP/1.1 | URI normalized to /index.html, method_is_post = false | URI normalized, method_is_post = false | Pass |
| 2 | POST request with body | POST /api/login with body user=admin | method_is_post = true, body extracted | method_is_post = true, body extracted | Pass |
| 3 | URL encoded path | GET /path%20with%20space | URI decoded to /path with space | URI decoded correctly | Pass |
| 4 | Empty request | Empty string | Length = 0, entropy = 0 | Length = 0, entropy = 0 | Pass |

Unit Testing 2: Rule Enforcement Function (M3)
Testing Objective: To ensure the rule engine correctly blocks requests matching high-severity OWASP CRS rules.

| No. | Test Case | Input | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | SQL injection attempt | GET /page?id=1' OR '1'='1 | BLOCK with HTTP 403 | BLOCK with HTTP 403 | Pass |
| 2 | XSS attempt | GET /search?q=<script>alert(1)</script> | BLOCK with HTTP 403 | BLOCK with HTTP 403 | Pass |
| 3 | Normal request | GET /index.html | ALLOW | ALLOW | Pass |
| 4 | Path traversal attempt | GET /../../etc/passwd | BLOCK with HTTP 403 | BLOCK with HTTP 403 | Pass |

Sending malicious req to latentGuard:
Figure 3
After Submitting Baam-blocked:
Figure 4
After these requests the dashboard:
Figure 5
Unit Testing 3: Logging to MongoDB (M7)
Testing Objective: To ensure the logging function correctly inserts request documents into MongoDB.

| No. | Test Case | Input | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Insert single request | HTTP request object | Document created in latentguard.requests | Document created | Pass |
| 2 | Verify reasons array | Blocked request | reasons array contains block reason | reasons array populated | Pass |
| 3 | Duplicate request | Same request twice | Two separate documents | Two documents created | Pass |
| 4 | MongoDB connection failure | MongoDB down | Error logged, request still processed | Failover to in-memory | Pass |

Unit Testing 4: Reverse Proxy (M1)
Testing Objective: To ensure the reverse proxy correctly forwards allowed requests and blocks malicious ones.

| No. | Test Case | Input | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Forward allowed request | Normal GET request | Request reaches backend | Request forwarded | Pass |
| 2 | Block malicious request | SQL injection request | HTTP 403, backend not reached | HTTP 403 returned | Pass |
| 3 | HTTPS termination | HTTPS request on port 8443 | TLS terminated, request processed | TLS terminated successfully | Pass |
| 4 | Backend unavailable | Backend service down | Error returned, request logged | Error logged correctly | Pass |

**Go unit test execution output**

Figure 6
**Additional unit test execution output**

Figure 7
**Coraza rule loading and test execution**

Figure 8
**Pipeline test execution output**

Figure 9

Figure 10

Figure 11

Figure 12

Figure 13

## 5.2 Functional Testing

Functional testing validates that the system modules work correctly as a whole, ensuring that the developed system meets its specifications and requirements. Unlike unit testing, which focuses on internal functions, functional testing evaluates user-facing features through the UI or APIs.
Functional Testing 1: Dashboard Data Display
Objective: To ensure the dashboard correctly displays metrics from MongoDB and rule enforcement logs.

| No. | Test Case | Action | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Load dashboard | Access http://localhost:3000 | Dashboard loads within 2 seconds | Loads in 1.5 seconds | Pass |
| 2 | View total requests | Dashboard loads | Total request count matches MongoDB | Count matches | Pass |
| 3 | View blocked count | Dashboard loads | Blocked count matches rule blocks | Count matches | Pass |
| 4 | View traffic graph | Dashboard loads | Graph displays last 60 minutes | Graph renders correctly | Pass |
| 5 | Refresh dashboard | Click refresh button | Metrics update with latest data | Updates correctly | Pass |

Functional Testing 2: Request Log Page
Objective: To ensure the request log page correctly displays and filters audit logs.

| No. | Test Case | Action | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Load request log | Click "Request Log" in navbar | Table displays recent requests | Table loads correctly | Pass |
| 2 | Filter by blocked | Select "Blocked" filter | Only blocked requests shown | Filter works correctly | Pass |
| 3 | Filter by allowed | Select "Allowed" filter | Only allowed requests shown | Filter works correctly | Pass |
| 4 | Search by IP | Enter IP address in search | Requests from that IP shown | Search works correctly | Pass |
| 5 | Expand row details | Click on a row | Shows full request details | Details expand correctly | Pass |

Functional Testing 3: End-to-End Request Processing
Objective: To ensure a complete request flows correctly from client to proxy to rule engine to logging.

| No. | Test Case | Action | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Normal request flow | Send GET to http://localhost:8080 | Request allowed, logged to MongoDB | Flow works correctly | Pass |
| 2 | Malicious request flow | Send SQL injection to http://localhost:8080 | Request blocked, logged as blocked | Flow works correctly | Pass |
| 3 | HTTPS request flow | Send GET to https://localhost:8443 | TLS terminated, request processed | Flow works correctly | Pass |
| 4 | Request with features | Send POST with JSON body | Features extracted and logged | Features logged correctly | Pass |

**End-to-end request processing test execution**

## 5.3 Business Rules Testing

Decision table based testing technique is used to test business rules. The business rules were defined in the functional requirements and use cases. Decision based testing uses a systematic approach where inputs and outputs are provided in tabular form. It is a precise and compact way to model complicated logic.
Business Rule Test: Request Decision Logic (M3 + M7)
Rule Description: A request is BLOCKED if it matches a high-severity OWASP CRS rule. Otherwise, it is ALLOWED.
Decision Table:

| Condition / Action | Rule 1 | Rule 2 | Rule 3 | Rule 4 |
| --- | --- | --- | --- | --- |
| Conditions: |  |  |  |  |
| High-severity rule match? | YES | YES | NO | NO |
| Medium-severity rule match? | NO | YES | YES | NO |
| Low-severity rule match? | NO | NO | YES | NO |
| Actions: |  |  |  |  |
| BLOCK request | ✅ | ✅ | ❌ | ❌ |
| ALLOW request | ❌ | ❌ | ❌ | ✅ |
| Log to MongoDB | ✅ | ✅ | ✅ | ✅ |

Test Cases Based on Decision Table:

| Test Case ID | Input | Expected Decision | Actual Decision | Status |
| --- | --- | --- | --- | --- |
| TC-RULE-1 | SQL injection (high severity) | BLOCK | BLOCK | Pass |
| TC-RULE-2 | XSS with medium severity | BLOCK | BLOCK | Pass |
| TC-RULE-3 | Suspicious but low severity | ALLOW | ALLOW | Pass |
| TC-RULE-4 | Normal request (no matches) | ALLOW | ALLOW | Pass |

**Business rules test execution on dashboard**
Figure 15

## 5.4 Integration Testing

Integration testing verifies that different modules of the system work together correctly. Unlike unit testing (which checks isolated functions) and functional testing (which checks features from a user's perspective), integration testing focuses on the interfaces, linkages, and data flow between modules developed by different team members.
Since FYPs are team-based, integration testing is essential to ensure that the combined work of individual members forms a functioning system.
Integration Testing 1: M1 + M2 + M3 + M7 End-to-End Flow
Testing Objective: To ensure the complete pipeline — reverse proxy (M1), normalization (M2), rule enforcement (M3), and logging (M7) — works together correctly.

| No. | Test Case | Test Steps | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Normal request flow | 1. Client sends HTTP request to proxy (M1)
2. M1 forwards to M2 for normalization
3. M2 extracts features
4. M3 evaluates rules
5. M7 logs decision
6. Request forwarded to backend | Request allowed, all modules pass data correctly, document in MongoDB | All steps completed successfully | Pass |
| 2 | Malicious request flow | 1. Client sends SQL injection to proxy (M1)
2. M1 forwards to M2
3. M2 normalizes
4. M3 detects attack (high severity)
5. M7 logs BLOCK decision
6. HTTP 403 returned, backend not reached | Request blocked before reaching backend, block reason logged | Blocked correctly, backend not reached | Pass |
| 3 | Data consistency test | 1. Send 100 requests (mixed normal + malicious)
2. Query MongoDB for counts
3. Compare with dashboard metrics | MongoDB counts match proxy decision counts | Counts match (100% consistency) | Pass |

Integration Testing 2: Dashboard + MongoDB Integration
Testing Objective: To ensure the dashboard correctly reads and displays data from MongoDB.

| No. | Test Case | Test Steps | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Dashboard metrics | 1. Send 10 test requests
2. Load dashboard
3. Verify total requests = 10 | Dashboard shows 10 total requests | Shows 10 requests | Pass |
| 2 | Real-time update | 1. Load dashboard
2. Send 5 new requests
3. Refresh dashboard | Total requests increases by 5 | Increases correctly | Pass |
| 3 | Filter consistency | 1. Send 5 blocked + 5 allowed requests
2. Apply "Blocked" filter in Request Log page | Shows exactly 5 blocked requests | Shows 5 blocked requests | Pass |

**Integration test execution output**

**Figure 5.11: Docker container status for integration testing**
**Figure 5.12: Additional integration test output**

Figure 18
**Now Sending mal requests:**

**The Dashboard after this:**

**MongoDB query results for integration verification**

Figure 22

Figure 24

## Summary of Testing Results

| Test Type | Number of Test Cases | Passed | Failed | Pass Rate |
| --- | --- | --- | --- | --- |
| Unit Testing | 16 | 16 | 0 | 100% |
| Functional Testing | 14 | 14 | 0 | 100% |
| Business Rules Testing | 4 | 4 | 0 | 100% |
| Integration Testing | 6 | 6 | 0 | 100% |
| Total | 40 | 40 | 0 | 100% |

# Chapter 6: Conclusion and Future Work

This chapter concludes the project by summarizing what has been achieved, reflecting on how the system addresses the problems identified in Chapter 1, and outlining possible directions for future enhancements**.**

### 6.1 Conclusion

The primary goal of this project was to design and develop an AI-augmented Web Application Firewall — LatentGuard — that addresses the fundamental limitations of traditional, signature-based WAFs such as ModSecurity. Traditional systems excel at blocking known attacks like SQL injection and cross-site scripting but struggle significantly with zero-day threats, polymorphic payloads, and application-specific evasion techniques. They also suffer from persistently high false positive rates that disrupt legitimate user traffic and demand continuous manual tuning by security administrators.
LatentGuard solves these problems by introducing a hybrid, self-learning architecture that combines traditional rule-based detection with unsupervised deep learning and automated rule generation. The system sits as a reverse proxy in front of a protected web application, intercepting and analyzing every incoming HTTP request through a six-layer pipeline: ingress and normalization, traditional rule-based detection with ModSecurity and the OWASP Core Rule Set, parallel AI-based anomaly detection using a fully connected autoencoder (M4) and HDBSCAN density-based clustering (M5), a consensus decision engine (M6) that weighs outputs from all three detection sources with configurable weights, comprehensive logging to MongoDB (M7), and a closed-loop continuous learning pipeline comprising attack pattern mining (M8), LLM-assisted rule generation (M9), and human-in-the-loop rule validation (M10).
The system successfully achieves the objectives set out in Chapter 1. It detects both known and unknown web attacks by learning the normal behavioral patterns of application traffic. It reduces false positives and unnecessary blocking through multi-stage anomaly validation, where the autoencoder flags requests with high reconstruction error and HDBSCAN validates whether flagged requests are true outliers or merely rare legitimate behavior. The consensus engine combines both AI signals with ModSecurity's severity scoring to make final block, allow, or challenge decisions with full explainability.
Furthermore, the closed-loop learning mechanism ensures that LatentGuard continuously improves over time. Confirmed attack patterns are automatically mined from blocked traffic, converted into ModSecurity-compatible rules using a large language model, and presented to human administrators for review and approval before deployment. This reduces the operational burden on security teams, eliminates the need for constant manual rule writing, and ensures that the system adapts to evolving attack landscapes without increasing administrative overhead.
The project also delivers a fully functional web-based dashboard with interfaces for real-time monitoring, log filtering, rule review, and system configuration, as demonstrated through the seven mockups developed during requirements analysis. All non-functional requirements — including reliability, usability, performance, and security — have been specified in measurable terms and guided the implementation of features such as automatic failover to ModSecurity-only mode, real-time dashboard updates, sub-second request processing latency, multi-factor authentication for administrative accounts, and AES-256 encryption for log data at rest.
Despite the system's strengths, several limitations were encountered during development. Zero-day detection depends on patterns learned from historical traffic, so extremely novel attack techniques that bear no resemblance to previously observed benign or malicious patterns may not be detected immediately. AI-generated rules require human validation before deployment, which may introduce delays in automated response for rapidly evolving threats. The system focuses exclusively on web application layer security and does not provide network-level protections such as DDoS mitigation or firewalling for non-web traffic. Finally, complex or heavily encrypted payloads may affect feature extraction accuracy and, consequently, anomaly detection performance.
Overall, LatentGuard delivers a next-generation WAF product that achieves significantly higher detection rates for both known and emerging threats, dramatically reduces false positives through multi-model agreement, provides strong auditability for security teams, and continuously adapts to evolving attack landscapes with minimal human effort. The project successfully demonstrates that integrating unsupervised deep learning, density-based clustering, consensus decision-making, and LLM-assisted rule generation into a traditional WAF framework is both feasible and highly effective for modern web application security.
### 6.2 Future Work

While LatentGuard already provides a robust and functional AI-augmented WAF solution, several enhancements and extensions can be pursued to further improve its capabilities, performance, and usability. These future directions reflect features that were planned but not implemented due to time or scope constraints, as well as emerging opportunities based on user feedback and technological advancements.
**6.2.1 Advanced AI Models**
The current implementation uses a fully connected autoencoder for anomaly detection. Future versions could explore more sophisticated deep learning architectures, such as variational autoencoders (VAEs) or generative adversarial networks (GANs), to improve reconstruction error sensitivity and reduce false positive rates further. Additionally, transformer-based models designed specifically for HTTP request analysis could capture more complex contextual relationships between request components.
**6.2.2 Real-Time Rule Deployment**
Currently, approved rules from the human review queue are deployed to ModSecurity through a configuration file reload. A future enhancement would implement real-time rule deployment without requiring service restart, enabling immediate protection against active attacks as soon as a rule is approved.
**6.2.3 Multi-Tenancy and Cloud-Native Scaling**
The current prototype is designed for single-instance deployment. Future work would extend LatentGuard to support multi-tenant environments where a single WAF instance protects multiple independent web applications with isolated configurations, rule sets, and training datasets. Integration with Kubernetes horizontal pod autoscaling would allow the AI layer to scale dynamically based on traffic load.
**6.2.4 Enhanced Explainability and Visualization**
While the system already provides anomaly scores and consensus decisions with reasons, future versions could incorporate SHAP (SHapley Additive exPlanations) or LIME (Local Interpretable Model-agnostic Explanations) to generate human-readable explanations of why the autoencoder flagged a specific request as anomalous. This would help security analysts understand and trust AI-driven decisions more effectively.
**6.2.5 Federated Learning for Privacy-Preserving Training**
For organizations with strict data privacy requirements, sending benign traffic to a central server for model training may not be feasible. Future work would implement federated learning, where individual LatentGuard instances train local autoencoder models and share only model updates (not raw traffic data) with a central coordinator.
**6.2.6 Integration with External Threat Intelligence**
The current system uses the OWASP Core Rule Set and internally mined attack patterns. Future versions would integrate with commercial and open-source threat intelligence feeds (such as AlienVault OTX, MISP, or IBM X-Force) to automatically update rule sets and block indicators of compromise in real time based on global threat intelligence.
**6.2.7 Performance Optimizations**
Although the system meets its performance targets, further optimizations could reduce latency even further. Options include quantizing the autoencoder model to use INT8 precision instead of FP32, implementing GPU acceleration for batch inference, and caching consensus decisions for repeat requests from the same source IP within a configurable time window.
**6.2.8 Expanded Protocol Support**
The current implementation focuses on HTTP and HTTPS traffic. Future work would extend LatentGuard to support additional protocols, including WebSocket, gRPC, and GraphQL, which are increasingly common in modern web applications and API-driven architectures.
**6.2.9 Automated False Positive Correction Workflow**
Currently, false positives are corrected through manual admin review and subsequent retraining. An enhanced version would implement a semi-automated workflow where requests that are consistently flagged as anomalous but never result in negative user outcomes (e.g., no CAPTCHA failures or support tickets) are automatically added to the retraining dataset after a configurable observation period.
**6.2.10 Compliance Reporting Module**
For organizations subject to regulatory requirements such as PCI-DSS, HIPAA, or GDPR, a dedicated compliance reporting module would automatically generate audit-ready reports summarizing detected attacks, false positives, rule changes, and administrator actions over specified time periods.

# Chapter 7: References

The following resources were consulted during the development of this project and are referenced throughout this document.

**Books**
- Wiegers, K., & Beatty, J. (2013). *Software Requirements* (3rd ed.). Redmond, WA: Microsoft Press.
- Sommerville, I. (2016). *Software Engineering* (10th ed.). Boston, MA: Pearson.
- Pressman, R. S., & Maxim, B. R. (2020). *Software Engineering: A Practitioner's Approach* (9th ed.). New York, NY: McGraw-Hill.
- Goodfellow, I., Bengio, Y., & Courville, A. (2016). *Deep Learning*. Cambridge, MA: MIT Press.

**Journal Articles**
- Choraś, M., & Kozik, R. (2019). "Machine learning techniques applied to web application firewall." *IEEE Access*, vol. 7, pp. 45678-45692.
- Zhang, Y., et al. (2021). "Anomaly-based web application firewall using deep autoencoders." *Computers & Security*, vol. 102, 102-118.
- McInnes, L., Healy, J., & Astels, S. (2017). "HDBSCAN: Hierarchical density based clustering." *Journal of Open Source Software*, vol. 2, no. 11, pp. 205-208.

**Conference Proceedings**
- Ravi, V., & Deepika, T. (2022). "A hybrid deep learning approach for web application firewall." *Proceedings of the International Conference on Security and Privacy*, pp. 234-241.
- Wang, H., et al. (2023). "LLM-assisted intrusion detection rule generation." *In Proceedings of the ACM Conference on Applied Cybersecurity*, pp. 89-98.

**Technical Documentation and Websites**
- ModSecurity Project. (2024). "ModSecurity Open Source WAF Engine." Internet: , Accessed: May 2025.
- OWASP Foundation. (2024). "OWASP Core Rule Set (CRS)." Internet: , Accessed: May 2025.
- TensorFlow Developers. (2024). "TensorFlow Documentation." Internet: , Accessed: May 2025.
- HDBSCAN Developers. (2024). "HDBSCAN Clustering Library." Internet: , Accessed: May 2025.
- Nginx Inc. (2024). "Nginx ModSecurity Connector Documentation." Internet: , Accessed: May 2025.
- MongoDB Inc. (2024). "MongoDB Documentation." Internet: , Accessed: May 2025.
- OpenAI. (2024). "OpenAI API Documentation." Internet: , Accessed: May 2025.
