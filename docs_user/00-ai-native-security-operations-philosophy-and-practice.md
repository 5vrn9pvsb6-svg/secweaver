**Languages:** English (this page) | [简体中文](00-ai-native-security-operations-philosophy-and-practice.zh-CN.md)

# AI-Native Security Operations: Philosophy & Practice

**Editor's Note**

In the era of traditional security operations, many teams cared most about whether they had alerts, logs, and platforms. In the era of AI-driven attacks, the real questions are becoming: Has the alert been confirmed? Has the evidence been stitched together? Has the attack chain been reconstructed? Have missing data sources been discovered?

Over the years we built large numbers of security devices, SOC, SIEM, situational awareness platforms, log platforms, EDR, WAF, NDR, HIDS, bastion hosts, and database audit systems. Yet when a real incident occurs, analysts still hop between systems: check a WAF alert, then hunt for web access logs; see a source IP, then query DNS, authentication, host processes, file changes, and network connections—only to find mismatched fields, missing logs, unclear assets, and hostnames that do not map to IPs.

There is another common pitfall: assuming that piping security product alerts into a SOC or SIEM completes AI-native data preparation. In reality, alerts from WAF, IDS, NDR, and EDR usually tell you only that *something might be wrong*—they rarely answer on their own whether the attack succeeded, landed on a host, what was executed, or whether lateral movement and outbound C2 occurred. Those conclusions depend heavily on host behavior and network behavior data: process execution, command audit, file changes, authentication logins, listening ports, DNS resolution, connection five-tuples, traffic sessions, internal access paths, and more. AI-native security operations cannot collect only security-device alerts; host and network behavioral data must be registered and correlated in the same evidence system.

The core tension in security operations is no longer simply "do we have data," but:

```text
Can data be understood by AI? Can evidence be correlated automatically? Can investigations be reviewed?
```

An AI-native security operations system (security analysis and traceability investigation system) is not about building another chatty security Q&A bot. It is about enabling large models to perform explainable, traceable, and verifiable security analysis in real operational environments—grounded in data assets, evidence chains, investigation scenarios, and correlation rules.

First, a mindset shift is required. AI-native does not mean dumping logs, tables, screenshots, and tribal knowledge that humans can read but machines struggle with into a model and hoping it gets smarter. AI-native means humans proactively prepare data for AI: semantics, location, fields, permissions, query methods, correlation relationships, and applicable scenarios—so AI can clearly understand data and reliably obtain it.

AI-native also does not mean replacing the security team with AI. It means humans and AI working together: humans do what humans do best; AI does what AI does best. Humans excel at business context, boundary judgment, recognizing exceptions in anomalies, final accountability, and turning frontline experience into rules and methods. AI excels at large-scale search across alerts and logs, cross-source correlation, repetitive triage, evidence assembly, and report generation. They are not competitors—they are collaborators.

In the past, humans adapted to systems: analysts knew which platform to open, which menu to click, which field to query, which colleague to ask. In the future, systems adapt to AI: data sources declare what they are, where they live, how to query them, what they can prove, and what they cannot.

```text
The starting point of AI-native security operations: turn data into work objects that AI can understand, invoke, and correlate—then talk about intelligent analysis.
```

Security capability depends on the quality of data preparation and how smoothly human–machine collaboration runs. Ideally, daily security operations is not just "clear today's alerts," but continuous accumulation of security experience and capability.

---

**Summary:** Prepare security data as assets that agents can query and correlate, then ground investigations in scenarios and evidence. People retain authorization, review, and response decisions. This is a philosophy essay; start with the [quickstart](00-security-operator-quickstart.md) for hands-on use.

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [0x2 Solution: From Alert Center to Security Data Registry](#0x2-solution-from-alert-center-to-security-data-registry)
- [0x3 Practice 1: Alert Confirmation Is Not a True/False Question—It Is an Evidence Question](#0x3-practice-1-alert-confirmation-is-not-a-truefalse-questionit-is-an-evidence-question)
- [0x4 Practice 2: Traceability Investigation Is Reconstructing the Attack Chain](#0x4-practice-2-traceability-investigation-is-reconstructing-the-attack-chain)
- [0x7 Practice 5: AI and Humans Collaborate—AI Does Not Replace Humans](#0x7-practice-5-ai-and-humans-collaborateai-does-not-replace-humans)

## (I) Introduction

Over the past few years, changes in AI attack capability are no longer theoretical. Frontier models can assist with vulnerability discovery, script writing, automated reconnaissance, exploitation, persistence, and lateral movement planning. Work that once required multiple expert roles can now be decomposed into automatically orchestrated, repeatedly executable task units.

The underlying shift is not "attackers got another tool," but:

```text
Attack activity is moving from human-driven operations to continuous production driven jointly by models and toolchains.
```

In the past, a high-quality attack depended on experience, patience, tooling, and heavy manual judgment. Today, agents can tirelessly enumerate exposure, try weak passwords, analyze responses, generate payloads, summarize failures, and adjust the next step.

When attacks accelerate, defenders face three direct pressures:

1. More alerts.
2. Longer attack chains.
3. Shorter investigation windows.

In traditional mode, tier-1 analysts triage, tier-2 investigate deeply, tier-3 experts trace and review. But as long as key investigation steps still require manually moving information across systems, stitching clues, capturing screenshots, and writing conclusions, the platform cannot form a continuously running investigation loop.

Many teams already have vast log volumes yet still cannot answer critical questions during incidents:

- Which asset was attacked first?
- Was the entry point the URL in the WAF alert, or another unreported interface?
- Did the attack actually succeed?
- Did it reach the host after the web layer?
- Were commands executed, files written, reverse shells established, or privileges escalated on the host?
- Was there lateral movement to databases or other internal machines?
- Which evidence supports each conclusion?
- Which data sources are missing, forcing only medium or low confidence?

These questions cannot be answered by a single alert—or by a model relying on common sense.

This is also the trap many teams fall into when doing AI security analysis: treating AI as a smarter person without supplying the context human analysts rely on. Analysts know an IP is a scanner, that a field is really a NAT'd source address, that a system's logs are offset by eight hours, that a machine named web-01 actually serves as a jump host. AI does not know—unless that information is structured, declared, and authorized for access.

So AI-native security analysis is first a data-preparation problem, not a model problem.

```text
Humans must shift from "querying data themselves" to "preparing data that AI can understand, obtain, and correlate."
```

True security analysis and traceability investigation is essentially cross-source, cross-entity, cross-time-window evidence reconstruction.

---

## 0x1 Investigation Challenges Under Offense–Defense Change

### 1.1 Attacker Side: Find an Entry, Expand Along the Path

For attackers, any exploitable exposure in the environment can become the starting point of a longer chain.

A web service exposed to the internet, an unpatched historical vulnerability, a default password, a phished account, a misopened management port—once one point succeeds, the attacker moves into execution, privilege escalation, lateral movement, persistence, outbound communication, and data access.

In the AI attack era, this chain moves faster.

Attackers once needed manual judgment for the next step; now agents choose actions based on responses, logs, pages, error messages, and permission state. More attack steps mean more signals for defenders—*if* those signals are collected, parsed, and correlated.

If WAF sees only HTTP requests, host logs only process execution, auth logs only successful logins, and network logs only connection five-tuples—with no layer to stitch them together—each system sees only fragments.

Fragments are not an evidence chain.

### 1.2 Defender Side: Rich Environmental Facts, But Not on AI's Workbench

Defenders actually hold the most critical environmental facts.

Enterprises have their own assets, accounts, business systems, network topology, historical logs, access habits, operational processes, allowlists, scanners, bastion hosts, and automation platforms—context attackers lack when they enter the environment.

The problem is that this context is scattered:

- Assets in CMDB.
- Alerts in SOC.
- Raw logs in SLS / ES / Splunk.
- Host information in cloud consoles or spreadsheets.
- Network zones in topology diagrams.
- Allowlists in team experience.
- On-call knowledge in chat and ticket notes.
- Field meanings in someone's head.

A common pattern emerges: the enterprise has home-field advantage, yet AI and frontline analysts still investigate like outsiders, starting from scratch.

Home-field advantage becomes real defensive capability only when structured into data assets that AI can query, correlate, and review. The most critical category is not "another alert from a security product," but behavioral facts continuously produced on hosts and networks.

### 1.3 Bottlenecks in Traditional Security Analysis

Traditional analysis often stalls in three places.

**First: unclear data source semantics.**

Is a log source a WAF alert, web access log, host execution log, SSH login log, DNS log, or system syslog? Do fields like `src_ip`, `client_ip`, `remote_addr`, `host`, `hostname`, and `__source__` mean the same thing? Without clear semantics, AI struggles even with logs in hand.

**Second: unclear data retrieval paths.**

Analysts know which logs to query; AI does not know which system holds the data, which connector to use, which query template, which time field, which fields are indexed, or what time window is appropriate. Without retrieval paths, agents stay at "you should go check that."

**Third: unclear evidence correlation.**

Can a WAF alert source IP join to web access logs? Can web request time join to host process execution windows? Can outbound targets on a host join to DNS, threat intel, and network connection logs? Without explicit join keys, time windows, and correlation paths, AI reasoning devolves into guessing.

So the first step of AI-native security analysis is not writing a longer prompt—it is turning security data into data assets AI can use.

---

## 0x2 Solution: From Alert Center to Security Data Registry

Many security platforms were alert centers:

```text
Devices generate alerts → SOC aggregates → manual triage → manual investigation → ticket closed
```

AI-native security analysis should first build a **security data registry**:

```text
Security product alerts + host behavior data + network behavior data + identity / access logs
        ↓
Data assetization
        ↓
Scenario-driven investigation
        ↓
Evidence correlation
        ↓
AI analysis and review
        ↓
Traceability report / data gaps / defensive assets
```

"Data" here must not be narrowed to alerts. Security product alerts are investigation entry points; host and network behavior data are the primary evidence for reconstructing attack chains. The former answers "where something might be wrong"; the latter answers "what the attacker actually did and what was impacted."

Host behavior data typically includes: process execution, command audit, file read/write, scheduled tasks, login sessions, listening ports, privilege escalation, script drops, and more. Network behavior data typically includes: DNS queries, TCP/UDP connections, internal access, outbound targets, traffic sessions, proxy forwarding, north–south and east–west access paths, and more. For alert confirmation and traceability, both categories must live in the same registration, retrieval, and correlation system as WAF, EDR, NDR, and other security product alerts—not in silos.

This shift looks like platform architecture change; in substance it is a change in security operations thinking.

Data security has long had data governance: catalogs, classification, lineage, quality, permissions—familiar concepts. In traditional offense–defense and security operations, we rarely treated logs, alerts, hosts, accounts, networks, and processes as governed data assets. "Devices produce logs, platforms can search logs, analysts know where to look" was considered enough.

That path fails in the AI era. AI does not natively know which log source is trustworthy, which field represents the true source IP, which hostname maps to which asset, which data source proves attack success, or which query failure means missing evidence. Traditional offense–defense must now add a lesson in security data governance.

But governance here does not mean dragging security teams into a long, heavy, spreadsheet-driven data governance program. AI-native security analysis needs **lightweight governance oriented to investigation tasks**: register first the data sources, field semantics, retrieval channels, correlation relationships, and gap expressions that AI investigations need most—so data becomes usable—then incrementally improve quality, permissions, versioning, and audit through use.

Past data building was mainly for humans: pages to search, fields to view, reports to export—analysts stitched them together from experience. AI-native data building must be for AI: each data source needs clear semantics, each field an explanation, each retrieval path invocable, each evidence type knowing what it can prove, each investigation scenario knowing what to query first, next, and what is missing.

This aligns with Palantir's long-emphasized approach to data building. Palantir's core value is not just an analysis UI—it connects data from scattered systems, organizes it into understandable, actionable, reusable business objects and relationship networks, and lets people decide and act on that foundation. In the AI era this matters more: for models to participate in real work, they should not face raw tables and logs directly, but a semantic layer that is modeled, authorized, governed, and mapped to real business objects.

Palantir's Ontology repeatedly emphasized elevating enterprise data from "tables and fields" to "objects, relationships, permissions, and actions." Data is not merely records in storage—it maps to orders, devices, people, locations, processes, and decisions in the real world; who can view, who can change, what actions can be triggered—all must be explicitly modeled. Then AI is not doing text Q&A on a database, but working in a semantic world close to real business structure.

In security, SecWeaver does something similar but more focused: not building a generic enterprise data platform, but registering alerts, logs, hosts, accounts, networks, processes, files, and connections as security data assets that AI can understand and invoke—for analysis and traceability investigation.

```text
Not AI adapting to chaotic data—but humans organizing data into a form AI can work with.
```

This is SecWeaver's basic approach.

SecWeaver does not ask a large model to judge alert risk in a vacuum. Through DataAsset, Correlation Matrix, Scenario Pattern, and Skills, it organizes scattered security logs, alerts, host behavior, network connections, and identity data into evidence chains that models can query, correlate, analyze, and review.

### 2.1 AI-Native Data Preparation: Pave the Way for AI First

Many people understand AI-native as "adding AI to existing systems." That is not enough.

True AI-native means assuming from the start that future investigation actions will be executed not only by humans, but by human-supervised AI agents. Data cannot be prepared only for human page browsing—it must be prepared for how agents execute tasks.

For humans, a field named `src`, `sip`, or `remote_addr` may be fine after a few looks; for AI, without aliases, semantic notes, and query templates, it cannot know whether these all represent source IP or which field supports cross-log correlation.

For humans, a log source named "prod SLS project 3" may suffice because the team knows what is inside; for AI, it must know whether that Asset is WAF alerts, web access logs, host execution logs, or SSH auth logs.

For humans, failed retrieval means switching systems, asking a colleague, or searching chat; for AI, retrieval failure, missing fields, insufficient permissions, or unavailable indexes must be expressed explicitly—otherwise it fabricates plausible conclusions on incomplete context.

So AI-native security analysis requires humans to prepare three things in advance:

1. **Semantic preparation**: Tell AI what this data is, what fields mean, and which security scenario it belongs to.
2. **Channel preparation**: Tell AI where the data lives, how to access it with authorization, and how to query by entity and time window.
3. **Correlation preparation**: Tell AI which data can join with which, what can be proven, and what missing data implies.

This is not extra burden—it is new infrastructure for security operations in the AI era.

### 2.2 DataAsset: Let AI First Know "What Data Exists"

DataAsset is the foundation of AI-native security analysis.

It answers basic questions:

- What type of data source is this?
- Which security data domain does it belong to?
- What fields exist?
- What is the time field?
- How long is retention?
- Which connector retrieves it?
- Which query templates apply?
- Which log-source hosts does it cover?
- Do sensitive fields require masking?

In SecWeaver, the data asset model consists of four object types:

```text
Asset ──connector_id / connector_ids──→ Connector ──credentials_ref──→ Credentials
  │
  ├── coverage.hosts (log source IPs) ──→ Host ──network_id / interfaces[].network_id──→ Network
  │
  ├── query_template_ids ──→ Query Template
  │
  └── asset_type ──→ Evidence Spec / Scenario / Correlation Matrix
```

A key point: Asset is not just a "data source registration form." It is the entry point for AI to understand data semantics during investigation.

Without Asset, AI sees a pile of fields; with Asset, AI knows this is WAF alerts, host execution logs, SSH auth logs, DNS logs, or database audit logs.

Many analysis failures are not because the model is dumb, but because the data source was never explained before entering the model.

### 2.3 Connector: Let AI Know "How to Collect Evidence"

Knowing a data source exists is not enough—you must know how to retrieve it.

Connector describes the retrieval path:

- SLS, ES, Splunk, database, SSH file, or HTTP API?
- How are credentials referenced?
- What are query limits?
- Which fields are indexed?
- Does it support time-range filtering?
- Can it query by IP, host, user, process?

Where security agents add real value is not "suggest checking logs," but choosing appropriate data sources within authorization, generating queries, executing collection, handling failures, adjusting parameters, and continuing to expand the investigation.

Without Connector, AI is an advisor; with Connector, AI can become an investigator.

### 2.4 Host / Network: Let AI Understand "Where This Entity Sits"

The same outbound behavior on a production server, office endpoint, bastion, DNS server, scanner, or test machine carries completely different risk.

The same internal IP in DMZ, office network, production database segment, management network, or cloud VPC is judged differently.

SecWeaver therefore maintains Host and Network separately:

- **Host**: identity, primary address, aliases, OS, role, exposure.
- **Network**: CIDR, logical zone, network type, trust level.

This looks like asset management; it is actually investigation context.

AI cannot judge whether behavior is anomalous from behavior alone—it must see which entity, zone, and business role the behavior occurs in.

### 2.5 Correlation Matrix: Let AI Know "How Evidence Connects"

The heart of security investigation is not point judgment—it is evidence correlation.

WAF alerts can correlate to web access logs; web access to host processes; host processes to file changes; file changes to outbound connections; outbound to DNS and threat intel; auth logs to lateral movement.

This requires explicit definition of:

- Which data sources can join.
- What the join keys are.
- What time windows apply.
- Which fields serve as anchors.
- What `join_edges` are output on success.
- What `data_gaps` are output on failure.

Correlation Matrix turns expert mental investigation paths into evidence correlation rules that AI can execute and review.

AI can reason—but should not reinvent investigation methodology from scratch every time.

### 2.6 Scenario Pattern: Give AI Investigation SOPs, Not Free Exploration

Real security investigation is neither a purely fixed playbook nor completely free exploration.

Fully fixed SOAR playbooks stall on complex scenarios; fully free agents drift, scatter, and cost spirals.

Scenario Pattern is the balanced approach:

- How to trace an external IP?
- How to confirm a WAF alert?
- How to investigate host anomalies?
- How to analyze lateral movement?
- How to assess risk from externally listening processes?
- How to investigate data exfiltration?
- How to discover a new log format?

Scenario Pattern gives AI an investigation framework; Correlation Matrix gives correlation rules; DataAsset gives semantics and retrieval paths; Skills organize them into runnable analysis and investigation capabilities.

---

## 0x3 Practice 1: Alert Confirmation Is Not a True/False Question—It Is an Evidence Question

When teams first use large models for security analysis, they often ask the simplest question:

```text
Is this alert a real attack?
```

It looks simple; it is not.

A SQL injection alert may be scanner probing—or may have read sensitive data. A WebShell upload alert may be false positive—or a file may already be on disk. An anomalous login may be an employee traveling—or credential theft. A command execution alert may be normal ops—or an attacker dropping a reverse shell.

Alert confirmation cannot rely on alert fields alone—it needs at least three layers of evidence.

### 3.1 Layer 1: The Alert Itself

Start with the alert:

- Alert type?
- Why did the rule fire?
- Source IP, destination IP, URL, payload, status code?
- Alert time?
- Request body, response body, matched rule, risk level?

This layer answers "why it fired."

### 3.2 Layer 2: Raw Logs and Context

Then raw logs and context:

- Continuous probing from the same source IP?
- Abnormal responses on the same URL?
- Was the attack payload processed by the server?
- What business is the target asset? Internet-exposed?
- Abnormal processes or file changes on the target host in the same time window?
- Follow-up access to admin panels, upload paths, or sensitive APIs by the same attacker?

This layer answers "did it get in."

### 3.3 Layer 3: Downstream Attack Chain Evidence

Finally, downstream attack chain:

- Abnormal commands on the host?
- Scheduled tasks, WebShell writes, crontab changes?
- Outbound connections to suspicious IPs or ports?
- Lateral logins, internal scanning, credential access?
- Database or sensitive file access?

This layer answers "what was impacted."

Only when all three layers connect does alert confirmation move from "model judgment" to "evidence-based conclusion."

SecWeaver's alert-confirmation Skill should output not just a verdict, but:

- Conclusion.
- Confidence.
- Supporting evidence.
- Counter-evidence or uncertainty.
- Correlated evidence edges.
- Missing data sources.
- Next investigation steps.

This is the biggest difference between AI-native security analysis and ordinary alert classification.

---

## 0x4 Practice 2: Traceability Investigation Is Reconstructing the Attack Chain

Alert confirmation answers "is this alert valid."

Traceability investigation answers another set of questions:

- Where did the attack start?
- Which asset was compromised first?
- What actions did the attacker take?
- Was there lateral movement?
- Was there data access or exfiltration?
- What is the impact scope?
- Which evidence supports this timeline?

No single log source can do this alone.

### 4.1 Start from Anchors, Not Full-Volume Logs

Real investigation cannot start with full-volume search across all logs. Cost is too high; you get lost.

Find anchors first:

- An attacker source IP.
- A target host.
- A URL.
- An account.
- A process.
- A file path.
- An outbound domain.
- A time window.

Then expand along anchors.

For example, after WAF alert confirmation of successful attack, traceability can unfold:

```text
WAF alert
→ Web access logs
→ Target host
→ Host process execution
→ File changes
→ Network outbound
→ Authentication logins
→ Lateral movement
→ Data access
```

### 4.2 Attack Chains Are Not Drawn on Diagrams—They Are Joined from Evidence

Many products love attack chain graphs, but the value is not the graph—it is the evidence behind each edge.

An edge should answer:

- Why are these two events related?
- Which fields correlate them?
- What is the time window?
- Strong or weak correlation?
- Alternative explanations?
- Missing evidence?

For example:

```text
WAF alert src_ip = 1.2.3.4
  correlates within 5-minute window to Web access remote_addr = 1.2.3.4
  hitting URL = /upload.php
  then target host shows php-fpm child process executing /bin/sh
```

That is a join edge with investigative value.

An attack chain graph that cannot trace back to evidence is just a pretty slide deck.

### 4.3 data_gaps Matter as Much as verdict

Often traceability cannot reach high confidence—not because AI cannot analyze, but because data is missing.

For example:

- WAF alert exists, but no response body.
- Web access logs exist, but no host process logs.
- Host syslog exists, but no auditd execution logs.
- SSH login logs exist, but no bastion command records.
- Outbound connections exist, but no DNS resolution logs.
- Database access exists, but no SQL audit.

Traditional reports often soften uncertainty and deliver seemingly definitive conclusions.

AI-native security analysis should do the opposite: explicitly output **data_gaps**.

```text
Not every investigation must reach a definitive conclusion—but every uncertain conclusion must clearly state what evidence is missing.
```

This matters for security operations. data_gaps are not just regret from one investigation—they are input for the next round of data source building, collection governance, and detection tuning.

---

## 0x5 Practice 3: Risk Identification Should Capture Attack Chain Invariants

Attack techniques change; payloads change; tools change—but certain behaviors on the attack chain change less easily.

Attackers must still:

- Reconnaissance.
- Login.
- Execution.
- Read files.
- Write files.
- Privilege escalation.
- Lateral movement.
- Outbound communication.
- Persistence.
- Access sensitive data.

AI-native security analysis should not chase every new payload—it should capture attack chain invariants.

### 5.1 Externally Listening Processes Executing High-Risk Commands

A process listening on an external port that executes abnormal commands after external access is far riskier than ordinary process execution.

For example:

- Web service child process executing `bash -c`.
- Java process launching `curl | sh`.
- nginx / php-fpm spawning a shell.
- Externally exposed service process reading sensitive files.
- Web process making abnormal outbound connections.

This risk identification requires three evidence pieces:

```text
External listening port
→ Process identity
→ Executed command / outbound behavior
```

A single command may false-positive; a single port is insufficient—only in process identity and network exposure does risk become clear.

### 5.2 Abnormal Outbound Is Not Just IP Threat Intel

Outbound connections cannot rely on threat intel alone.

Many newly registered domains, fresh C2, and ephemeral cloud hosts are not yet in intel feeds. Real value comes from entity context:

- Has this host historically connected to foreign IPs?
- Does this process normally access the internet?
- Is this port common?
- Was the destination triggered by a command just executed?
- Did web attack, file write, or permission change precede outbound?

AI's value is combining this context—not simple IOC matching.

### 5.3 Lateral Movement Is About Paths, Not Isolated Logins

A successful SSH login is not necessarily an attack.

But in the following context, it is highly suspicious:

- Source host was just hit by a web attack.
- Login account is not normally used from that source.
- Target belongs to a higher-trust network segment.
- Batch commands run immediately after login.
- Internal scanning or credential access follows.

The key to lateral movement is not "was there a login"—but whether that login sits on an attack path.

SecWeaver's Host / Network / Correlation Matrix exists so AI can see that path.

---

## 0x6 Practice 4: New Data Source Onboarding Is Not Form-Filling—It Is Giving AI New Senses

A common misconception: data source onboarding means configuring a connection URL, filling credentials, and being done when logs are searchable.

A second misconception: onboarding only WAF, EDR, NDR, SIEM alerts and detection logs while ignoring raw host and network behavior. Many real attacks do not reliably trigger high-quality alerts, but always leave traces in execution, file changes, auth logins, DNS, outbound connections, and internal lateral movement. If the registry has only "alert assets" and no "behavior assets," AI can explain alerts but struggles to confirm success or complete traceability.

A third misconception: treating data preparation as a traditional data governance project—design exhaustive standards first, refactor all systems, then spend years platformizing. That has its place in data security, warehouses, and master data—but in AI-native security analysis it is often too heavy, too slow, and poorly matched to the pace of offense–defense.

SecWeaver should adopt lightweight, convenient, iterative onboarding: register a source, explain fields, run queries, establish key correlations, support a minimum evidence set for one scenario—then incrementally add fields, templates, correlations, permissions, and quality checks based on real **data_gaps** and failure cases from investigations.

```text
Security data preparation is not a one-time governance project—it is an engineering onboarding process that evolves around investigation scenarios.
```

For AI-native security analysis, data source onboarding has at least four layers.

### 6.1 Layer 1: Can Connect

Can the connector reach the target system? Are credentials valid? Do queries succeed? Are rate limits and timeouts controlled?

This is a connectivity problem.

### 6.2 Layer 2: Can Understand

What do log fields mean? Time field? IP fields? Host fields? Event type? Risk level?

This is a semantics problem.

### 6.3 Layer 3: Can Query Accurately

Are fields indexed? Are query templates correct? Do time ranges work? Can you search by key entities? Is enough context returned?

This is a forensics problem.

### 6.4 Layer 4: Can Correlate

Which data sources can this join with? Join keys—IP, host, user, process, file hash, URL, session id? Time window? What does correlation failure imply?

This is an evidence chain problem.

Many systems stop at layer one, maybe layer two. SecWeaver must reach layer four.

Because AI investigation needs not "we have logs," but "logs can become evidence."

---

## 0x7 Practice 5: AI and Humans Collaborate—AI Does Not Replace Humans

AI-native security analysis is not removing security staff from the process, nor letting AI bear all judgment responsibility alone.

Its core is a stable human–machine collaboration model: humans do what humans do best; AI does what AI does best.

**AI excels at:**

- 24/7 processing of large alert and log volumes.
- Automated collection and cross-source search by template and scenario.
- Stitching scattered evidence into preliminary investigation chains.
- Structured conclusions, confidence, and data_gaps.
- Scalable triage and review of similar events.

**Humans excel at:**

- Business context, organizational boundaries, risk appetite.
- Judging exceptions and high-impact events where AI is uncertain.
- Defining investigation boundaries, response strategy, and final accountability.
- Turning frontline experience into Scenario Patterns, Skills, and precedents.
- Driving data source building, rule tuning, and capability validation.

**Past human work was mainly:**

- Open alerts.
- Query logs.
- Copy IPs.
- Switch systems.
- Screenshot.
- Write conclusions.
- Close tickets.

**Future human work should be:**

- Prepare data for AI.
- Audit AI conclusion quality.
- Handle low-confidence or high-impact events.
- Correct AI misjudgments.
- Turn experience into Scenario Patterns.
- Turn investigation paths into Skills.
- Turn missing evidence into data source tasks.
- Turn real cases into evaluation samples.

```text
AI handles scale; humans handle boundaries. AI executes; humans calibrate. AI discovers; humans accumulate.
```

Every human correction should not live only in ticket notes—it should enter:

- Precedent library.
- Evaluation sets.
- Entity profiles.
- Allowlist governance.
- Rule optimization.
- Data source improvement plans.

Human work focus does not shrink—it shifts from repetitive handling to defining boundaries, validating quality, and turning experience into system capability.

More importantly, AI-native security operations should turn "clearing today's alert batch" into "tomorrow's investigations are faster, judgments more accurate, capability stronger." Daily work processes not only events but compound organizational security experience.

---

## 0x8 Engineering: The Model Is the Last Link—Data Preparation Sets the Ceiling

Many AI security projects fail not because the model is weak, but because the engineering pipeline is not connected.

In production, factors affecting AI analysis quality include:

- Data source availability.
- Correct field parsing.
- Unified time.
- Hostname–IP matching.
- Connector stability.
- Accurate query templates.
- Log indexing.
- Sensitive field masking.
- Traceable evidence.
- Versioned prompts.
- Audited Skill invocations.
- Replayable model outputs.

None of these are "model IQ"—but all determine whether AI investigation can land.

SecWeaver's engineering focus is not stuffing everything into the model, but placing the model on a trustworthy evidence pipeline:

```text
Data asset validation
→ Connector health check
→ Query template execution
→ Evidence bundle construction
→ Correlation edge generation
→ Gap identification
→ AI analysis
→ Report output
→ Result audit
→ Feedback accumulation
```

Only when this pipeline is stable does AI move from "can talk" to "can query, prove, and review."

---

## 0x9 Boundaries: What SecWeaver Should Stand For—and Not Cross

Clear product boundaries make AI security analysis easier to deploy.

### 9.1 Behind Security Devices, Not Replacing Them

SecWeaver should not be positioned as replacing WAF, EDR, NDR, SIEM, HIDS, DLP, or database audit products.

Those systems have their own data ingress and specialized detection. SecWeaver fits **behind** them—organizing scattered alerts and logs into evidence chains for secondary confirmation, deep investigation, and traceability analysis.

### 9.2 Control Where the Large Model Is Used—Do Not Send Full Logs In

Sending full logs directly into large models is unsustainable in cost, latency, and security.

Large models should be used for:

- Multi-step reasoning.
- Uncertain judgment.
- Cross-source evidence explanation.
- Investigation path planning.
- Report generation.
- Gap analysis.

Millisecond detection, simple rule hits, and fixed-field aggregation should still be done by traditional rules, query engines, and deterministic scripts.

### 9.3 Response Must Be Controlled—Automation Is Not the Default Answer

Before evidence chains, permissions, approval, audit, and rollback mature, automatic blocking, isolation, or account disablement can create business risk.

Phase one of AI-native investigation should emphasize:

```text
Automated analysis, assisted confirmation, human oversight, controlled response.
```

### 9.4 Expert Experience Must Be Productized—Not Trapped in Prompts

Expert experience written only in prompts is hard to version, audit, reuse, and validate.

Real value comes from structuring expert experience as:

- DataAsset.
- Query Template.
- Correlation Matrix.
- Scenario Pattern.
- Skill.
- Case Memory.
- Detection Rule.
- Evaluation Sample.

Prompts are entry points; engineered assets are the long-term moat.

---

## (II) Outlook: From One-Off Investigations to Accumulating Security Capability

Traditional SOC work often stops at alert handling:

Alerts arrive daily; analysts process a batch; tickets close; similar alerts return the next day; repetitive labor continues. Operational value often stays at "did we miss a major event today"—not "did organizational security capability improve because of it."

AI-native SOC should not merely close alerts faster. It should let AI and humans collaborate on daily operations: AI executes scalable investigation; humans define boundaries, validate quality, and accumulate experience. Every alert confirmation, every traceability run, every human correction should become reusable security capability.

```text
If investigation results live only in reports, value fades quickly—only when accumulated as rules, templates, profiles, samples, or onboarding improvements do they enter the next operational cycle.
```

These defensive assets can include:

- A more accurate detection rule.
- A new query template.
- A field mapping fix.
- A log parser.
- An attack chain scenario template.
- A reusable precedent.
- An evaluation sample.
- A data source gap recommendation.
- A host or account profile.
- A time-bounded allowlist.
- A hunting hypothesis.
- A response playbook.

Attacker intelligence investment often serves a single breach; defender intelligence investment must accumulate into capability that can be invoked repeatedly and calibrated continuously.

SecWeaver's long-term direction is not just an AI analysis tool, but an **evidence-driven, AI-native security investigation and analysis foundation**:

```text
Foundation: DataAsset / Connector / Host / Network
Middle: Correlation Matrix / Scenario Pattern / Evidence Graph
Top: Alert Confirmation / Traceability / Risk Identification Skills
Operations: Triage / Review / Human Feedback / Case Memory / Detection Engineering / Validation
```

When security teams accumulate data sources, evidence chains, investigation paths, human experience, and evaluation validation, AI can truly take over repetitive investigation work—freeing humans for higher-value judgment and governance.

AI provides scalable processing; humans own goals, boundaries, and final accountability; evidence chains keep conclusions trustworthy; validation keeps the system continuously usable. Ideally, security operations compounds daily: today's investigation experience becomes tomorrow's rules, templates, profiles, and precedents; today's data gaps become tomorrow's onboarding tasks; today's human corrections become tomorrow's evaluation samples and system improvements.

---

## Conclusion

In the AI attack era, defenders cannot rely only on stacking devices, rules, and headcount against machine-speed attacks.

But defenders are not without advantage. Enterprises hold their own assets, history, logs, business context, and frontline experience. The problem is that these advantages were too scattered—never organized into an evidence system AI could use.

Therefore, AI-native is first a transformation in **how data is prepared** and **how security operations thinks**.

This is not copying traditional data governance wholesale into offense–defense. It is building a **lighter security data registry for AI investigation**: fast onboarding, semantic explanation, declared retrieval methods, described correlation relationships, exposed data gaps. Governance yes—but not so heavy it blocks onboarding; standards yes—but growing around investigation scenarios.

Palantir's trajectory also shows a trend: before AI capability truly lands, enterprises usually organize data objects, relationships, permissions, and action semantics. Its Ontology reminds us that data building is not connecting more tables—it is expressing the real business objects and action boundaries behind data. Without that foundation, AI stays at Q&A and summarization; with it, AI enters real workflows. SecWeaver's emphasis on data assets, connectors, correlation matrices, and investigation Skills is essentially building that work foundation for security AI.

We used to assume "humans can read it is enough": inconsistent field names compensated by experience, log locations found by asking colleagues, unclear asset relationships checked ad hoc, allowlist reasons dug from chat. That mode barely worked for small-scale human investigation—it fails when AI agents analyze in bulk, collect evidence automatically, and trace continuously.

The future must shift to "AI can understand, obtain, correlate, and review": self-describing data sources, semantic fields, retrieval channels, entity profiles, evidence correlation rules, and explicitly expressed gaps.

The core of AI-native security analysis and traceability investigation is not letting the model guess like a security expert—it is letting the model work on a complete, accurate, traceable evidence chain.

Without data assets, AI does not know what exists.

Without connectors, AI does not know how to query.

Without a correlation matrix, AI does not know how to stitch evidence.

Without scenario patterns, AI does not know how to investigate.

Without data gaps, AI does not know where it is uncertain.

Without a validation loop, AI does not know whether it is improving.

So AI-native security operations is not a procurement event or prompt engineering—it is turning security data, investigation methods, expert experience, and operational feedback into a runnable, auditable, continuously iterable engineering system.

This is what SecWeaver aims to do:

```text
Register security data as AI-usable data assets, turn investigations into reviewable evidence chains, and convert every traceability run into faster, more accurate analysis next time.
```

In the AI era, every enterprise needs an AI + data dual-driven AI security defense line. Interested readers can scan the QR code to join our open-source community.
