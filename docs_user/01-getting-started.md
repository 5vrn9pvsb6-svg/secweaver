# 01. Getting Started with SecWeaver

**Languages:** English (this page) | [简体中文](01-getting-started.zh-CN.md)

This page explains—in terms operators can follow—what SecWeaver is, what problems it solves, and why you need to configure `dataasset`.

This is optional conceptual reading, not an installation prerequisite. Start with the [10-minute quickstart](00-security-operator-quickstart.md) for hands-on use; the [platform introduction](14-platform-introduction.md) provides optional product context.

---

## What is SecWeaver?

SecWeaver is an AI-native security analysis and incident investigation platform for security operations.

Its goal is not simply to plug in a large language model for chat. It is to let the model actually use your security data:

- Query logs.
- Query alerts.
- Query host behavior.
- Query network connections.
- Query database audit records.
- Correlate evidence from multiple sources.
- Produce security conclusions you can verify.

You can think of it as:

```text
Security operations data asset catalog + investigation playbooks + AI analysis assistant
```

---

## What problems does it solve?

In traditional security operations, frontline analysts often run into these issues:

1. Too many logs—unclear where to start.
2. Different systems use different field names, making correlation hard.
3. WAF, hosts, SSH, firewalls, and DNS are queried in isolation, breaking the evidence chain.
4. Investigation know-how lives in individuals’ heads; the path changes when someone else takes over.
5. AI can suggest approaches but does not know which logs you actually have.

SecWeaver aims to solve this:

```text
Turn “what to query, how to query, how to correlate, and how to explain” into configurable, reusable, auditable workflows.
```

---

## Why can’t we rely on the LLM alone?

Large models know a lot of security common sense. For example, they know:

- After a WAF alert, check web access logs.
- WebShell activity may involve file writes and command execution.
- Lateral movement often shows up in SSH, RDP, and SMB.
- Data exfiltration requires checking outbound connections, DNS, traffic, and database access.

But the model does not know about your environment:

- Which log sources actually exist.
- Which log sources are already in production.
- Whether fields are named `src_ip` or `client_ip`.
- Which SLS project holds WAF logs.
- Whether SSH logs come from SLS, files, or a database.
- Which join rules are trustworthy in your setup.
- How far before and after an event to query by default.

So SecWeaver is designed as:

```text
Configuration tells the AI “what data exists and how to query it”;
the AI handles “understanding the question, running the investigation, and explaining the evidence.”
```

---

## How does an investigation run?

Take “Help me determine whether this WAF alert indicates a successful attack” as an example:

```text
1. User asks a question
   ↓
2. System recognizes this as an alert confirmation scenario
   ↓
3. Scenario Pattern tells the system: query WAF first, then web access, then host behavior
   ↓
4. Fetch Plan generates data-fetch tasks from configuration
   ↓
5. Query Template queries the corresponding data sources
   ↓
6. Evidence is normalized to unified fields
   ↓
7. Correlation Matrix links WAF, web, and host behavior
   ↓
8. AI outputs a conclusion from the evidence chain: false positive / suspicious / success / insufficient evidence
```

In this process, the model does not guess freely—it works along the data assets and investigation playbooks you configured.

---

## The most important directories in SecWeaver

Operators should focus on `dataasset/`:

```text
dataasset/
├── assets/             # Logical data assets: what this data is
├── connectors/         # Connectors: how to reach data sources
├── credentials/        # Credentials: secrets live here, not in plain text
├── hosts/              # Hosts: important server metadata
├── networks/           # Networks: which IP belongs where, trust level
├── bundles/            # Bundles: which data a given investigation needs
├── scenarios/          # Investigation scenarios: what to query first for a question type
├── query-templates/    # Query templates: how to query in practice
└── schema/             # Validation rules
```

---

Validation and test scripts live at `src/dataasset/` from the repository root, separately from `dataasset/`. The bundled `dataasset/` contains synthetic examples. Edit this directory by default, or optionally copy it to `dataasset_my/` for isolation, prepared as described in [data source configuration](03-configure-data-sources.md).

## What do you mainly do as an operator?

You typically:

1. Add or modify data sources.
2. Configure how to connect to data sources.
3. Confirm field meanings and field mappings.
4. Register key hosts and network segments clearly.
5. Add commonly used data sources to appropriate bundles.
6. Run validation scripts to ensure configuration is correct.
7. Start investigations with AI and review the results.

---

## Minimum viable path

For a first experience, use the [synthetic-data quickstart](00-security-operator-quickstart.md); no live sources are required. This section is for a subsequent production pilot, starting with three data types:

```text
WAF alerts
Web access logs
Host command execution logs
```

These three support:

- WAF alert confirmation.
- WEB intrusion assessment.
- Whether the attack reached a host.
- Whether command execution occurred.

Then expand with:

- SSH login logs: lateral movement and account compromise.
- Firewall logs: cross-segment access.
- DNS logs: suspicious domain lookups.
- Network traffic: large-volume exfiltration.
- Database audit: sensitive data access.

---

## Common misconceptions to avoid

### Misconception 1: Connect every log before using the platform

You do not need to. Get one critical chain working first, then expand step by step.

### Misconception 2: Let the LLM decide everything

Not recommended. The model should work within configuration constraints; otherwise it may miss queries or invent details.

### Misconception 3: Inconsistent fields are fine

They are not. Inconsistent fields break correlation. For example, if one log uses `client_ip` and another uses `src_ip`, you need field mapping to unify them.

### Misconception 4: Skip validation after configuration

After every change under `dataasset/`, run the validation script.

---

## Next steps

Continue with: [02. Core Concepts](02-core-concepts.md)
