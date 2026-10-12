package auditportexecmon

// auditAttributionSnapshot freezes the result of primary-record admission.
// PID, source transaction, executable and key bind the decision to one syscall;
// a boolean accepted flag alone cannot prevent a later lookup using a reused PID.
// This is reader-owned memory, never deserialized from audit field names.
type auditAttributionSnapshot struct {
	decided                           bool
	verified                          bool
	listener                          listenerInfo
	msg, pid, ppid, exe, key, syscall string
}

func snapshotAuditAttribution(fields map[string]string, listener listenerInfo, verified bool) auditAttributionSnapshot {
	return auditAttributionSnapshot{
		decided: true, verified: verified, listener: listener,
		msg: fields["msg"], pid: fields["pid"], ppid: fields["ppid"],
		exe: fields["exe"], key: fields["key"], syscall: fields["syscall"],
	}
}

// matches prevents a duplicate/conflicting primary or pooled accumulator from
// transferring a prior decision to another syscall. Auxiliaries only add context.
func (s auditAttributionSnapshot) matches(fields map[string]string) bool {
	return s.msg != "" && s.msg == fields["msg"] && s.pid == fields["pid"] &&
		s.ppid == fields["ppid"] && s.exe == fields["exe"] &&
		s.key == fields["key"] && s.syscall == fields["syscall"]
}

// consumeAttributedAuditLine is shared by both production transports. Resolve
// once, before observation can schedule cleanup or another /proc read, then carry
// the immutable decision through assembly. History is never used to install rules.
func (m *processTreeMonitor) consumeAttributedAuditLine(accs map[string]*auditAccumulator, line string, fields map[string]string, keepRaw bool) string {
	id := extractMsgID(line)
	if id == "" {
		return ""
	}
	acc := accs[id]
	if acc != nil && acc.fields["msg"] != fields["msg"] {
		// Serial-only IDs remain public for compatibility, but assembly must also
		// match the source timestamp. Reject foreign tails without changing owners.
		m.recordAttribution("transaction_conflict")
		return ""
	}
	primary := fields["type"] == "SYSCALL"
	var snapshot auditAttributionSnapshot
	if primary {
		if acc != nil && acc.attribution.decided {
			if !acc.attribution.matches(fields) {
				acc.attribution.verified = false
				m.recordAttribution("transaction_conflict")
			}
			return id // replay cannot renew a decision or repeat clone expansion
		}
		listener, matched := m.matchListener(fields)
		snapshot = snapshotAuditAttribution(fields, listener, matched)
	}
	m.observeAuditFields(fields)
	if fields["key"] == m.cloneKey {
		return ""
	}
	if primary && m.usesBoundedAudit() && !snapshot.verified && fields["attribution_status"] != "unknown" {
		m.recordAttribution("outside_scope")
		return ""
	}
	id, _ = consumeAuditLineParsed(accs, line, fields, keepRaw)
	if acc = accs[id]; primary && acc != nil {
		acc.attribution = snapshot
		if snapshot.verified {
			m.recordAttribution("snapshot_saved")
		}
	}
	return id
}

// assembledListener never revalidates a captured syscall against today's /proc.
// Legacy direct parser callers without admission still use the normal matcher;
// both real readers always provide a decision for SYSCALL records.
func (m *processTreeMonitor) assembledListener(acc *auditAccumulator) (listenerInfo, bool) {
	if !acc.attribution.decided {
		return m.matchListener(acc.fields)
	}
	if !acc.attribution.verified || !acc.attribution.matches(acc.fields) {
		return listenerInfo{}, false
	}
	m.recordAttribution("snapshot_used")
	return acc.attribution.listener, true
}
