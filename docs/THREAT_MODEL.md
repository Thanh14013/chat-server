# VCS SecureChat — Threat Model

> Analysis framework: **STRIDE** (Microsoft)
> Scope: server process, client process, and TCP transport between them.

---

## 1. Assets

| Asset                   | Sensitivity | Description                              |
|-------------------------|-------------|------------------------------------------|
| Chat messages           | HIGH        | May contain confidential information     |
| User credentials        | CRITICAL    | Nicknames + passwords                    |
| Session tokens          | HIGH        | Grant authenticated access               |
| Chat history (SQLite)   | HIGH        | Persistent record of conversations       |
| Audit log               | HIGH        | Tamper-evident security log              |
| Server private key      | CRITICAL    | Used for RSA key exchange (week 2)       |
| Ban/whitelist lists     | MEDIUM      | Operational security policy              |

---

## 2. STRIDE Analysis

### S — Spoofing Identity

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| Attacker claims another user's nickname     | Nickname uniqueness enforced at connect; re-auth on room join |
| Session token replay after disconnect       | Tokens are in-memory, expire on server restart               |
| Fake server (MITM)                          | Certificate pinning (TOFU) in week 2 client                  |

**Residual risk:** No PKI infrastructure; TOFU is only effective after first connection.

---

### T — Tampering with Data

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| Modify chat message in transit              | CRC32 on every packet; malformed packets dropped             |
| Inject forged packets without valid session | Session tokens required for all non-handshake packets        |
| Tamper with SQLite audit log directly       | Hash chain: modifying row *k* invalidates all rows *k+1..n* |
| Path traversal in file transfer filenames  | Filename sanitized: strips `../`, `\`, leading dots          |

---

### R — Repudiation

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| User denies sending a message               | Audit log records every MSG_CHAT_SEND with actor + timestamp |
| Admin denies issuing kick/ban               | All admin commands logged with chain hash                    |
| Log file deletion                           | Chain hash detects gaps; future work: remote syslog          |

---

### I — Information Disclosure

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| Wireshark / tcpdump traffic sniffing        | AES-256-GCM encryption after week-2 handshake               |
| Log files world-readable                    | `logs/` directory created with mode 0755; recommend 0700    |
| SQLite database readable by other users     | `vcs_chat.db` should have mode 0600                         |
| Stack traces leak internal state            | Exceptions caught; only generic errors sent to clients       |

---

### D — Denial of Service

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| Message flood from single client            | Token Bucket rate limiter (10 msg/s default)                |
| Connection flood from single IP             | IDS tracks connection rate; auto-temp-ban on threshold       |
| Slow loris (connect but never send)         | EventLoop pings every 30s; drops non-responsive clients      |
| MAX_CLIENTS exhaustion                      | Hard limit 256; reject with ERR_SERVER_FULL                  |
| Malformed oversized packet                  | payload_length checked before allocation; capped at 4352 B  |

---

### E — Elevation of Privilege

| Threat                                      | Mitigation                                                   |
|---------------------------------------------|--------------------------------------------------------------|
| Regular user sends admin commands           | Server checks `session.role` before executing any admin cmd  |
| USER promotes themselves to ADMIN           | Only OWNER role can call promote                             |
| SQL injection via chat message              | MessageFilter blocks SQL pattern keywords before broadcast   |
| Command injection via filename              | Filename whitelist extension + sanitize function             |

---

## 3. Attack Scenarios

### Scenario A: Brute Force Login
```
Attacker: sends MSG_CONNECT_REQUEST with wrong password repeatedly
Server:   IDS adds +10/attempt → temp ban at score 100 (~10 attempts)
          Account lock after AUTH_MAX_ATTEMPTS (config, default 5)
```

### Scenario B: Message Flood (DoS)
```
Attacker: sends 1000 messages/second
Server:   Token bucket allows burst of 10, then drops
          After 4 violations: IDS scores +5 each → temp ban escalation
```

### Scenario C: SQL Injection Attempt
```
Attacker: sends "DROP TABLE Users; --"
Filter:   containsInjection() matches "DROP TABLE" → BLOCKED_INJECTION
Audit:    SECURITY event logged with actor + message snippet
IDS:      +30 threat score applied to attacker IP
```

### Scenario D: Audit Log Tampering
```
Attacker: opens vcs_chat.db in SQLite editor, modifies row 50
Admin:    ./vcs_server --verify-audit-log
          "Audit chain broken at event: <uuid>"
          All entries from row 51 onward have invalid prev_hash
```

### Scenario E: Port Scan / Probe
```
Attacker: connects but sends nothing (port scan behaviour)
Server:   No MSG_CONNECT_REQUEST within ping window → disconnect
IDS:      +100 score for PORT_SCAN → immediate temp ban
```

---

## 4. Residual Risks (Known Limitations)

| Risk                              | Severity | Notes                                       |
|-----------------------------------|----------|---------------------------------------------|
| No Perfect Forward Secrecy        | MEDIUM   | Future: ECDH per-session key exchange       |
| RSA key not rotated               | LOW      | Rotates on server restart                   |
| Chat history stored plaintext     | MEDIUM   | Trade-off: searchability vs. confidentiality |
| No TLS (custom crypto only)       | MEDIUM   | Educational choice; production = OpenSSL TLS |
| TOFU cert pinning not cryptographic| LOW     | Sufficient for internal deployment           |
| No distributed server             | LOW      | Single point of failure; future work        |

---

## 5. Security Controls Summary

| Control                    | Type         | Where Implemented              |
|----------------------------|--------------|--------------------------------|
| Token Bucket Rate Limiter  | Preventive   | `RateLimiter` + `TcpServer`   |
| IDS with auto-ban          | Detective    | `IntrusionDetector`            |
| Message injection filter   | Preventive   | `MessageFilter`                |
| Tamper-evident audit log   | Detective    | `AuditLogger` (hash chain)     |
| Role-based access control  | Preventive   | `ClientSession::role`          |
| File transfer validation   | Preventive   | `FileTransfer` (ext whitelist) |
| Session keepalive + timeout| Preventive   | `EventLoop`                    |
| Graceful shutdown          | Operational  | `TcpServer::stop()` + SIGINT   |
