# Network Digital Twin (NDT)

## Vision

Build a Digital Twin of enterprise network infrastructure capable of understanding, explaining and planning network communication.

The Digital Twin should answer questions that today require senior network architects.

Examples:

- How does Host A communicate with Host B?
- Which ACL permits this communication?
- Which route is selected?
- Which VRF is used?
- Which VPN transports the traffic?
- Which business systems are affected if this firewall is changed?
- Can KMS be migrated safely?
- Generate a migration plan.
- Generate rollback steps.

---

# Core Principles

## Graph First

Everything becomes a node and a relationship.

Never reason directly on Cisco configuration.

Configuration is only input.

Knowledge Graph is the truth.

---

## Domain Models

Engines never return dictionaries.

Every engine returns domain models.

Examples

- PathResult
- ImpactResult
- DependencyResult
- MigrationPlan

---

## Explainability

Every conclusion must be explainable.

Never answer:

"It should work."

Instead answer:

"It works because..."

and show the complete dependency chain.

---

## Host A → Host B

Every feature must improve our ability to explain communication between two hosts.

If a feature does not improve that capability, it is probably not a priority.

This is our North Star.

---

## Architecture

```
Cisco Configs
        │
        ▼
     Parsers
        │
        ▼
 Domain Models
        │
        ▼
  Graph Builder
        │
        ▼
 Knowledge Graph
        │
 ┌──────┼────────────┐
 │      │            │
Explorer Path    Impact
 │      │            │
 └──────┼────────────┘
        ▼
 Migration Engine
        │
        ▼
 AI Assistant
```

---

# Long-term Goal

Create a platform capable of building a complete Digital Twin of enterprise network infrastructure.

The platform should:

- Discover
- Understand
- Explain
- Analyse
- Assess Risk
- Plan Migration
- Generate Documentation
- Assist Engineers using AI

---

# Success Criteria

Given any two hosts...

The platform can explain:

- Communication path
- Firewall traversal
- ACL evaluation
- Routing
- NAT
- VPN
- Dependencies
- Business impact

and generate a migration plan.