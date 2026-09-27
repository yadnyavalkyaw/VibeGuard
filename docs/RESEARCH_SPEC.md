# Research Specification — AIAG (Authorization-Intent Attack Graph)

## 1. Abstract

Vibe-coded applications—built rapidly using Large Language Models—frequently suffer from authorization vulnerabilities such as Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), and privilege escalation. These flaws arise because LLMs routinely generate correct data access logic while omitting subtle context-dependent authorization guards. Existing static tools produce excessive false positives due to lack of runtime state awareness, while dynamic tools lack structural insight into implied code contracts.

We introduce **AIAG (Authorization-Intent Attack Graph)**, a hybrid security testing framework that statically infers implied authorization intent from source code and dynamically verifies compliance using multi-identity runtime graph contradiction analysis.

---

## 2. Theoretical Formulation

### 2.1 Static Authorization Intent Extraction
Let an application $A$ consist of a set of endpoints $E = \{e_1, e_2, \dots, e_n\}$.
For each endpoint $e_i$, static analysis extracts an implied **Authorization Intent** tuple:

$$I(e_i) = \langle R_{req}, A_{act}, AuthLvl, OwnCheck \rangle$$

where:
- $R_{req} \in \mathcal{R}$ is the target domain resource type (e.g. `Order`, `Invoice`, `UserProfile`).
- $A_{act} \in \{\text{CREATE}, \text{READ}, \text{UPDATE}, \text{DELETE}, \text{EXECUTE}\}$ is the operation.
- $AuthLvl \in \{\text{public}, \text{authenticated}, \text{admin}\}$ is the required identity level.
- $OwnCheck \in \{\text{TRUE}, \text{FALSE}\}$ indicates whether the code implies a owner constraint (e.g. `resource.owner_id == principal.id`).

### 2.2 Dynamic Runtime Observation
During dynamic multi-identity execution across principals $P = \{P_A, P_B, P_{admin}, P_{anon}\}$, dynamic scanning records a set of runtime observations:

$$O(P_k, e_i, r_j) = \langle \text{status\_code}, \text{body\_hash}, \text{data\_returned} \rangle$$

where $r_j$ is a specific resource instance owned by principal $P_{owner}(r_j)$.

### 2.3 Contradiction Engine & Theorem
Let $\text{ExpectedAccess}(P_k, r_j, e_i)$ be defined by the static authorization intent:

$$\text{ExpectedAccess}(P_k, r_j, e_i) = \begin{cases} 
\text{FALSE} & \text{if } OwnCheck = \text{TRUE} \land P_k \neq P_{owner}(r_j) \\
\text{FALSE} & \text{if } AuthLvl = \text{admin} \land \text{Role}(P_k) \neq \text{admin} \\
\text{TRUE} & \text{otherwise}
\end{cases}$$

Let $\text{ObservedAccess}(P_k, r_j, e_i)$ be derived from dynamic observation $O$:

$$\text{ObservedAccess}(P_k, r_j, e_i) = \begin{cases}
\text{TRUE} & \text{if status\_code} \in [200, 299] \land \text{data\_returned} \neq \emptyset \\
\text{FALSE} & \text{if status\_code} \in [401, 403, 404]
\end{cases}$$

A **Vulnerability Contradiction** $\mathcal{C}$ exists if and only if:

$$\mathcal{C}(P_k, r_j, e_i) \iff \Big( \text{ExpectedAccess}(P_k, r_j, e_i) = \text{FALSE} \Big) \land \Big( \text{ObservedAccess}(P_k, r_j, e_i) = \text{TRUE} \Big)$$

---

## 3. Graph Schema Representation

The AIAG is constructed within PostgreSQL using nodes and typed edges:

### Node Types
- `Principal`: User identities ($P_A$, $P_B$, Admin, Anonymous).
- `Role`: User roles (`user`, `admin`, `manager`).
- `Endpoint`: API routes (`GET /api/orders/[id]`).
- `Action`: HTTP method/semantic operation (`READ`).
- `Resource`: Abstract resource type (`Order`).
- `ResourceInstance`: Specific DB record (`Order #1042`, owner=$P_A$).
- `AuthorizationRequirement`: Extracted constraint rule (`owner_id == principal.id`).
- `RuntimeObservation`: Executed HTTP request trace.
- `Finding`: Verified security flaw.

### Directed Edge Types
- `HAS_ROLE`: $(Principal \to Role)$
- `PERFORMS`: $(Endpoint \to Action)$
- `TARGETS`: $(Action \to Resource)$
- `OWNED_BY`: $(ResourceInstance \to Principal)$
- `REQUIRES`: $(Endpoint \to AuthorizationRequirement)$
- `OBSERVES`: $(RuntimeObservation \to Endpoint)$
- `ACCESSES`: $(RuntimeObservation \to ResourceInstance)$
- `CONTRADICTS`: $(RuntimeObservation \to AuthorizationRequirement)$
- `PRODUCES`: $(Contradiction \to Finding)$
