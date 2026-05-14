# Burp Suite Enterprise Integration

The ultimate goal of BBPTS is to separate the *discovery* phase from the *testing* phase, allowing security engineers to maximize their time in Burp Suite focusing on high-value, prioritized targets.

This guide details the optimized workflow for piping BBPTS intelligence directly into Burp Suite Professional.

---

## The Workflow

### 1. Intelligence Generation
Begin by running a comprehensive BBPTS scan over your target scope. Ensure you generate the CSV summary, which contains computed risk scores and testing heuristics.

```bash
./bbpts -input scope.txt -tools subfinder,httpx,waybackurls,katana -summary bbpts-prioritized.csv -debug
```

### 2. Analysis & Triage
Open `bbpts-prioritized.csv`. Pay strict attention to the following columns:
- **severity**: Sort by `high` and `medium`.
- **tags**: Look for `api`, `auth`, `sensitive`, and `parameterized`.
- **suggested_tests**: This column maps directly to Burp Scanner configuration blocks (e.g., *IDOR, SQLi, XSS*).

### 3. Burp Suite Project Configuration
1. Open Burp Suite and create a new Project.
2. Navigate to **Target -> Scope settings**.
3. Import the exact domains listed in the BBPTS CSV into your advanced scope configuration.
4. Go to **Proxy -> Proxy settings** and ensure "Intercept Client Requests" is set to "And URL Is in target scope".

### 4. Active Scanning Strategy
Instead of blindly scanning the entire application, use the BBPTS `Suggested Tests` column to configure targeted scans.

1. Navigate to **Dashboard -> New Scan**.
2. Input a target URL from your BBPTS `CRITICAL` tier.
3. Select **Scan Configuration -> Select from library**.
4. If BBPTS tagged the host with `api`, select **Audit checks - API and out-of-band**.
5. If BBPTS tagged the host with `parameterized`, ensure **Audit checks - light active** or custom injection lists are enabled.

### 5. Manual Testing Checklist
For each high-priority target, use Burp Repeater and Intruder against the specific attack vectors identified by BBPTS:

- **Auth Tags**: Immediately test for authentication bypass, weak token generation, and IDOR in the session handlers.
- **API Tags**: Map the endpoint in Burp, export the OpenAPI spec (if available via BBPTS endpoints), and fuzz JSON parameters using Intruder.

By letting BBPTS handle the wide-net reconnaissance, your time in Burp Suite is spent exclusively on targeted, high-probability exploitation.
