Our project is to manage and observe our cyber security lab products, that seamlessly scans the entire source code for vulnerability. 

we have self hosted code management system called gitea,for each and every push from the developers in gitea that trigger's the jenkins pipeline, that actually clone the entire repository for application secuirty checks by using SCA 
SAST and DAST tools, that acts as a self hosted devsecops pipeline.

then it compare the results from pipeline with actual CVE's,that are fetched from real CVE database, if those resuls matches with CVE's then it will get into AI-Engine, that ai-engine fixes those code as per the actual pathces in 
the CVE database 

Then the ai-engine will create a PULL REQUEST on developers repository with the fixed code, that includes CVE and remediation details, then we manully compare the vulnerable code with the new Pull request,if it's legitimate then
developers will merge into the  main brach.

the entire process will be scraped by prometheus and displayed by grafana

version 2

Our project focuses on managing and monitoring cybersecurity lab products through an automated vulnerability management platform that continuously scans source code for security issues.

We use a self-hosted code management system, Gitea, where every code push made by developers automatically triggers a Jenkins pipeline.


The pipeline clones the entire repository and performs comprehensive application security testing using Software Composition Analysis (SCA),Static Application Security Testing (SAST)
and Dynamic Application Security Testing (DAST) tool as part of a self-hosted DevSecOps workflow.

The vulnerabilities identified during the scanning process are then correlated with real-world CVEs retrieved from a live CVE database.
If a match is found, the affected code is forwarded to an AI-powered remediation engine.
The AI engine analyzes the vulnerability and automatically generates code fixes based on the official patches and remediation guidance associated with the corresponding CVEs.

Once the remediation is completed, the AI engine creates a Pull Request (PR) in the developer's repository containing the proposed code changes, along with detailed CVE information and remediation notes. 
The security team or developers then manually review the vulnerable code against the generated fixes to validate their accuracy and legitimacy. Upon successful validation, the Pull Request is merged into the main branch.

The entire workflow, including pipeline execution, vulnerability findings, remediation activities, and system metrics, is monitored through Prometheus and visualized using Grafana dashboards, 
providing complete observability of the DevSecOps ecosystem.
