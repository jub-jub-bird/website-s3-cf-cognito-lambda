# RUNBOOK — AWS Website Pattern (Pulumi)

This runbook documents the exact steps required to go from a fresh clone of the GitHub repo to a working local setup and deployed infrastructure.

It is built incrementally.  
Each stage is added only after it has been validated on a real machine.

---

## Stage 1 — Clone the repo locally (Windows / PowerShell)

**Goal:** Create a local working copy of the repo in a predictable folder name.

1) In PowerShell, change into the parent directory where you want the repo folder created.

Example parent directory:

C:\Users\pmull\OneDrive\Desktop\AWSOrg\_github\website-iac\pulumi

2) Clone the repo and specify the target folder name:

git clone <repo-url> <target-folder-name>  
cd <target-folder-name>

Example:

git clone https://github.com/<org-or-user>/<repo>.git example-com-deployment  
cd example-com-deployment

3) Validate:

git status

**Pass condition:**  
git status runs successfully and shows you are on the expected branch with no errors.

---

## Stage 2 — Create & activate Python virtual environment (Windows / PowerShell)

**Goal:** Use an isolated Python environment for Pulumi dependencies.

From the repo root:

python -m venv .venv  
.\.venv\Scripts\Activate.ps1  
python --version  
pip --version  

**Pass condition:**

- PowerShell prompt shows `(.venv)`  
- python and pip commands return successfully

---

## Stage 3 — Create Pulumi stacks

**Goal:** Create the required Pulumi stacks for this website.

From the repo root (with venv active):

pulumi stack init example-com-network  
pulumi stack init example-com-staging  
pulumi stack init example-com-prod  

Validate:

pulumi stack ls  

**Pass condition:**

- Stack list includes:
  - example-com-network  
  - example-com-staging  
  - example-com-prod  
- No errors during stack creation

---

## Stage 4 — Install Python dependencies

**Goal:** Install all required Python dependencies for the Pulumi project.

From the repo root (with venv active):

pip install -r requirements.txt  

**Pass condition:**

- pip completes without errors  
- All listed packages are installed successfully
