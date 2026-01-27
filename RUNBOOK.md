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

pulumi logout
pulumi login s3://pmullins-iac-state
git clone https://github.com/jub-jub-bird/website-s3-cf-cognito-lambda.git mullinsfam-co-uk
cd .\mullinsfam-co-uk\
python -m venv .venv
.venv\Scripts\Activate.ps1
python.exe -m pip install --upgrade pip
pip install -r requirements.txt

python .\scripts\config_init.py --domain mullinsfam.co.uk --force

pulumi stack init mullinsfam-co-uk-network
pulumi stack init mullinsfam-co-uk-staging
pulumi stack init mullinsfam-co-uk-prod

python .\scripts\create_secrets.py --domain mullinsfam.co.uk --force
python .\scripts\config_init.py --domain mullinsfam.co.uk --force --inject-secrets

aws sso login --profile 954837761502_AdministratorAccess
$env:AWS_PROFILE="954837761502_AdministratorAccess"

pulumi up -s mullinsfam-co-uk-prod
pulumi up -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-network

pulumi config set mullinsfam-co-uk:enableCustomDomain true -s mullinsfam-co-uk-prod
pulumi config set mullinsfam-co-uk:enableCustomDomain true -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-prod
pulumi up -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-network

pulumi config set mullinsfam-co-uk:enableCognitoDomain true -s mullinsfam-co-uk-prod
pulumi config set mullinsfam-co-uk:enableCognitoDomain true -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-prod
pulumi up -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-network

pulumi config set mullinsfam-co-uk:enableAuthApiDomain true -s mullinsfam-co-uk-prod
pulumi config set mullinsfam-co-uk:enableAuthApiDomain true -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-prod
pulumi up -s mullinsfam-co-uk-staging
pulumi up -s mullinsfam-co-uk-network
