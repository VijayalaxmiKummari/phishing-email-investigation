# How to Upload This Project to GitHub

Two ways to do it. Option A needs no commands. Option B uses Git in the Terminal, which is the skill employers expect, so try it when you feel ready.

## Before you start

1. Create a free account at https://github.com if you do not have one.
2. Unzip the project so you have a folder called `phishing-email-investigation` on your computer.

## Option A - Upload in the browser (easiest)

1. Sign in to GitHub. Click the **+** in the top right corner and choose **New repository**.
2. **Repository name:** `phishing-email-investigation`
3. **Description:** `SOC analyst project: phishing email analysis, IOC extraction and incident report`
4. Choose **Public** so employers can see it.
5. Leave "Add a README", ".gitignore" and "licence" **unticked**. The project already has them.
6. Click **Create repository**.
7. On the next page, click the link **uploading an existing file**.
8. Open the `phishing-email-investigation` folder on your computer, select **everything inside it** (on a Mac press `Cmd + A`), and drag it into the browser window. The folders keep their structure.
9. In the "Commit changes" box type `Add phishing email investigation project` and click **Commit changes**.

Hidden files such as `.gitignore` may not be picked up by drag and drop. That is fine for this project.

## Option B - Upload with Git (recommended once you are comfortable)

### 1. Tell Git who you are (once per computer)

```bash
git config --global user.name "Your Name"
git config --global user.email "the-email-on-your-github-account"
```

### 2. Create an empty repository on GitHub

Follow steps 1 to 6 of Option A. Leave the page open; it shows your repository address.

### 3. Push the project

In the Terminal:

```bash
cd ~/Documents/phishing-email-investigation
git init
git add .
git commit -m "Add phishing email investigation project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/phishing-email-investigation.git
git push -u origin main
```

What each line does:

| Command | Meaning |
|---|---|
| `git init` | Start tracking this folder with Git |
| `git add .` | Select every file for the next save |
| `git commit -m "..."` | Save a snapshot with a message |
| `git branch -M main` | Name the main branch `main` |
| `git remote add origin ...` | Tell Git where the GitHub repository is |
| `git push -u origin main` | Upload the snapshot to GitHub |

### 4. If Git asks for a password

GitHub does not accept your account password here. Use a personal access token:

1. On GitHub go to **Settings > Developer settings > Personal access tokens > Tokens (classic)**.
2. Click **Generate new token (classic)**, tick **repo**, and generate it.
3. Copy the token and paste it when the Terminal asks for a password. Nothing appears as you paste; that is normal.

Keep the token private. Never put it in a file in your repository.

## After uploading

1. Open the repository page and check the README shows with its tables.
2. In `README.md`, replace `YOUR-USERNAME` in the clone command with your GitHub username. Click the pencil icon on the file to edit it in the browser.
3. On the repository page click the cog next to **About** and add topics: `cybersecurity`, `phishing`, `soc-analyst`, `incident-response`, `python`, `blue-team`.
4. On your GitHub profile, click **Customize your pins** and pin this repository.

## Share it on LinkedIn

Add it under **Projects** on your profile and write a short post. A starting point:

> I have just finished a phishing email investigation project. I analysed a suspicious email's headers, checked SPF, DKIM and DMARC, traced its route, extracted and defanged the indicators, mapped it to MITRE ATT&CK and wrote an incident report. I also built a small Python tool that automates the triage.
>
> Project: [your repository link]
>
> #cybersecurity #SOC #phishing #blueteam
