# Pushing CertForge to GitHub

Follow these steps to push the CertForge project to the GitHub repository at https://github.com/osage-io/certforge:

## Prerequisites

1. Ensure you have Git installed
2. Have appropriate write access to the osage-io organization on GitHub

## Steps

1. Initialize the Git repository and add all files:

```bash
cd /Users/dfedick/sw/certforge
git init
git add .
```

2. Create the initial commit:

```bash
git commit -m "$(cat COMMIT_MSG.txt)"
```

3. Add the GitHub repository as the remote origin:

```bash
git remote add origin https://github.com/osage-io/certforge.git
```

4. Push to the main branch:

```bash
git push -u origin main
```

## GitHub Repository Setup

If the repository hasn't been created yet, you can create it first:

1. Go to https://github.com/organizations/osage-io/repositories/new
2. Set Repository name to "certforge"
3. Add the description: "Simple Binary for working with TLS Certificates"
4. Choose "Public" visibility
5. Do not initialize with a README, .gitignore, or license (we'll push these from our local repo)
6. Click "Create repository"

Then follow the steps above to push your local repository.

## Alternative: GitHub CLI

If you have the GitHub CLI (`gh`) installed, you can create the repository and push in one step:

```bash
cd /Users/dfedick/sw/certforge
gh repo create osage-io/certforge --public --description "Simple Binary for working with TLS Certificates" --source=. --push
```

## After Pushing

Once pushed, verify that all files appear correctly on the GitHub repository page. You may want to:

1. Set up branch protection rules
2. Enable GitHub Actions for CI/CD
3. Add collaborators
4. Set up issue templates

Remember to delete this file before pushing, as it's only meant for your reference.
