# Maintainer Notes

This file is for deployment, publishing, and maintenance notes. `README.md` is the public GitHub-facing project page. Keep this file practical and maintainer-focused.

## Local Run

The app must be served over HTTP because it loads `data.json` and `tool-manuals.json` with `fetch()`.

```bash
python3 -m http.server 4173
```

Then open `http://127.0.0.1:4173/`.

## Deployment Options

This is a static project with no build step, so it can be deployed almost anywhere.

### GitHub Pages

- Push the repository to GitHub
- Enable GitHub Pages for the repository
- Publish from the repository root or the default branch, depending on the Pages setup you choose
- Make sure the static files stay in the root unless you intentionally reorganize the project

### Render

- Create a new static site
- Point it at this repository
- Use the repo root as the publish directory
- No build command is required

### Any Static Host

- Upload the project files as-is
- Serve `index.html`, `style.css`, `script.js`, `data.json`, and `tool-manuals.json` together
- Do not deploy in a way that strips access to the JSON files

## GitHub Push Flow

```bash
git add .
git commit -m "Initial playbook release"
git remote add origin <your-repo-url>
git push -u origin main
```

## Content Maintenance

- `data.json`: workflows, paths, entries, tags, notes, examples, and source metadata
- `tool-manuals.json`: curated manuals, syntax, parameter notes, flags, and related tools
- `script.js`: rendering, search logic, placeholder handling, routing, and UI behavior
- `style.css`: theme, spacing, component styling, and responsive layout

## Good Release Check

Before pushing or deploying:

- Confirm `node --check script.js` passes
- Confirm both JSON files parse cleanly
- Open the app through a local web server, not `file://`
- Test search for a few important tools and workflows
- Check the sidebar, dashboard, manual views, and copy buttons
- Make sure the README still matches the current app behavior

## Content Direction

The project is meant to stay useful for junior and mid-level pentesters, so keep the content:

- Practical instead of bloated
- Structured around real workflow stages
- Clear enough to use during an assessment
- Open to contributions without becoming messy


