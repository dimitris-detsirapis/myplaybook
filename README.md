# my pl4yb00k

`my pl4yb00k` is an open pentester's playbook built for fast access during assessments. It combines tool manuals, saved commands, workflow notes, flags, parameters, and quick references into one searchable interface so operators can spend less time digging through scattered notes and more time working methodically.

The project is aimed at junior and mid-level pentesters, but it is built to be useful for anyone who wants a cleaner, faster, more structured way to move through common testing tasks.

[![Live Demo](https://img.shields.io/badge/Live_App-Click_Here-2ea44f?style=for-the-badge)](https://dimitris-detsirapis.github.io/myplaybook/)

## Why I Made It

Most pentesting notes become hard to use under pressure. Commands live in one file, tool flags live somewhere else, manuals are half-remembered, and workflow steps disappear across too many tabs.

This project was made to solve that problem by turning a personal operator knowledge base into a structured playbook:

- Fast to search
- Easy to expand
- Clear enough to use during live work
- Practical enough to help newer pentesters build better habits

## What It Does Well

- Search across tools, workflows, flags, parameters, notes, and saved examples
- Support typo-tolerant search so rushed queries still land on useful results
- Group commands inside real workflow stages instead of dumping them into a flat cheat sheet
- Attach compact manuals, syntax guidance, flags, and related tools to the same workflow view
- Surface reusable command inputs like `<TARGET>` or `<DOMAIN>` inside tool manuals
- Stay lightweight and portable because the app is fully static

## How It Was Built

The app is built with plain HTML, CSS, and JavaScript.

- `index.html` provides the shell and layout
- `style.css` defines the visual system, layout, and responsive behavior
- `script.js` handles rendering, routing, search, copy actions, parameter extraction, and UI state
- `data.json` stores the workflows, entries, metadata, and navigation structure
- `tool-manuals.json` stores curated tool manuals, parameter notes, flags, and related-tool references

There is no framework, no build step, and no backend. That keeps the playbook easy to host, easy to edit, and easy for contributors to understand.

## Project Structure

- `Scoping & Setup` for evidence handling, request replay, proxy setup, and clean baselines
- `Recon & Surface Mapping` for discovery, application mapping, service review, and footprinting
- `Validation & Attack Surface` for content discovery, auth testing, stack-specific checks, and focused validation
- `Active Directory & Domain Ops` for enumeration, Kerberos, relay, coercion, AD CS, and domain execution workflows
- `Exploitation & Access` for injection, API work, SQLi automation, and framework-assisted exploitation
- `Post-Exploitation & Escalation` for credential operations, staging, pivoting, and privilege escalation

## Live Version on GitHub Pages

🌍 **Live Demo:** [Click here to use my pl4yb00k](https://dimitris-detsirapsi.github.io/my-playbook/)

## Running The App Locally

This is a static app, but it still needs to be served through a local web server. A simple python http server would be enough.

Important: do not open `index.html` directly with `file://`. The app loads `data.json` and `tool-manuals.json` with `fetch()`, and modern browsers block those requests for local files.

```bash
python3 -m http.server 4173
```

Then open `http://127.0.0.1:4173/`.

## Contributing

Contributions are welcome. The goal is to keep this useful as an open, practical project for pentesters who want fast access to commands, workflow context, and tool knowledge without losing clarity.

- Add or improve commands and workflows in `data.json`
- Expand manuals, parameters, flags, and notes in `tool-manuals.json`
- Keep explanations practical, readable, and useful during live work
- Prefer clean, scoped changes over giant content dumps
- Use sources that support authorized security testing and defensive learning

## Usage Note

Use this playbook only on systems you own or are explicitly authorized to assess.
