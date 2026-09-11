<!-- meta:title Documentation Guide -->
<!-- meta:description Architecture and maintenance guide for the Falcon MCP documentation. -->
<!-- meta:section development -->
<!-- meta:link-base /falcon-mcp/ -->

## Overview

This repository is the single source of truth for Falcon MCP documentation. The `docs/` directory contains standard GitHub-flavored Markdown with HTML comment annotations that an external documentation site uses to build the published pages. The annotations are invisible when rendered on GitHub.

For the full annotation reference, see [Content Tag Guide](/falcon-mcp/development/content-tag-guide/).

## Directory Structure

```text
docs/
  getting-started/         # Hand-authored: installation, credentials, config, quickstart
  usage/                   # Hand-authored: CLI, transports, editor integration, flight control
  modules/                 # AUTO-GENERATED: one page per Go module + overview
  deployment/              # Hand-authored: Docker, Amazon Bedrock, Google Cloud
  development/             # Hand-authored: contributing, module dev, resource dev, testing, this guide
  examples/                # Hand-authored: basic usage, MCP config
  changelog.md             # AUTO-GENERATED: copied from root CHANGELOG.md
```

Governance files (`CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`) live in `.github/`, not in `docs/`.

> [!CAUTION]
> Auto-generated files are overwritten on every build. Do not edit them by hand — your changes will be lost.

## Page Metadata

Every content file starts with HTML comment annotations that the external site uses for page metadata and rendering. These are invisible on GitHub.

Required tags at the top of every file:

```markdown
<!-- meta:title Page Title -->
<!-- meta:description A short description of the page. -->
<!-- meta:section getting-started -->
<!-- meta:link-base /falcon-mcp/ -->
```

Optional tags:

```markdown
<!-- frontmatter:sidebar order:10 -->
```

| Tag | Purpose |
|-----|---------|
| `meta:title` | Page title used on the documentation site |
| `meta:description` | Page description used on the documentation site |
| `meta:section` | Subdirectory this page belongs to (`getting-started`, `usage`, `modules`, `deployment`, `development`, `examples`) |
| `meta:link-base` | URL prefix for internal links (typically `/falcon-mcp/`) |
| `frontmatter:sidebar` | Sidebar ordering (e.g., `order:10`) |

## Admonitions

Use GitHub-flavored admonition syntax:

```markdown
> [!NOTE]
> This is a note.

> [!CAUTION]
> This is a caution.

> [!TIP]
> This is a tip.
```

These render natively on GitHub and get converted to Starlight `:::` directives by the external site's build process.

## Auto-Generated Content

### Module Pages

The generator `tools/gendocs` statically analyzes the Go source in `internal/modules/` and produces one page per module under `docs/modules/`, each containing:

- Title and description (title from the generator's metadata map; description from the module's `Description()` method)
- API scopes (traced from the `base.Scope` values each tool's handler passes to `base.APIError`)
- Tools with descriptions, per-tool scopes, annotations (read-only / mutating / destructive), and example prompts
- Resources with URIs and descriptions

### Module Overview Page

A summary table (`docs/modules/overview.md`) listing all modules with their API scopes and descriptions.

### Changelog

The root `CHANGELOG.md` is copied with annotation tags prepended. This happens in `scripts/build_docs.sh`.

### How Titles and Descriptions Are Derived

- **Title**: Looked up in the `moduleMetadata` map in `tools/gendocs/data.go`, keyed by the module's `Name()`. A module absent from the map falls back to a title-cased key.
- **Description**: Taken verbatim from the module's `Description()` method.
- **Slug** (output filename): From `moduleMetadata`, defaulting to the module key.

To override a title or slug, add or edit an entry in `moduleMetadata` in `tools/gendocs/data.go`.

## Adding a New Module to Docs

Nothing is needed. The generator discovers every package under `internal/modules/` (except `base` and `registry`) automatically. Any new module is picked up on the next `make generate`.

If you need a custom title or slug, add an entry to `moduleMetadata` in `tools/gendocs/data.go`:

```go
var moduleMetadata = map[string]meta{
    "mymodule": {title: "My Custom Title", slug: "my-module"},
}
```

To add example prompts for a tool, add entries to `toolExamples` in `tools/gendocs/examples.go`:

```go
var toolExamples = map[string][]string{
    "falcon_my_tool": {
        "Example prompt for the tool",
    },
}
```

## Adding or Editing Content Pages

Content pages live under `docs/`. Each `.md` file needs annotation tags at the top (see Page Metadata above). The external site handles sidebar configuration. Use the `frontmatter:sidebar` tag to control page ordering within each section.

The `modules/` directory is auto-generated; pages there don't need manual creation.

## Local Workflow

Generate module docs, copy the changelog, and lint all markdown:

```bash
bash scripts/build_docs.sh
```

This runs:

1. `make gen-docs` — regenerates `docs/modules/`
2. Copies `CHANGELOG.md` with annotation tags to `docs/changelog.md`
3. Runs `markdownlint` on all files under `docs/`

You can also regenerate the module docs directly:

```bash
make gen-docs
# or, alongside the other generators:
make generate
```

## CI Freshness Check

The `.github/workflows/docs-check.yml` workflow ensures module documentation stays in sync with the code. On pull requests that touch `internal/modules/`, `tools/gendocs/`, or `docs/`, the workflow:

1. Runs `make gen-docs`
2. Checks `git diff --exit-code docs/modules/`

If the committed module docs differ from what the generator produces, the check fails. This prevents stale documentation from being merged.

After adding or modifying a module, always regenerate and commit the updated docs:

```bash
make generate
git add docs/modules/
```
