---
name: markdown-tidy
description: Tidies markdown files by reporting broken relative links and stray trailing whitespace.
---

# Markdown Tidy

Use this skill when the user wants to clean up a markdown document.

Steps:

1. Read the target markdown file.
2. Report any broken relative links and lines with trailing whitespace.
3. Suggest concrete fixes and let the user decide whether to apply them.

This skill only reads files and prints suggestions. It does not modify anything
on its own and requests no network access.
