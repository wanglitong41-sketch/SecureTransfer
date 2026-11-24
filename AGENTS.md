# Repository Guidelines

## Scope and Design References

SecureTransfer is a Windows-native coursework application using Vue 3, TypeScript, Node.js, WSS, and SQLite. Follow `docs/PLAN.md` for the seven development stages, `docs/技术规格.md` for protocol and acceptance rules, and `docs/DESIGN_AND_REPORT.md` for reporting. Resolve conflicts explicitly before implementation. Keep solutions appropriate to a local, single-process experiment. Stage six must include public-key login and per-user bandwidth limits; see `docs/EXTENSIONS_DESIGN.md`.

## Project Structure & Module Organization

The npm workspace layout is:

- `apps/web/`: Vue interface and browser assets.
- `apps/server/`: HTTPS/WSS, authentication, sessions, owned files, and chunked transfers.
- `packages/protocol/`: shared constants, codecs, types, and request validation.
- `tests/`: integration and browser tests; colocate focused unit tests with modules.
- `scripts/`: PowerShell setup, certificates, permissions, and launch helpers.
- `docs/evidence/`: reproducible test results and sanitized screenshots.
- `runtime/`: generated database, storage, temporary uploads, and logs; exclude from Git.

## Build, Test, and Development Commands

Use Node.js 26.13.1 and PowerShell. See `docs/STAGE_1.md` for setup and `docs/STAGE_4.md` for transfers and `docs/STAGE_5.md` for deployment:

- `npm ci`: install locked dependencies after the lockfile exists.
- `npm run dev`: start HTTPS development services.
- `npm run build`: compile shared protocol, backend, and frontend.
- `npm run start`: serve the built application at `https://localhost:8443`.
- `npm test`: run Vitest unit and integration tests.
- `npm run test:e2e`: run Playwright browser tests.
- `npm run test:long`: verify 60-second WSS idle keepalive with a real authenticated session.

Document actual prerequisites and verify commands before reporting success.

## Coding Style & Naming Conventions

Use strict TypeScript, two-space indentation, camelCase functions/variables, PascalCase types and Vue components, and UPPER_SNAKE_CASE protocol constants. Keep protocol definitions shared. Use `npm run lint` and `npm run format:check` for ESLint/Prettier checks. Prefer small modules and mature libraries over custom cryptography.

## Testing Guidelines

Use `*.test.ts` for Vitest and `*.spec.ts` for Playwright. Cover protocol boundaries, authorization, transfer integrity, retries, and relevant failure paths. Follow specification acceptance criteria; no percentage coverage target is defined. Save real evidence and distinguish passed, failed, and skipped checks.

## Commit & Pull Request Guidelines

Git is initialized; no commit history exists yet. Adopt focused imperative commits, such as `feat(protocol): add header codec`. PRs should describe behavior, stage, validation, and remaining limitations; link relevant issues and include screenshots for interface changes. Synchronize affected specifications and tests.

## Security and Agent Workflow

Preserve certificate verification, ownership checks, and parameterized SQL. Never commit private keys, tokens, passwords, or runtime data. Bind services to loopback. Keep audit records free of secrets. Apply deployment ACLs only to a prepared isolated checkout; a WhatIf check is not restricted-account evidence. Complete and verify the current stage before advancing; report changes, evidence, and unresolved issues without inventing results.
