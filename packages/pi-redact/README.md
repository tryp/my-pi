# @spences10/pi-redact

<!-- package-readme:header:start -->

[![built with Vite+](https://img.shields.io/badge/built%20with-Vite+-646CFF?logo=vite&logoColor=white)](https://viteplus.dev)
[![tested with Vitest](https://img.shields.io/badge/tested%20with-Vitest-6E9F18?logo=vitest&logoColor=white)](https://vitest.dev)
[![npm version](https://img.shields.io/npm/v/@spences10/pi-redact?color=CB3837&logo=npm&logoColor=white)](https://www.npmjs.com/package/@spences10/pi-redact)
[![license](https://img.shields.io/npm/l/@spences10/pi-redact)](https://www.npmjs.com/package/@spences10/pi-redact)

![my-pi package preview](https://raw.githubusercontent.com/spences10/my-pi/main/assets/pi-package-preview.png)

<!-- package-readme:header:end -->

Prevent accidental secret exposure before tool output reaches the
model. `pi-redact` scans command results for likely tokens, keys, and
credentials, replacing them with safe placeholders while preserving
enough context to debug.

## Installation

<!-- package-readme:install:start -->

```bash
pi install npm:@spences10/pi-redact
```

<!-- package-readme:install:end -->

Local development from this monorepo:

```bash
pnpm --filter @spences10/pi-redact run build
pi install ./packages/pi-redact
# or for one run only
pi -e ./packages/pi-redact
```

## What it does

`@spences10/pi-redact` listens for Pi `tool_result` events and
rewrites text content before it is added to model context. It is
intended as a last-mile safety net for accidental secrets in command
output, file reads, logs, and config files.

It currently detects and redacts:

- quoted JSON and unquoted environment/config fields with sensitive
  names such as `password`, `client_secret`, `access_token`, and
  `api_key`, including values containing shell punctuation
- GitHub, GitLab, Slack, npm, Google, SendGrid, JWT, and common
  vendor-prefixed tokens
- AWS credentials, bearer tokens, and connection strings with embedded
  credentials
- private-key blocks in complete native `read` inputs, including an
  unterminated block through EOF
- SSH config metadata such as `Host`, `HostName`, `User`,
  `IdentityFile`, `ProxyJump`, and forwarding directives

Redactions preserve a short prefix where helpful and append a marker
such as `[REDACTED:GitHub Token]`.

## Commands

### `/redact-stats`

Shows how many values were redacted in the current Pi session.

```text
/redact-stats
```

## Example

If a tool returns:

```text
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890
```

The model receives something like:

```text
GITH********************[REDACTED:GitHub Token]
```

## Using from a custom harness

```ts
import redact from '@spences10/pi-redact';

// pass `redact` as an ExtensionFactory to your Pi runtime
```

`my-pi` imports this package directly and enables it as the built-in
`filter-output` extension. When active with a host that supports
`registerReadTextProcessor`, native `read` input is processed in full before
line and byte selection, so a middle-of-file read is redacted without relying
on previous calls. The host bounds processor input and fails closed if
processing fails. Legacy/custom tools handled only through `tool_result` do
not receive this whole-input-before-slice guarantee.

## Limitations

This extension is defensive, not a guarantee. Recognized credential candidates are consumed independently of length, but recognition remains heuristic and does not discover every unlabelled, encoded, obfuscated, or dynamically assembled secret. The native read processor receives a bounded complete text snapshot (currently limited by the host to 16 MiB) and applies all classifiers before selection; scanning/output allocation is O(n), not unlimited-memory streaming. File reads are not atomic snapshots against a hostile same-user writer: host metadata checks may detect ordinary observable changes but cannot prove stability or prevent same-size overwrite/metadata restoration, hardlink, or unusual-filesystem races. Do not treat this extension or those checks as a security boundary. Other tools and custom read backends processed through `tool_result` may provide only partial text and do not have the native-read guarantee. The extension intentionally does not blanket-redact unlabelled base64, compressed, encrypted, or other high-entropy output because source archives, hashes, and build artifacts commonly have the same shape. Broad patterns can also occasionally redact benign values.

Use proper secret hygiene as the primary control:

- do not print or encode secrets unnecessarily
- avoid reading `.env` files into model context; prefer `nopeek` for
  secret-safe environment loading
- prefer scoped, revocable tokens
- rotate anything that may have been exposed

## Development

<!-- package-readme:development:start commands="check,test,build" -->

Package scripts build transitive workspace dependencies first, then
run local tools through Vite+ with `vp exec`.

```bash
pnpm --filter @spences10/pi-redact run check
pnpm --filter @spences10/pi-redact run test
pnpm --filter @spences10/pi-redact run build
```

<!-- package-readme:development:end -->

## License

MIT
