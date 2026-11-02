# Security policy

## Reporting a vulnerability in MCPDoctor
Please use GitHub's private vulnerability reporting ("Security" tab -> "Report a vulnerability"). Do not open a public
issue for a security problem. Expect an acknowledgement within a week.

## What MCPDoctor does to the servers you point it at
`mcpdoctor scan` **runs the server and calls its tools**. Only scan servers you are allowed to test.
- By default tools that look destructive (names or annotations suggesting delete/write/send/exec) are skipped.
- The server runs with a fake `HOME`, an empty working directory and planted canary secrets, never your real ones.
- `--static-only` never calls a tool. `--sandbox` runs the server in a locked-down Docker container (no network,
  read-only filesystem, all capabilities dropped, non-root user).
- A server you start from a local command is still arbitrary code running as you unless you use `--sandbox`.

## Out of scope
A clean report is not a proof of safety. See "What MCPDoctor cannot tell you" in the README.
