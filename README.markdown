# chi-nah

A [chi](https://github.com/dm1try/samagotchi) bundle that runs [nah](https://github.com/manuelschipper/nah)'s
deterministic guards on the shell and file calls a chi session makes.

nah reads a call (a shell command, a file read or write) as typed effects on the real cwd and repo, and runs
its guards over them. It answers only **block** or **delegate**. It never approves a call, so installing this
bundle can't widen what chi allows. A delegated call goes on to chi's own allow / ask / deny rules, as if the
bundle weren't there.

It is opt-in protection for the riskier setups: small or unfamiliar models, unattended or delegated sessions,
`--non-interactive` runs, long autonomous chains.

## Install

1. Install nah (macOS or Linux, one static binary in `~/.local/bin`):

   ```sh
   curl -fsSL nahguard.ai/install | sh
   ```

2. Install the bundle:

   ```sh
   chi bundle install https://github.com/dm1try/chi-nah            # the main branch
   chi bundle install https://github.com/dm1try/chi-nah#v0.1.0     # a tag
   ```

3. Point chi at nah by its absolute path (recommended, see [PATH](#path)), in `~/.config/samagotchi/config.yml`:

   ```yaml
   bundles:
     chi-nah:
       bin: ~/.local/bin/nah
   ```

4. Restart running sessions' workers: a worker loads bundle hooks when it starts.

`chi bundle status chi-nah` shows the bundle; `chi bundle upgrade chi-nah` pulls a newer version;
`chi bundle uninstall chi-nah` removes it.

The bundle has no `trust_level`, so chi lists it as *experimental*. That is deliberate: a bundle that isn't
shipped with chi can't vouch for itself. Read [`hooks/nah_guard.rb`](hooks/nah_guard.rb) before installing; it
is under 300 lines and runs inside chi.

## What it checks

| chi tool | sent to nah as |
|---|---|
| `execute`, `task_create` | `Bash {command}` (in the call's own `cwd:`) |
| `read` | `Read {file_path}` |
| `write` | `Write {file_path, content}` |
| `edit` | `Edit {file_path, old_string, new_string}` |

Paths are sent as chi resolves them (absolute). Every other tool (memory, web, delegate, MCP, plugin tools) is
not checked and starts no process.

A block comes back to the model as chi's usual guardrail denial, with nah's guard names as the rule and a
last clause on how you pause them:

```
[execute] Error: denied by guardrail (rule git-clean-force, git-hard-reset, nah): git-clean-force blocked a forced
clean selecting the project root; …; git-hard-reset blocked git reset --hard; …; the user can pause them with
`nah nap git-clean-force git-hard-reset` in their own terminal. The user was not asked. Do not retry it or reach
the same result another way; ask the user how to proceed.
```

A block by nah's self-protection names no guard and gets no such clause (its reason already says how).

The bundle also installs a short memory, `chi_nah`, that tells the model a block is final and to name the
guard to you.

### Blocked and delegated (nah 1.6.1, default guards)

Blocked:

- secrets: reading `.env` or `~/.ssh/id_*`, `cat .env | curl …` (exfiltration)
- `rm -rf ~`, `rm -rf <the project root>`
- `git reset --hard`, `git clean -fd`, `git restore .`, `git push --force` without a lease
- remote code: `curl … | sh`, base64-decoded text piped to a shell
- Python's `shutil.rmtree` on the home folder
- the agent changing nah itself (`nah guard disable …`, `nah nap`, writes under `~/.nah`)

Delegated (left to chi's rules):

- everyday work: `git status`, `git commit`, `git push`, `bundle exec rspec`, `rm -rf node_modules`,
  ordinary reads, writes and edits, `.env.example`
- chi's own files: writes to `~/.config/samagotchi/…` (memories, config.yml, hooks) and to session files.
  chi asks about its own config and hooks itself.
- guards that are off by default: `rm -rf ../sibling` (`fs-outside-workspace-delete`), `gem push`
  (`registry-publish`), `kubectl delete ns` (`infra-k8s-delete`), a write to `~/.zshrc` (`fs-shell-profile`)

`nah guards` lists every guard and whether it is on (29 of 47 in 1.6.1).

## Settings

All optional, under `bundles: chi-nah:` in config.yml:

| key | default | meaning |
|---|---|---|
| `bin` | `nah` | the nah executable; an absolute path or `~/…` is safest |
| `timeout` | `2` | seconds for one decision (writing the call, running nah, reading its answer) |
| `unavailable` | `notify` | what happens when nah gives no decision: `notify`, `ask` or `deny` |
| `tools` | all five | only check these of `execute`, `task_create`, `read`, `write`, `edit` |

### When nah gives no decision

"No decision" is anything other than a clean block or delegate: nah missing, a timeout (nah is killed), exit 3
(nah's own "no decision", which a panic inside nah also reports), an answer that doesn't parse or has an
unexpected shape, or an error inside the hook.

- `notify` (default): the call goes on to chi's own rules, and one warning line says nah was skipped. It shows
  once per chi process; later misses only go to chi's log.
- `ask`: you are asked about each such call. The approval is offered for this call or this session only, so a
  standing rule can't hide later failures.
- `deny`: the call is denied. Use it for unattended runs that must fail closed.

`deny` covers everything that happens while the hook runs. It can't cover a hook that never loads (its file
edited after install, so its checksum no longer matches; a Ruby error at load): chi then reports the hook as not
loaded and runs without it. To have chi deny every tool call in that case too, install your own copy with
`on_error: fail_closed` on the hook in `manifest.yml`:

```sh
git clone https://github.com/dm1try/chi-nah && cd chi-nah
sed -i.bak 's/on_error: log/on_error: fail_closed/' manifest.yml
chi bundle install .
```

### PATH

A worker started by `chi web` or the desktop helper may have a shorter `PATH` than your shell (no
`~/.local/bin`). Set `bin:` to an absolute path. chi's `needs:` check only looks at `PATH`, so with a custom `bin:`
`chi bundle status chi-nah` and the `[needs nah: not found on PATH]` mark on the memory's index line can say nah
is missing while the hook works. The hook's own warning (above) is the real signal.

## When nah blocks something you need

nah keeps its state in `~/.nah`. From your own terminal (never the agent's):

```sh
nah log                          # recent decisions; chi's show under the runtime "unknown"
nah log --blocked
nah why <decision-id>            # the full explanation of one
nah nap secrets-env              # pause one guard for ten minutes
nah guard disable secrets-env    # turn it off (nah guard reset secrets-env restores it)
nah tui                          # guards, trusted projects, recent decisions
```

The `.env` block is the one most likely to get in the way: a project that reads its own `.env` legitimately
needs `secrets-env` napped or disabled.

## Limits

- **Not a sandbox.** nah sees the call's text, not what the command does when it runs. A script that reads a
  secret once it runs, or a tool chi doesn't send to nah, isn't covered.
- **Speed:** each checked call starts one `nah decide` process, about 50–60 ms on an Intel i7 laptop. That's
  small next to a model turn; it adds up only in very long, tool-heavy turns. Use `tools:` to check fewer.
- nah moves fast. This bundle relies only on nah's `decide` contract (JSON in, `nah/decide/v1` out, exit 1
  block / 2 delegate). If that changes, nah's answers become "no decision" and the `unavailable` setting
  applies; nothing is let through as a block would have been without a warning.

## Development

```sh
ruby -Itest test/nah_guard_test.rb    # a fake nah (test/fake/nah), no chi needed
script/sha                            # after editing the hook or the memory: refresh manifest.yml's checksums
```

chi installs every top-level `*.md` file of a bundle as a memory, which is why this file is `README.markdown`.

## License

MIT, as is nah.
