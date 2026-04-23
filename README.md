# SshKeyNinja

A cross-platform CLI tool that generates SSH ED25519 key pairs in OpenSSH format, with optional passphrase encryption and automatic SSH agent integration.

## Features

- Generates ED25519 key pairs (OpenSSH `openssh-key-v1` format)
- Optional passphrase protection (AES-256-CTR + bcrypt KDF)
- Adds the key directly to the SSH agent (no re-entering the passphrase)
- Masked passphrase input with visual feedback
- Works on Windows, Linux, and macOS

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

## Build

```bash
git clone <repo-url>
cd SshKeyNinja
dotnet build
```

To create a self-contained executable:

```bash
# Windows
dotnet publish src/SshKeyNinja -c Release -r win-x64

# Linux
dotnet publish src/SshKeyNinja -c Release -r linux-x64

# macOS (Intel)
dotnet publish src/SshKeyNinja -c Release -r osx-x64

# macOS (Apple Silicon)
dotnet publish src/SshKeyNinja -c Release -r osx-arm64
```

The binary will be in `src/SshKeyNinja/bin/Release/net10.0/<rid>/publish/`.

## Usage

```
SshKeyNinja [options]
```

### Key Generation

| Option | Description |
|---|---|
| `-C <comment>` | Key comment (default: `user@hostname`) |
| `-f <path>` | Output file path (default: `~/.ssh/id_ed25519`) |
| `-N <passphrase>` | Set passphrase non-interactively |
| `-P <1-16>` | Generate a Diceware passphrase and encrypt the key |
| `-PP <1-16>` | Same as `-P` but also displays the passphrase |
| `--no-agent` | Don't add the key to the SSH agent |

### Passphrase Only

| Option | Description |
|---|---|
| `-P <1-16> --no-keygen` | Generate a passphrase only (copy to clipboard) |
| `-PP <1-16> --no-keygen` | Same but also displays the passphrase |

### Agent Management

| Option | Description |
|---|---|
| `-x` | Remove keys from the SSH agent interactively |

### Examples

Generate a key with interactive passphrase prompt:

```bash
dotnet run --project src/SshKeyNinja
```

Generate a key with a specific comment and file path:

```bash
dotnet run --project src/SshKeyNinja -- -C "me@example.com" -f ~/.ssh/id_github
```

Generate a key with an auto-generated 5-word passphrase:

```bash
dotnet run --project src/SshKeyNinja -- -PP 5
```

Generate only a passphrase (no key):

```bash
dotnet run --project src/SshKeyNinja -- -PP 6 --no-keygen
```

Set passphrase non-interactively (e.g. in scripts):

```bash
dotnet run --project src/SshKeyNinja -- -N "mypassphrase" -f ~/.ssh/id_deploy
```

## SSH Agent

By default, the generated key is added to the running SSH agent automatically. This works via the native agent protocol:

- **Windows** -- connects to the OpenSSH Authentication Agent service via named pipe. Make sure the service is running (`Get-Service ssh-agent`).
- **Linux / macOS** -- connects via the `SSH_AUTH_SOCK` Unix domain socket. Make sure `ssh-agent` is running.

Use `--no-agent` to skip this step.

## Project Structure

```
SshKeyNinja/
  src/SshKeyNinja/
    Program.cs              # CLI entry point
    OpenSshKeyWriter.cs     # OpenSSH key format serialization
    BcryptPbkdf.cs          # bcrypt_pbkdf key derivation (ISC License)
    SshAgentClient.cs       # SSH agent protocol client
    PassphraseGenerator.cs  # Diceware passphrase generator
    SshKeyNinja.csproj      # Project file
  SshKeyNinja.sln           # Solution file
  LICENSE                   # MIT License
  THIRD-PARTY-NOTICES.md    # Third-party license notices
```

## Wordlists

This software uses the "EFF Large Wordlist" (© 2016 Electronic Frontier Foundation),
licensed under the Creative Commons Attribution 3.0 License (CC-BY 3.0).  
→ https://creativecommons.org/licenses/by/3.0/  
→ Original: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

## License

MIT -- see [LICENSE](LICENSE).

This project uses third-party libraries. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for details.
