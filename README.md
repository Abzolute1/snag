# snag

P2P file sharing from your terminal. No accounts, no cloud, files go directly between computers.

Uses QUIC for transport, end-to-end encrypted with a SPAKE2 + Noise handshake. NAT traversal is automatic (UPnP, NAT-PMP, STUN, hole punching) so most transfers connect directly without needing a relay.

## Install

```
curl -sSL https://abzolute1.github.io/snag/install.sh | sh
```

On Windows (PowerShell):
```
irm https://abzolute1.github.io/snag/install.ps1 | iex
```

Or build from source with `cargo build --release`.

## Usage

Send some files from a directory:
```
snag send report.pdf
```

Send a file not being inside the directory:
```
snag send /home/Abzolute1/Documents/report.pdf
```

You get a share code + QR code. Give that to whoever's receiving.

Receive with the full command or the short alias:
```
snag receive fox-ram-log-K7XM9PR2
snag r fox-ram-log-K7XM9PR2
```

Running `snag` with no arguments opens an interactive TUI dashboard.

Short aliases: `s` = send, `r` = receive, `d` = discover, `u` = update, `cfg` = config

A few more things you can do:
```
snag s file.zip --timer 30m          # stop sharing after 30 min
snag s homework.pdf --downloads 3    # stop after 3 downloads
snag r CODE -o ~/Downloads           # receive to a specific dir
snag r CODE -y                       # skip the confirmation prompt
snag discover                        # find peers on your LAN
```

Check `snag --help` and `snag send --help` etc. for the full flag list.

## How it works

Both sides authenticate with a SPAKE2 exchange derived from the share code, then set up a Noise_XXpsk3 session. File data goes through ChaCha20-Poly1305 in chunks, each verified with BLAKE3. Compression is zstd.

For NAT traversal, snag tries a bunch of things before falling back to a relay: UPnP port mapping, NAT-PMP, STUN discovery + hole punching, and port prediction for symmetric NATs. In practice, most connections end up being direct.

## Config

```
snag config > ~/.config/snag/config.toml
```

## License

MIT or Apache-2.0.

---

Inspired by [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole). Built from scratch in Rust with direct P2P connections instead of relying on relay servers.
