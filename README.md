# WIP: PhantomSocket 0.3.0

A **modular**, **obfuscatable** SOCKS-based proxy framework designed for censorship-circumvention research.

---

## 1 · Key Ideas

| Layer | Responsibility | Typical Classes (src/…) |
|-------|----------------|-------------------------|
| **Listener** | Accept raw TCP/UDP connections and hand them off | `listener/TcpListener` |
| **Handler** | Do protocol hand-shake / auth and decide target | `handler/Socks5ClientHandler`, `handler/Socks5ServerHandler` |
| **Session** | Bi-directional data pump (select / asyncio) | `session/Session` |
| **Interceptor** | Transform each **frame** (compress, encrypt, obfuscate, log…) | everything in `interceptors/` |
| **Transport Adapter** | Optional extra wrapping (TLS, WS, QUIC…). Default is plain TCP | `transport/PlainTCPAdapter` |

> Add a **new protocol** → implement a new *Handler* (and maybe a *TransportAdapter*).  
> Add a **new obfuscation / crypto** → implement a new *Interceptor*.  
> Other layers stay untouched.

---

## 2 · Installation

```bash
# clone & editable-install
git clone https://github.com/Phantom0day/PhantomSocket.git
cd PhantomSocket && pip install -e .
````

Requires **Python ≥ 3.8** (tested on 3.11).

---

## 3 · Quick Start

### Run remote server

```bash
python run.py server  -c configs/default.yaml
```

### Run local SOCKS5 proxy

```bash
python run.py local   -c configs/default.yaml \
                      --server-host <REMOTE_IP>
```

Point applications at **127.0.0.1:1080** for SOCKS5.

> Add `-v` for verbose logs; use `--profile basic_obfuscation` to switch interceptor sets.

---

## 4 · Configuration Cheat-Sheet (`config.yaml`)

```yaml
server:
  host: 0.0.0.0      # bind interface
  port: 8388

local:
  host: 127.0.0.1    # local SOCKS5 bind
  port: 1080
  server_host: 203.0.113.1   # <-- remote server
  server_port: 8388

general:
  log_level: INFO    # DEBUG for full dump

active_profile: basic_obfuscation   # which profile below is active

profiles:
  basic_obfuscation:
    interceptors:
      - name: PacketLogger
        options: {log_level: "debug"}
      - name: ObfuscationInterceptor
        options: {prefix: "\u0000\u00ff", suffix: "\u00ff\u0000"}
```

Every interceptor can be toggled on/off or given its own options.

---

## 5 · Writing Interceptors (Example)

```python
from src.interceptors.core import BaseInterceptor

class CaesarShift(BaseInterceptor):
    def __init__(self, shift=3):
        self.shift = shift

    def pack(self, ctx):
        ctx.data = bytes((b + self.shift) % 256 for b in ctx.data)
        return ctx

    def unpack(self, ctx):
        ctx.data = bytes((b - self.shift) % 256 for b in ctx.data)
        return ctx
```

Add it to a profile and run—no other code changes needed.

---

## 6 · Directory Layout (core parts)

```
├── src/
│   ├── listener/      # TcpListener etc.
│   ├── handler/       # protocol hand-shake
│   ├── session/       # select-loop data pump
│   ├── interceptors/  # obfuscation / crypto / log
│   ├── transport/     # PlainTCPAdapter / future TLS
│   └── proxy/         # glue code (ClientProxy / ServerProxy)
└── configs/           # sample yaml profiles
```

---

## 7 · Roadmap

* 🔒 TLS / gRPC transport adapters
* 🚀 UDP-associate & QUIC backend
* 📈 Prometheus metrics export

---

## 8 · Disclaimer & License

PhantomSocket is MIT-licensed and intended **solely for legitimate privacy protection and research**. Users are responsible for complying with local laws.
