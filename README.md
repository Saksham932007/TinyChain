# 🪙 TinyChain — Minimal Blockchain with REST + PoA/PoS + Gossip + Merkle Proofs

TinyChain is an **educational blockchain prototype** written in pure Python.  
It demonstrates the core building blocks of a blockchain system in less than a single file:

- ✅ REST API (FastAPI) — submit transactions, query chain, register peers  
- ✅ Consensus — Proof-of-Authority (PoA, default) or Proof-of-Stake (PoS, simple demo)  
- ✅ Merkle Root — transaction integrity & efficient proofs  
- ✅ Peer-to-Peer Gossip — broadcast blocks and resolve forks with the longest valid chain  
- ✅ Minimal & Readable — designed for learning, hacking, and extending  

> ⚠️ **Disclaimer:** This is **not** production-ready blockchain software.  
> It is intended for learning purposes only.

---

## 🚀 Features

- **REST API** for interaction:
  - `POST /transactions/new` → add a transaction  
  - `GET /chain` → fetch the full chain  
  - `POST /nodes/register` → register peer nodes  
  - `POST /nodes/receive_block` → accept gossiped blocks  
  - `POST /nodes/resolve` → resolve conflicts via longest valid chain  
  - `POST /propose_signed` → propose a new signed block  

- **Consensus**
  - **Proof-of-Authority (PoA):** Authorities sign blocks with a secret key (HMAC in demo, ECDSA recommended for real systems).  
  - **Proof-of-Stake (PoS):** Weighted leader election demo, proportional to registered stake.  

- **Merkle Root** stored in each block header for transaction proofs.  

- **Peer-to-Peer Gossip** outline: nodes broadcast new blocks to peers, peers accept or request chain resolution.

---

## 🛠 Installation

```bash
git clone https://github.com/<your-username>/tinychain.git
cd tinychain
pip install -r requirements.txt
