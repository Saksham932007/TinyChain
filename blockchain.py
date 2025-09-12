import hashlib, json, time, hmac, secrets
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, AnyHttpUrl
import threading

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def merkle_root_from_list(items: List[str]) -> str:
    if not items:
        return sha256_hex("")
    layer = [sha256_hex(item) for item in items]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256_hex(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

@dataclass
class BlockHeader:
    index: int
    timestamp: float
    previous_hash: str
    merkle_root: str
    signer: Optional[str] = None
    extra: Optional[dict] = None
    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

@dataclass
class Block:
    header: BlockHeader
    transactions: List[dict]
    signature: Optional[str] = None
    def compute_hash(self) -> str:
        header_json = self.header.to_json()
        tx_json = json.dumps(self.transactions, sort_keys=True)
        return hashlib.sha256((header_json + tx_json).encode()).hexdigest()

class TinyChainNetwork:
    def __init__(self, node_id: str, authorities: Dict[str, str]=None, use_pos: bool=False, stakes: Dict[str,int]=None):
        self.node_id = node_id
        self.chain: List[Block] = []
        self.current_transactions: List[dict] = []
        self.peers: set = set()
        self.authorities = authorities or {}
        self.use_pos = use_pos
        self.stakes = stakes or {}
        self.lock = threading.Lock()
        self.create_genesis()

    def create_genesis(self):
        header = BlockHeader(0, time.time(), "0", merkle_root_from_list([]), signer="genesis", extra={})
        genesis = Block(header, [], signature=None)
        self.chain = [genesis]

    def last_block(self) -> Block:
        return self.chain[-1]

    def submit_transaction(self, tx: dict):
        self.current_transactions.append(tx)
        return True

    def build_header(self, signer: Optional[str]=None, extra: Optional[dict]=None, timestamp: Optional[float]=None) -> BlockHeader:
        merkle = merkle_root_from_list([json.dumps(tx, sort_keys=True) for tx in self.current_transactions])
        ts = timestamp if timestamp is not None else time.time()
        return BlockHeader(len(self.chain), ts, self.last_block().compute_hash(), merkle, signer=signer, extra=extra or {})

    def sign_block_poa(self, header_json: str, authority_id: str) -> str:
        if authority_id not in self.authorities:
            raise ValueError("unknown authority")
        secret = self.authorities[authority_id].encode()
        return hmac.new(secret, header_json.encode(), hashlib.sha256).hexdigest()

    def verify_signature_poa(self, header_json: str, signature: str, authority_id: str) -> bool:
        if authority_id not in self.authorities:
            return False
        secret = self.authorities[authority_id].encode()
        expected = hmac.new(secret, header_json.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def select_pos_leader(self, seed: str) -> str:
        if not self.stakes:
            raise ValueError("no stakes configured")
        total = sum(self.stakes.values())
        if total <= 0:
            raise ValueError("total stake <= 0")
        pick = int(hashlib.sha256(seed.encode()).hexdigest(), 16) % total
        cumulative = 0
        for node, stake in sorted(self.stakes.items()):
            cumulative += stake
            if pick < cumulative:
                return node
        return list(self.stakes.keys())[0]

    def propose_block(self, proposer_id: str, signature: Optional[str]=None) -> Tuple[Block, str]:
        with self.lock:
            if self.use_pos:
                leader = self.select_pos_leader(self.last_block().compute_hash())
                if proposer_id != leader:
                    raise PermissionError(f"proposer {proposer_id} is not the chosen leader {leader}")
                header = self.build_header(signer=proposer_id, extra={"method": "PoS"})
                block = Block(header, list(self.current_transactions), signature=None)
                block_hash = block.compute_hash()
                self.chain.append(block)
                self.current_transactions = []
                return block, block_hash
            else:
                if proposer_id not in self.authorities:
                    raise PermissionError("proposer not an authority")
                # build header and expect signature for that header
                header = self.build_header(signer=proposer_id, extra={"method": "PoA"})
                header_json = header.to_json()
                if not signature:
                    raise PermissionError("missing signature for PoA block")
                if not self.verify_signature_poa(header_json, signature, proposer_id):
                    raise PermissionError("invalid signature for PoA block")
                block = Block(header, list(self.current_transactions), signature=signature)
                block_hash = block.compute_hash()
                self.chain.append(block)
                self.current_transactions = []
                return block, block_hash

    def propose_block_with_signed_header(self, header: BlockHeader, signature: str) -> Tuple[Block, str]:
        """Append a block when the caller built & signed the header externally (useful for matching signatures)."""
        with self.lock:
            method = header.extra.get("method") if header.extra else None
            if method == "PoA":
                signer = header.signer
                if not signer or signer not in self.authorities:
                    raise PermissionError("invalid signer for PoA")
                header_json = header.to_json()
                if not self.verify_signature_poa(header_json, signature, signer):
                    raise PermissionError("invalid PoA signature")
                block = Block(header, list(self.current_transactions), signature=signature)
                block_hash = block.compute_hash()
                self.chain.append(block)
                self.current_transactions = []
                return block, block_hash
            elif method == "PoS":
                leader = self.select_pos_leader(self.last_block().compute_hash())
                if header.signer != leader:
                    raise PermissionError("header signer is not selected PoS leader")
                block = Block(header, list(self.current_transactions), signature=None)
                block_hash = block.compute_hash()
                self.chain.append(block)
                self.current_transactions = []
                return block, block_hash
            else:
                raise PermissionError("unknown consensus method in header")

    def is_valid_chain(self, chain: List[Block]) -> bool:
        if not chain:
            return False
        for i in range(1, len(chain)):
            prev, curr = chain[i-1], chain[i]
            if curr.header.previous_hash != prev.compute_hash():
                return False
            expected_merkle = merkle_root_from_list([json.dumps(tx, sort_keys=True) for tx in curr.transactions])
            if curr.header.merkle_root != expected_merkle:
                return False
            method = curr.header.extra.get("method") if curr.header.extra else None
            if method == "PoA":
                signer = curr.header.signer
                if not signer or not curr.signature:
                    return False
                header_json = curr.header.to_json()
                if signer not in self.authorities:
                    return False
                if not self.verify_signature_poa(header_json, curr.signature, signer):
                    return False
            if method == "PoS" and self.use_pos:
                leader = None
                try:
                    leader = self.select_pos_leader(chain[i-1].compute_hash())
                except Exception:
                    return False
                if curr.header.signer != leader:
                    return False
        return True

    def register_node(self, address: str):
        self.peers.add(address)

    def replace_chain(self, new_chain: List[Block]) -> bool:
        if len(new_chain) > len(self.chain) and self.is_valid_chain(new_chain):
            self.chain = new_chain
            return True
        return False

    def receive_block_gossip(self, block: Block) -> bool:
        with self.lock:
            if block.header.previous_hash == self.last_block().compute_hash():
                if not self.is_valid_chain(self.chain + [block]):
                    return False
                self.chain.append(block)
                return True
            else:
                return False

app = FastAPI(title="TinyChainNet", version="0.2")

class TransactionModel(BaseModel):
    sender: str
    recipient: str
    amount: float
    memo: Optional[str] = None

class NodesModel(BaseModel):
    nodes: List[AnyHttpUrl]

class ProposeModel(BaseModel):
    proposer_id: str
    signature: Optional[str] = None

class SignedHeaderModel(BaseModel):
    header: dict
    signature: str

DEMO_AUTHORITIES = {"auth1": "secret_auth1_please_change", "auth2": "secret_auth2_please_change"}
DEMO_STAKES = {"nodeA": 10, "nodeB": 30, "nodeC": 60}

node = TinyChainNetwork(node_id="node_local", authorities=DEMO_AUTHORITIES, use_pos=False, stakes=DEMO_STAKES)

@app.post("/transactions/new")
async def new_transaction(tx: TransactionModel):
    node.submit_transaction(tx.dict())
    return {"message": "Transaction added", "pending": len(node.current_transactions)}

@app.get("/chain")
async def get_chain():
    def block_to_dict(b: Block):
        return {"header": asdict(b.header), "transactions": b.transactions, "signature": b.signature, "hash": b.compute_hash()}
    return {"length": len(node.chain), "chain": [block_to_dict(b) for b in node.chain]}

@app.post("/nodes/register")
async def register_nodes(nodes: NodesModel):
    for n in nodes.nodes:
        node.register_node(str(n))
    return {"message": "Nodes registered", "peers": list(node.peers)}

@app.post("/propose_signed")
async def propose_signed(payload: SignedHeaderModel):
    header_dict = payload.header
    signature = payload.signature
    try:
        header = BlockHeader(**header_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid header: {e}")
    try:
        block, h = node.propose_block_with_signed_header(header, signature)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return {"message": "block accepted", "hash": h, "header": asdict(block.header)}

@app.post("/nodes/receive_block")
async def receive_block(payload: dict):
    try:
        header_dict = payload["header"]
        header = BlockHeader(**header_dict)
        block = Block(header, payload.get("transactions", []), payload.get("signature"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid block payload: {e}")
    ok = node.receive_block_gossip(block)
    if ok:
        return {"message": "block appended"}
    else:
        return {"message": "block does not extend chain; resolve needed"}, 409

@app.get("/nodes/resolve")
async def resolve_conflicts():
    instructions = ("For each peer in node.peers: GET {peer}/chain; if returned chain is longer and valid, replace local chain. "
        "Use requests or httpx with timeouts and verify payload formats.")
    return {"message": "resolve algorithm (see instructions)", "instructions": instructions, "known_peers": list(node.peers)}

if __name__ == "__main__":
    print("Demo: create txs and propose PoA block with external signature...")
    node.submit_transaction({"sender":"alice","recipient":"bob","amount":5})
    node.submit_transaction({"sender":"bob","recipient":"carol","amount":2.5})
    header = node.build_header(signer="auth1", extra={"method":"PoA"}, timestamp=time.time())
    header_json = header.to_json()
    sig = node.sign_block_poa(header_json, "auth1")
    block, h = node.propose_block_with_signed_header(header, sig)
    print("Proposed block hash:", h)
    print("Chain valid?", node.is_valid_chain(node.chain))
    print("Demo complete.")
