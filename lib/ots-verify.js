// ots-verify.js — minimal in-browser OpenTimestamps verifier.
//
// Parses the .ots binary file produced by `ots stamp` and walks the
// timestamp tree. When it finds a BitcoinBlockHeaderAttestation it replays
// the op chain starting from the original target digest to compute the
// committed value, then fetches that Bitcoin block's merkle root from a
// public explorer (mempool.space, fallback blockstream.info) and compares.
//
// A successful match proves: the target digest was included in a Bitcoin
// block at the declared height, on or before the block's timestamp.
//
// Spec: https://github.com/opentimestamps/python-opentimestamps/blob/master/doc/timestamp-format.txt
// Op codes and attestation magic are the subset actually emitted by current
// OTS clients (sha256, ripemd160, append, prepend, reverse + Bitcoin/Pending
// attestations). Litecoin/Ethereum attestations are ignored — not used by us.
//
// License: MIT

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

// File header magic (31 bytes) — UTF-8 "\x00OpenTimestamps\x00\x00Proof\x00" + 7 bytes.
// Bytes after the magic: 1 version byte, then the file-hash op (algorithm id
// + hash bytes), then the timestamp tree.
const HEADER_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d,
  0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
  0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])

const TAG_ATTESTATION = 0x00
const TAG_FORK = 0xff

// Unary ops (consume current digest, produce a new digest)
const OP_SHA1 = 0x02
const OP_RIPEMD160 = 0x03
const OP_SHA256 = 0x08
const OP_KECCAK256 = 0x67
// Binary ops (with argument bytes)
const OP_APPEND = 0xf0
const OP_PREPEND = 0xf1
// Reverse op (no argument)
const OP_REVERSE = 0xf2
// hexlify — not used in our chains, ignored
const OP_HEXLIFY = 0xf3

// Hash function ids inside the FileHash op
const HASHID_SHA1 = 0x02
const HASHID_RIPEMD160 = 0x03
const HASHID_SHA256 = 0x08
const HASHID_KECCAK256 = 0x67

// 8-byte attestation magic prefixes
const ATTEST_PENDING = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])
const ATTEST_BITCOIN = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])
const ATTEST_LITECOIN = new Uint8Array([0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45])
const ATTEST_ETHEREUM = new Uint8Array([0x30, 0xfe, 0x80, 0x87, 0xb5, 0xc7, 0xea, 0xd7])

// ---------------------------------------------------------------------------
// Binary reader + helpers
// ---------------------------------------------------------------------------

class Reader {
  constructor(bytes) {
    this.b = bytes
    this.i = 0
  }
  eof() { return this.i >= this.b.length }
  rem() { return this.b.length - this.i }
  peek() { return this.b[this.i] }
  read(n) {
    if (this.i + n > this.b.length) throw new Error("truncated input")
    const out = this.b.slice(this.i, this.i + n)
    this.i += n
    return out
  }
  readByte() {
    if (this.i >= this.b.length) throw new Error("truncated input")
    return this.b[this.i++]
  }
  // OTS varuint: little-endian, 7-bit continuation, MSB signals more bytes.
  readVaruint() {
    let value = 0n
    let shift = 0n
    while (true) {
      const b = this.readByte()
      value |= BigInt(b & 0x7f) << shift
      if ((b & 0x80) === 0) break
      shift += 7n
      if (shift > 63n) throw new Error("varuint overflow")
    }
    // For our use case values fit in JS Number safely.
    return Number(value)
  }
  // OTS "varbytes": a varuint length followed by that many bytes.
  readVarbytes() {
    const n = this.readVaruint()
    return this.read(n)
  }
}

function eqBytes(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
function startsWith(buf, prefix) {
  if (buf.length < prefix.length) return false
  for (let i = 0; i < prefix.length; i++) if (buf[i] !== prefix[i]) return false
  return true
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}
function reverse(a) {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) out[i] = a[a.length - 1 - i]
  return out
}
async function sha256(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes)
  return new Uint8Array(d)
}
async function sha1(bytes) {
  const d = await crypto.subtle.digest("SHA-1", bytes)
  return new Uint8Array(d)
}
function toHex(b) {
  let s = ""
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0")
  return s
}

// ---------------------------------------------------------------------------
// Parse + walk the timestamp tree, collecting attestations with their
// committed digest. Each attestation is paired with the digest that results
// from applying all ops from the root to that leaf.
// ---------------------------------------------------------------------------

async function walkTree(reader, digest) {
  // Returns array of { kind, ...info, committedDigest }
  const tag = reader.readByte()
  if (tag === TAG_ATTESTATION) {
    return [await parseAttestation(reader, digest)]
  }
  if (tag === TAG_FORK) {
    // Two branches starting from the same digest.
    const left = await walkTree(reader, digest)
    const right = await walkTree(reader, digest)
    return left.concat(right)
  }
  // Otherwise tag is an op code. Apply it, then continue with the resulting
  // digest.
  const nextDigest = await applyOp(tag, reader, digest)
  return walkTree(reader, nextDigest)
}

async function applyOp(opCode, reader, digest) {
  switch (opCode) {
    case OP_SHA256: return sha256(digest)
    case OP_SHA1:   return sha1(digest)
    case OP_RIPEMD160:
      throw new Error("RIPEMD-160 non supportato in-browser (usa la CLI `ots verify`)")
    case OP_KECCAK256:
      throw new Error("KECCAK-256 non supportato in-browser")
    case OP_REVERSE: return reverse(digest)
    case OP_APPEND: {
      const arg = reader.readVarbytes()
      return concat(digest, arg)
    }
    case OP_PREPEND: {
      const arg = reader.readVarbytes()
      return concat(arg, digest)
    }
    case OP_HEXLIFY:
      throw new Error("hexlify non supportato")
    default:
      // Attestation tag that reached this branch shouldn't happen, but
      // guard just in case.
      throw new Error(`op code sconosciuto: 0x${opCode.toString(16)}`)
  }
}

async function parseAttestation(reader, digest) {
  const magic = reader.read(8)
  const content = reader.readVarbytes()
  const inner = new Reader(content)
  if (eqBytes(magic, ATTEST_BITCOIN)) {
    const height = inner.readVaruint()
    return { kind: "bitcoin", height, committedDigest: digest }
  }
  if (eqBytes(magic, ATTEST_PENDING)) {
    // content holds the UTF-8 calendar URI
    const uri = new TextDecoder().decode(content)
    return { kind: "pending", uri, committedDigest: digest }
  }
  if (eqBytes(magic, ATTEST_LITECOIN) || eqBytes(magic, ATTEST_ETHEREUM)) {
    return { kind: "other", committedDigest: digest }
  }
  return { kind: "unknown", magic: toHex(magic), committedDigest: digest }
}

// ---------------------------------------------------------------------------
// Entry point — parse the .ots file and return attestations with their
// committed digests. Caller is responsible for cross-checking against
// Bitcoin block headers.
// ---------------------------------------------------------------------------

/**
 * Parse the .ots file header and walk the timestamp tree.
 *
 * IMPORTANT — the Svelio seal worker calls `ots stamp <file>` where <file>
 * is a temp file whose bytes are the 32-byte digest SHA-256(manifest.json).
 * The CLI re-hashes whatever file it is given, so the FileHash actually
 * embedded in the .ots is SHA-256(SHA-256(manifest.json)) — NOT the plain
 * SHA-256(manifest.json). The caller must pass `expectedFileHash` matching
 * that convention (use the `expectedFileHashForManifest()` helper below).
 *
 * @param {Uint8Array} otsBytes raw .ots file contents
 * @param {Uint8Array} [expectedFileHash] if provided, throw when the .ots
 *   header does not stamp exactly this digest.
 * @returns {{ hashAlg: string, fileHash: Uint8Array, attestations: Array }}
 */
export async function parseOts(otsBytes, expectedFileHash) {
  const r = new Reader(otsBytes)
  // Header magic + version
  if (!startsWith(r.b, HEADER_MAGIC)) throw new Error("Magic OTS non riconosciuto")
  r.i = HEADER_MAGIC.length
  const version = r.readByte()
  if (version !== 1) throw new Error(`Versione OTS non supportata: ${version}`)
  // FileHash op: 1 byte hash id + hash bytes (length depends on algo)
  const hashId = r.readByte()
  let hashAlg, hashLen
  switch (hashId) {
    case HASHID_SHA256: hashAlg = "SHA-256"; hashLen = 32; break
    case HASHID_SHA1:   hashAlg = "SHA-1"; hashLen = 20; break
    case HASHID_RIPEMD160: hashAlg = "RIPEMD-160"; hashLen = 20; break
    case HASHID_KECCAK256: hashAlg = "KECCAK-256"; hashLen = 32; break
    default: throw new Error(`Hash algoritmo sconosciuto: 0x${hashId.toString(16)}`)
  }
  const fileHash = r.read(hashLen)
  if (expectedFileHash && !eqBytes(fileHash, expectedFileHash)) {
    throw new Error(
      `Il file .ots è stato stampato su un digest diverso da quello atteso per questo manifest (atteso ${toHex(expectedFileHash)}, trovato ${toHex(fileHash)})`,
    )
  }
  const attestations = await walkTree(r, fileHash)
  return { hashAlg, fileHash, attestations }
}

/**
 * Compute the digest that must appear in the .ots FileHash op for a given
 * manifest. Encodes the double-hash convention imposed by `ots stamp` (see
 * parseOts docstring).
 */
export async function expectedFileHashForManifest(manifestBytes) {
  const d1 = new Uint8Array(await crypto.subtle.digest("SHA-256", manifestBytes))
  const d2 = new Uint8Array(await crypto.subtle.digest("SHA-256", d1))
  return d2
}

// ---------------------------------------------------------------------------
// Bitcoin block header fetch + commit comparison
// ---------------------------------------------------------------------------

const BTC_EXPLORERS = [
  { name: "mempool.space", base: "https://mempool.space/api" },
  { name: "blockstream.info", base: "https://blockstream.info/api" },
]

async function fetchBlockMerkleRoot(height) {
  let lastErr = null
  for (const ex of BTC_EXPLORERS) {
    try {
      const hashRes = await fetch(`${ex.base}/block-height/${height}`, {
        redirect: "follow",
      })
      if (!hashRes.ok) throw new Error(`${ex.name} block-height: ${hashRes.status}`)
      const blockHash = (await hashRes.text()).trim()
      if (!/^[0-9a-fA-F]{64}$/.test(blockHash)) {
        throw new Error(`${ex.name} block-height: hash malformato`)
      }
      const metaRes = await fetch(`${ex.base}/block/${blockHash}`)
      if (!metaRes.ok) throw new Error(`${ex.name} block meta: ${metaRes.status}`)
      const meta = await metaRes.json()
      if (!meta.merkle_root) throw new Error(`${ex.name} meta senza merkle_root`)
      return {
        blockHash,
        merkleRoot: meta.merkle_root,
        timestamp: meta.timestamp,
        explorer: ex.name,
      }
    } catch (e) {
      lastErr = e
    }
  }
  throw new Error(`Impossibile contattare un explorer Bitcoin: ${lastErr?.message ?? "errore"}`)
}

/**
 * Full Bitcoin verification: parse .ots, for each BitcoinBlockHeaderAttestation
 * compare the committed digest (little-endian → big-endian hex) against the
 * merkle root of the referenced Bitcoin block as returned by mempool.space.
 *
 * @returns {{ state, block?, attestation?, pending?: string[], error? }}
 */
export async function verifyOtsAgainstBitcoin(otsBytes, manifestBytes) {
  let parsed
  try {
    const expected = await expectedFileHashForManifest(manifestBytes)
    parsed = await parseOts(otsBytes, expected)
  } catch (e) {
    return { state: "error", error: e.message || String(e) }
  }

  const bitcoinAtts = parsed.attestations.filter((a) => a.kind === "bitcoin")
  const pendingAtts = parsed.attestations.filter((a) => a.kind === "pending")

  if (bitcoinAtts.length === 0) {
    return {
      state: "pending",
      pending: pendingAtts.map((a) => a.uri),
    }
  }

  // Try each Bitcoin attestation; any match is enough to declare confirmed.
  const errors = []
  for (const att of bitcoinAtts) {
    // Bitcoin block headers serialize the merkle root in little-endian byte
    // order. Block explorers (mempool.space, blockstream.info) return it as
    // "display order" hex, which is the reverse of the wire bytes.
    // The OTS committed digest is in wire order (same LE as the block header
    // stores), so to compare against mempool.space we must reverse one of
    // the two.
    const committedHex = toHex(att.committedDigest)
    const committedReversedHex = toHex(reverse(att.committedDigest))
    try {
      const block = await fetchBlockMerkleRoot(att.height)
      const target = block.merkleRoot.toLowerCase()
      if (target === committedReversedHex.toLowerCase() || target === committedHex.toLowerCase()) {
        return {
          state: "confirmed",
          attestation: att,
          block,
          committedHex: committedReversedHex,
        }
      }
      errors.push(
        `blocco ${att.height}: merkle root non corrisponde ` +
          `(atteso ${committedReversedHex}, trovato ${block.merkleRoot})`,
      )
    } catch (e) {
      errors.push(`blocco ${att.height}: ${e.message || e}`)
    }
  }

  return { state: "mismatch", error: errors.join(" · ") }
}
