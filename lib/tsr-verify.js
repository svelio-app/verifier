// tsr-verify.js — in-browser RFC 3161 TimeStampResp parser and verifier.
//
// Minimal DER parser + walks the RFC 3161 TimeStampResp / TimeStampToken
// (itself a CMS SignedData with eContent = TSTInfo) to extract:
//   - messageImprint hash algorithm + hash value
//   - genTime (signing time of the TSA)
//   - signer cert (optional)
//   - signerInfo (optional, for signature verification)
//
// The caller can then compare the messageImprint hash to the SHA-256 of the
// manifest and, if it wants a fuller guarantee, verify the signerInfo
// signature against the bundled FreeTSA issuer certificate using WebCrypto.
//
// Scope limits:
//   - We support RSA+SHA-256 signatures only (what FreeTSA issues).
//   - Certificate chain is not validated up to a trust anchor here; the
//     caller does that separately by pinning the FreeTSA issuer cert.
//
// License: MIT

// ---------------------------------------------------------------------------
// Minimal DER parser
// ---------------------------------------------------------------------------

class DerNode {
  constructor(cls, tag, constructed, content, header, fullBytes) {
    this.cls = cls
    this.tag = tag
    this.constructed = constructed
    this.content = content
    this.header = header
    this.fullBytes = fullBytes
  }
  children() {
    if (!this.constructed) return []
    const out = []
    let off = 0
    while (off < this.content.length) {
      const node = derParse(this.content, off)
      out.push(node)
      off += node.header + node.content.length
    }
    return out
  }
}

function derParse(buf, off = 0) {
  let i = off
  if (i >= buf.length) throw new Error("DER truncated at tag")
  const t0 = buf[i++]
  const cls = (t0 >> 6) & 0x03
  const constructed = (t0 & 0x20) !== 0
  let tag = t0 & 0x1f
  if (tag === 0x1f) {
    tag = 0
    let b
    do {
      if (i >= buf.length) throw new Error("DER truncated at multi-byte tag")
      b = buf[i++]
      tag = (tag << 7) | (b & 0x7f)
    } while (b & 0x80)
  }
  if (i >= buf.length) throw new Error("DER truncated at length")
  const l0 = buf[i++]
  let len
  if (l0 < 0x80) {
    len = l0
  } else {
    const n = l0 & 0x7f
    if (n === 0) throw new Error("DER indefinite length not supported")
    if (i + n > buf.length) throw new Error("DER truncated at long length")
    len = 0
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++]
  }
  if (i + len > buf.length) throw new Error("DER truncated at content")
  const header = i - off
  const content = buf.slice(i, i + len)
  const fullBytes = buf.slice(off, i + len)
  return new DerNode(cls, tag, constructed, content, header, fullBytes)
}

function decodeOid(content) {
  if (content.length === 0) return ""
  const first = content[0]
  const parts = []
  if (first < 80) {
    parts.push(String(Math.floor(first / 40)))
    parts.push(String(first % 40))
  } else {
    parts.push("2")
    parts.push(String(first - 80))
  }
  let acc = 0n
  for (let i = 1; i < content.length; i++) {
    const b = content[i]
    acc = (acc << 7n) | BigInt(b & 0x7f)
    if ((b & 0x80) === 0) {
      parts.push(acc.toString())
      acc = 0n
    }
  }
  return parts.join(".")
}

function decodeGeneralizedTime(content) {
  const s = new TextDecoder("ascii").decode(content)
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s)
  if (!m) return { raw: s, date: null }
  const [, y, mo, d, h, mi, se, frac] = m
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${se}${frac ? "." + frac : ""}Z`
  return { raw: s, date: new Date(iso) }
}

// ---------------------------------------------------------------------------
// Structure constants
// ---------------------------------------------------------------------------

const OID = {
  SHA256: "2.16.840.1.101.3.4.2.1",
  SHA1:   "1.3.14.3.2.26",
  SHA384: "2.16.840.1.101.3.4.2.2",
  SHA512: "2.16.840.1.101.3.4.2.3",
  ID_SIGNED_DATA: "1.2.840.113549.1.7.2",
  ID_CT_TST_INFO: "1.2.840.113549.1.9.16.1.4",
}

function hashOidToName(oid) {
  return {
    [OID.SHA256]: "SHA-256",
    [OID.SHA1]:   "SHA-1",
    [OID.SHA384]: "SHA-384",
    [OID.SHA512]: "SHA-512",
  }[oid] ?? oid
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
function parseTimeStampResp(derBytes) {
  const root = derParse(derBytes)
  if (root.tag !== 0x10) throw new Error("TSR non SEQUENCE")
  const kids = root.children()
  // status (SEQUENCE) then timeStampToken (SEQUENCE = ContentInfo)
  const token = kids.find((k, i) => i > 0 && k.tag === 0x10)
  if (!token) throw new Error("TSR senza TimeStampToken")
  return parseContentInfo(token)
}

// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
function parseContentInfo(ci) {
  const kids = ci.children()
  if (kids.length < 2) throw new Error("ContentInfo malformato")
  const ctOid = decodeOid(kids[0].content)
  if (ctOid !== OID.ID_SIGNED_DATA) throw new Error("ContentInfo non e SignedData: " + ctOid)
  const explicit = kids[1]
  if (explicit.cls !== 2 || explicit.tag !== 0) throw new Error("ContentInfo content non [0] EXPLICIT")
  const signedData = derParse(explicit.content)
  return parseSignedData(signedData)
}

function parseSignedData(sd) {
  const kids = sd.children()
  const out = { encap: null, certificates: [], signerInfos: [] }
  for (const k of kids) {
    if (k.cls === 0 && k.tag === 0x02) continue // version
    if (k.cls === 0 && k.tag === 0x11) {
      // SET — could be digestAlgorithms (early) or signerInfos (tail). Disambiguate by index.
      continue
    }
    if (k.cls === 0 && k.tag === 0x10 && !out.encap) {
      out.encap = parseEncapContentInfo(k)
      continue
    }
    if (k.cls === 2 && k.tag === 0 && k.constructed) {
      for (let off = 0; off < k.content.length;) {
        const node = derParse(k.content, off)
        out.certificates.push(node)
        off += node.header + node.content.length
      }
      continue
    }
  }
  // Take the last SET — that is signerInfos
  const sets = kids.filter((k) => k.cls === 0 && k.tag === 0x11 && k.constructed)
  if (sets.length > 0) {
    const siSet = sets[sets.length - 1]
    for (const si of siSet.children()) out.signerInfos.push(parseSignerInfo(si))
  }
  return out
}

function parseEncapContentInfo(node) {
  const kids = node.children()
  if (kids.length < 2) throw new Error("EncapContentInfo senza eContent")
  const ctOid = decodeOid(kids[0].content)
  if (ctOid !== OID.ID_CT_TST_INFO) throw new Error("eContentType non TST Info: " + ctOid)
  const explicit = kids[1]
  const octet = derParse(explicit.content)
  return parseTstInfo(octet.content)
}

// TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
function parseTstInfo(octet) {
  const seq = derParse(octet)
  const kids = seq.children()
  const msgImprint = kids[2]
  const genTime = kids[4]
  const miKids = msgImprint.children()
  const algSeq = miKids[0]
  const algOid = decodeOid(algSeq.children()[0].content)
  const hashValue = miKids[1].content
  const gt = decodeGeneralizedTime(genTime.content)
  return {
    hashAlgOid: algOid,
    hashAlg: hashOidToName(algOid),
    hashValue,
    genTimeRaw: gt.raw,
    genTime: gt.date,
  }
}

function parseSignerInfo(node) {
  const kids = node.children()
  let idx = 0
  idx++ // version
  idx++ // sid
  const digestAlg = kids[idx++]
  let signedAttrs = null, sigAlg, sig
  if (kids[idx] && kids[idx].cls === 2 && kids[idx].tag === 0) {
    signedAttrs = kids[idx++]
  }
  sigAlg = kids[idx++]
  sig = kids[idx++]
  return {
    digestAlgOid: decodeOid(digestAlg.children()[0].content),
    signedAttrsNode: signedAttrs,
    signatureAlgOid: decodeOid(sigAlg.children()[0].content),
    signature: sig ? sig.content : null,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify that the TSR is a valid RFC 3161 TimeStampResp whose messageImprint
 * equals SHA-256(manifestBytes). Returns a structured result — state is one
 * of "ok", "mismatch", "unsupported", "error".
 */
export async function verifyTsrAgainstManifest(tsrBytes, manifestBytes) {
  try {
    const signed = parseTimeStampResp(tsrBytes)
    const tst = signed.encap
    if (tst.hashAlgOid !== OID.SHA256) {
      return {
        state: "unsupported",
        error: "Algoritmo TSR non supportato in-browser: " + tst.hashAlg,
      }
    }
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", manifestBytes))
    if (!bytesEqual(expected, tst.hashValue)) {
      return {
        state: "mismatch",
        error: "La marca e emessa per un digest diverso. Atteso " + toHex(expected) + ", nel TSR " + toHex(tst.hashValue),
      }
    }
    return {
      state: "ok",
      hashAlg: tst.hashAlg,
      genTime: tst.genTime,
      genTimeRaw: tst.genTimeRaw,
    }
  } catch (e) {
    return { state: "error", error: e.message || String(e) }
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
function toHex(b) {
  let s = ""
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0")
  return s
}

// ---------------------------------------------------------------------------
// Full signature verification (SignerInfo + cert chain against FreeTSA CA)
// ---------------------------------------------------------------------------

// Expected SHA-256 fingerprint of the bundled FreeTSA root CA certificate.
// Any change to vendor/freetsa-ca.pem must be reflected here — mismatch
// causes full verification to fail loudly.
const FREETSA_CA_FINGERPRINT = "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"

// Map known signature-algorithm OIDs to WebCrypto parameters.
const SIG_ALG = {
  // sha256WithRSAEncryption / 384 / 512
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
  // ecdsa-with-SHA256 / 384 / 512
  "1.2.840.10045.4.3.2":   { kind: "ecdsa", hash: "SHA-256" },
  "1.2.840.10045.4.3.3":   { kind: "ecdsa", hash: "SHA-384" },
  "1.2.840.10045.4.3.4":   { kind: "ecdsa", hash: "SHA-512" },
}

// Map named-curve OIDs (as they appear inside the SPKI AlgorithmIdentifier
// parameters for id-ecPublicKey) to WebCrypto namedCurve values.
const EC_CURVE_OID = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34":        "P-384",
  "1.3.132.0.35":        "P-521",
}

function pemToDer(pem) {
  const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem)
  if (!m) throw new Error("PEM malformato")
  const b64 = m[1].replace(/\s+/g, "")
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))
  let s = ""
  for (let i = 0; i < d.length; i++) s += d[i].toString(16).padStart(2, "0")
  return s
}

// Extract from a Certificate (X.509 SEQUENCE) node:
//   - tbsBytes (DER bytes of TBSCertificate, to verify against issuer)
//   - spkiBytes (DER bytes of SubjectPublicKeyInfo, to importKey)
//   - signatureAlgOid (of the whole cert, i.e. issuer used this alg)
//   - signatureValue (raw bytes, unwrap BIT STRING)
function parseCertificate(certNode) {
  const kids = certNode.children()
  if (kids.length < 3) throw new Error("Certificate malformato")
  const tbs = kids[0]
  const sigAlg = kids[1]
  const sigBit = kids[2]
  // BIT STRING: first byte is unused-bits count (should be 0), rest is raw
  if (sigBit.content.length < 2 || sigBit.content[0] !== 0) {
    throw new Error("Firma del certificato con unused-bits diversi da 0 — non supportato")
  }
  const signatureValue = sigBit.content.slice(1)
  const signatureAlgOid = decodeOid(sigAlg.children()[0].content)

  // Extract SubjectPublicKeyInfo — it is the SEQUENCE at position idx inside tbs
  // that is itself a SEQUENCE (AlgorithmIdentifier + BIT STRING).
  const tbsKids = tbs.children()
  // TBSCertificate layout:
  //   [0] version (optional EXPLICIT), serialNumber INTEGER, signature AlgorithmIdentifier,
  //   issuer Name, validity Validity, subject Name, subjectPublicKeyInfo, ...
  // We walk and find the first SEQUENCE that contains another SEQUENCE + BIT STRING.
  let spkiNode = null
  for (const k of tbsKids) {
    if (k.cls !== 0 || k.tag !== 0x10 || !k.constructed) continue
    const gkids = k.children()
    if (gkids.length === 2 && gkids[0].tag === 0x10 && gkids[1].tag === 0x03) {
      spkiNode = k
      break
    }
  }
  if (!spkiNode) throw new Error("SubjectPublicKeyInfo non trovato nel certificato")
  return {
    tbsBytes: tbs.fullBytes,
    spkiBytes: spkiNode.fullBytes,
    signatureAlgOid,
    signatureValue,
  }
}

// Extract the named curve OID from an EC SubjectPublicKeyInfo (so we can
// import it with the correct curve parameters). Returns null for RSA SPKIs.
function extractEcCurveName(spkiBytes) {
  const spki = derParse(spkiBytes)                 // SEQUENCE
  const algId = spki.children()[0]                 // SEQUENCE { algOid, params }
  const algKids = algId.children()
  const algOid = decodeOid(algKids[0].content)
  if (algOid !== "1.2.840.10045.2.1") return null  // id-ecPublicKey
  if (!algKids[1] || algKids[1].tag !== 0x06) return null // params is an OID
  const curveOid = decodeOid(algKids[1].content)
  return EC_CURVE_OID[curveOid] ?? null
}

// Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
// into the fixed-length IEEE-P1363 raw concatenation (r || s) that WebCrypto
// expects. `byteLen` is the curve-specific component size: 32 for P-256, 48
// for P-384, 66 for P-521.
function ecdsaDerToRaw(derSig, byteLen) {
  const seq = derParse(derSig)
  if (seq.tag !== 0x10) throw new Error("ECDSA sig non SEQUENCE")
  const parts = seq.children()
  if (parts.length !== 2) throw new Error("ECDSA sig non r,s")
  const trim = (buf) => {
    let i = 0
    while (i < buf.length - 1 && buf[i] === 0x00) i++
    return buf.slice(i)
  }
  const pad = (buf) => {
    if (buf.length === byteLen) return buf
    if (buf.length > byteLen) throw new Error("ECDSA int troppo grande")
    const out = new Uint8Array(byteLen)
    out.set(buf, byteLen - buf.length)
    return out
  }
  const r = pad(trim(parts[0].content))
  const s = pad(trim(parts[1].content))
  const out = new Uint8Array(byteLen * 2)
  out.set(r, 0)
  out.set(s, byteLen)
  return out
}

const CURVE_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 }

async function verifySignature(spkiBytes, sigAlgOid, signature, signedBytes) {
  const meta = SIG_ALG[sigAlgOid]
  if (!meta) throw new Error("Algoritmo firma non supportato: " + sigAlgOid)
  if (meta.kind === "rsa") {
    const key = await crypto.subtle.importKey(
      "spki",
      spkiBytes,
      { name: "RSASSA-PKCS1-v1_5", hash: meta.hash },
      false,
      ["verify"],
    )
    return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, signedBytes)
  }
  if (meta.kind === "ecdsa") {
    const namedCurve = extractEcCurveName(spkiBytes)
    if (!namedCurve) throw new Error("Curva EC della chiave pubblica non riconosciuta")
    const byteLen = CURVE_BYTES[namedCurve]
    if (!byteLen) throw new Error("Curva EC non supportata: " + namedCurve)
    const rawSig = ecdsaDerToRaw(signature, byteLen)
    const key = await crypto.subtle.importKey(
      "spki",
      spkiBytes,
      { name: "ECDSA", namedCurve },
      false,
      ["verify"],
    )
    return crypto.subtle.verify({ name: "ECDSA", hash: meta.hash }, key, rawSig, signedBytes)
  }
  throw new Error("Tipo di firma sconosciuto: " + meta.kind)
}

/**
 * Full TSR verification: messageImprint + SignerInfo signature + cert chain.
 *
 * @param {Uint8Array} tsrBytes
 * @param {Uint8Array} manifestBytes
 * @param {string} caPem  PEM-encoded FreeTSA root CA certificate
 * @returns {Promise<object>} rich result object
 */
export async function verifyTsrFully(tsrBytes, manifestBytes, caPem) {
  try {
    // 1. Parse TSR + check messageImprint binding
    const mi = await verifyTsrAgainstManifest(tsrBytes, manifestBytes)
    if (mi.state !== "ok") return mi

    // 2. Pin + parse CA
    const caDer = pemToDer(caPem)
    const caFpr = await sha256Hex(caDer)
    if (caFpr.toLowerCase() !== FREETSA_CA_FINGERPRINT.toLowerCase()) {
      return {
        state: "ca-fingerprint-mismatch",
        error: `Il certificato CA bundled ha fingerprint ${caFpr} diverso da quello atteso ${FREETSA_CA_FINGERPRINT}`,
      }
    }
    const caNode = derParse(caDer)
    const ca = parseCertificate(caNode)

    // 3. Extract signer cert from TSR SignedData and verify its signature
    //    against the CA public key.
    const signed = parseTimeStampResp(tsrBytes)
    if (signed.certificates.length === 0) {
      return { state: "no-signer-cert", error: "TSR senza certificato firmatario" }
    }
    const signerCertNode = signed.certificates[0]
    const signerCert = parseCertificate(signerCertNode)
    const certChainOk = await verifySignature(
      ca.spkiBytes,
      signerCert.signatureAlgOid,
      signerCert.signatureValue,
      signerCert.tbsBytes,
    )
    if (!certChainOk) {
      return {
        state: "cert-chain-invalid",
        error: "Il certificato del firmatario non è stato emesso dalla CA FreeTSA pinnata",
      }
    }

    // 4. Verify SignerInfo signature: reconstruct the SET-encoded signedAttrs
    //    and verify with the signer cert's public key.
    if (signed.signerInfos.length === 0) {
      return { state: "no-signer-info", error: "TSR senza SignerInfo" }
    }
    const si = signed.signerInfos[0]
    if (!si.signedAttrsNode) {
      return { state: "no-signed-attrs", error: "SignerInfo senza signedAttrs" }
    }
    // signedAttrs is serialized as IMPLICIT [0] (tag byte 0xa0). For the
    // signature, it must be re-encoded as SET (tag byte 0x31). Copy the bytes
    // and rewrite the tag.
    const signedAttrsCanonical = new Uint8Array(si.signedAttrsNode.fullBytes)
    signedAttrsCanonical[0] = 0x31
    const sigOk = await verifySignature(
      signerCert.spkiBytes,
      si.signatureAlgOid,
      si.signature,
      signedAttrsCanonical,
    )
    if (!sigOk) {
      return {
        state: "signature-invalid",
        error: "Firma SignerInfo non valida con la chiave del certificato del firmatario",
      }
    }

    // 5. All checks passed
    return {
      state: "fully-verified",
      hashAlg: mi.hashAlg,
      genTime: mi.genTime,
      genTimeRaw: mi.genTimeRaw,
      caFingerprint: caFpr,
    }
  } catch (e) {
    return { state: "error", error: e.message || String(e) }
  }
}
