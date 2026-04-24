// verifier.js — standalone Svelio proof verifier.
// Runs entirely in the browser. Makes zero network calls: all third-party
// JavaScript is vendored under ./vendor/ and served from the same origin.
// Content-Security-Policy is "default-src 'none'; script-src 'self'; …".
//
// Spec implemented: svelio-integrity-v1
//   - manifest.json fields: spec, verifyId, version, sealedAt, project{title,sender},
//     files[]{name,size,sha256}, merkleRoot
//   - merkleRoot construction: sort sha256 values lex, decode hex to bytes, pairwise
//     SHA-256(left || right) (duplicate last if odd), iterate until one value remains.
//   - manifest.sig is the raw 64-byte Ed25519 signature over the exact bytes of
//     manifest.json. It is accepted only if it verifies against one of the
//     pinned Svelio public keys below.
//
// No innerHTML is used with dynamic data; every text node is created with textContent
// or appended via document.createElement.
//
// License: MIT

import JSZip from "./vendor/jszip.js"
import * as ed from "./vendor/noble-ed25519.js"
import { sha512 } from "./vendor/noble-hashes-sha512.js"
import { verifyOtsAgainstBitcoin } from "./lib/ots-verify.js"
import { verifyTsrAgainstManifest, verifyTsrFully } from "./lib/tsr-verify.js"

// Bundled FreeTSA root CA, loaded once at startup. Pinned by SHA-256
// fingerprint inside tsr-verify.js (FREETSA_CA_FINGERPRINT).
let FREETSA_CA_PEM = null
fetch("./vendor/freetsa-ca.pem")
  .then((r) => (r.ok ? r.text() : null))
  .then((t) => { FREETSA_CA_PEM = t })
  .catch(() => { FREETSA_CA_PEM = null })

// noble/ed25519 expects a sync sha512 implementation for verify() below.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))

// -----------------------------------------------------------------------------
// Canonical Svelio public keys (pinned). The bundle may include a key file,
// but this verifier only reports a signature as "issued by Svelio" when the
// signing key is one of these. Additional keys are added here at rotation.
// Raw 32-byte Ed25519 public keys, base64-encoded.
// -----------------------------------------------------------------------------
const SVELIO_PUBLIC_KEYS = {
  "svelio-2026": "WWBx3aOFx6nV3RoMIqg/ycbC/+1Dh/TKTBpFz2762Wk=",
}

const $ = (id) => document.getElementById(id)

// --- hex / bytes helpers ---
function bytesToHex(bytes) {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0")
  return s
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

// Soft cap to avoid OOM on absurd inputs. 500 MB covers any realistic bundle
// (proofs are tiny) and any realistic single-file hash check (a 4K-intra
// RAW gallery of ~500 files at ~1 GB each would be hashed individually).
const MAX_FILE_BYTES = 500 * 1024 * 1024

function fileTooLarge(f) {
  return f.size > MAX_FILE_BYTES
}

async function sha256Hex(bytesOrBuffer) {
  const digest = await crypto.subtle.digest("SHA-256", bytesOrBuffer)
  return bytesToHex(new Uint8Array(digest))
}

async function merkleRoot(leavesHex) {
  if (!leavesHex.length) throw new Error("empty leaves")
  const sorted = [...leavesHex].sort()
  if (sorted.length === 1) return sorted[0]
  let layer = sorted.map(hexToBytes)
  while (layer.length > 1) {
    const next = []
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i]
      const right = i + 1 < layer.length ? layer[i + 1] : left
      const combined = new Uint8Array(left.length + right.length)
      combined.set(left, 0)
      combined.set(right, left.length)
      const digest = await crypto.subtle.digest("SHA-256", combined)
      next.push(new Uint8Array(digest))
    }
    layer = next
  }
  return bytesToHex(layer[0])
}

// --- small DOM helpers ---
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue
    if (k === "class") node.className = v
    else if (k === "text") node.textContent = v
    else node.setAttribute(k, v === true ? "" : String(v))
  }
  for (const child of children) {
    if (child == null || child === false) continue
    node.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
  return node
}

function base64ToBytes(b64) {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function verifyManifestSignature(manifestBytes, sigBytes) {
  // Try every pinned Svelio public key. Return the matching keyId (canonical)
  // or null if no pinned key validates the signature.
  for (const [keyId, keyB64] of Object.entries(SVELIO_PUBLIC_KEYS)) {
    try {
      const pub = base64ToBytes(keyB64)
      const ok = await ed.verifyAsync(sigBytes, manifestBytes, pub)
      if (ok) return keyId
    } catch {
      // ignore, try next key
    }
  }
  return null
}

// --- state ---
let bundle = null // { manifest, manifestBytes, hasOts, hasTsr, hasPubKey, sigStatus }

// --- wiring ---
const dropBundle = $("drop-bundle")
const inputBundle = $("file-bundle")
const dropFiles = $("drop-files")
const inputFiles = $("file-inputs")

function wireDrop(el, onFiles) {
  // NOTE: we do NOT add a manual click listener that calls input.click().
  // The <label> wrapping the <input type="file"> already opens the picker
  // natively on click; adding our own would fire it twice (the browser opens
  // the OS file chooser, you pick a file, then it opens again).
  el.addEventListener("dragover", (e) => {
    e.preventDefault()
    el.classList.add("over")
  })
  el.addEventListener("dragleave", () => el.classList.remove("over"))
  el.addEventListener("drop", (e) => {
    e.preventDefault()
    el.classList.remove("over")
    if (e.dataTransfer.files.length) onFiles(e.dataTransfer.files)
  })
}
wireDrop(dropBundle, (files) => loadBundle(files[0]))
wireDrop(dropFiles, (files) => verifyFiles(files))
inputBundle.addEventListener("change", (e) => {
  if (e.target.files.length) loadBundle(e.target.files[0])
})
inputFiles.addEventListener("change", (e) => {
  if (e.target.files.length) verifyFiles(e.target.files)
})

async function loadBundle(file) {
  const err = $("bundle-error")
  const summary = $("bundle-summary")
  err.classList.add("hidden")
  summary.classList.add("hidden")
  $("files-card").classList.add("hidden")
  $("root-card").classList.add("hidden")
  $("file-results").replaceChildren()
  $("drop-bundle-title").textContent = "Lettura pacchetto…"
  try {
    if (fileTooLarge(file)) {
      throw new Error(
        `Pacchetto troppo grande (${(file.size / 1024 / 1024).toFixed(0)} MB). Massimo ${MAX_FILE_BYTES / 1024 / 1024} MB.`,
      )
    }
    const zip = await JSZip.loadAsync(file)
    const manifestEntry = zip.file("manifest.json")
    if (!manifestEntry) throw new Error("manifest.json non trovato nel pacchetto")
    const manifestBytes = new Uint8Array(await manifestEntry.async("arraybuffer"))
    const manifestText = new TextDecoder("utf-8").decode(manifestBytes)
    const manifest = JSON.parse(manifestText)
    if (manifest.spec !== "svelio-integrity-v1")
      throw new Error("Formato non riconosciuto: " + manifest.spec)
    if (!Array.isArray(manifest.files) || !manifest.files.length)
      throw new Error("Manifest senza elenco file")
    if (typeof manifest.merkleRoot !== "string")
      throw new Error("Manifest senza merkleRoot")

    // Signature verification against pinned Svelio public keys
    let sigStatus = { state: "missing" } // missing | invalid | unknown-key | valid
    const sigEntry = zip.file("manifest.sig")
    if (sigEntry) {
      const sigBytes = new Uint8Array(await sigEntry.async("arraybuffer"))
      if (sigBytes.length !== 64) {
        sigStatus = { state: "invalid", reason: `lunghezza ${sigBytes.length} ≠ 64` }
      } else {
        const matchedKeyId = await verifyManifestSignature(manifestBytes, sigBytes)
        if (matchedKeyId) sigStatus = { state: "valid", keyId: matchedKeyId }
        else sigStatus = { state: "invalid" }
      }
    }

    const otsEntry = zip.file("ots.bin")
    const tsrEntry = zip.file("tsr.bin")
    const otsBytes = otsEntry ? new Uint8Array(await otsEntry.async("arraybuffer")) : null
    const tsrBytes = tsrEntry ? new Uint8Array(await tsrEntry.async("arraybuffer")) : null

    bundle = {
      manifest,
      manifestBytes,
      hasOts: otsBytes !== null,
      hasTsr: tsrBytes !== null,
      hasPubKey: Object.keys(zip.files).some((k) => k.endsWith(".pub")),
      sigStatus,
      // Async results — start them now, fill in when they resolve.
      otsResult: otsBytes ? { state: "checking" } : { state: "absent" },
      tsrResult: tsrBytes ? { state: "checking" } : { state: "absent" },
    }
    renderSummary()
    await checkMerkleRoot()
    const filesCard = $("files-card")
    filesCard.classList.remove("hidden")

    // Kick off OTS + TSR verification in background; re-render when each lands.
    if (otsBytes) {
      verifyOtsAgainstBitcoin(otsBytes, manifestBytes)
        .then((r) => { bundle.otsResult = r; renderSummary() })
        .catch((e) => { bundle.otsResult = { state: "error", error: e.message }; renderSummary() })
    }
    if (tsrBytes) {
      const tsrPromise = FREETSA_CA_PEM
        ? verifyTsrFully(tsrBytes, manifestBytes, FREETSA_CA_PEM)
        : verifyTsrAgainstManifest(tsrBytes, manifestBytes)
      tsrPromise
        .then((r) => { bundle.tsrResult = r; renderSummary() })
        .catch((e) => { bundle.tsrResult = { state: "error", error: e.message }; renderSummary() })
    }
    // Nudge the user to the next step — scroll + brief highlight so they know
    // "ora devi caricare i file".
    setTimeout(() => {
      filesCard.scrollIntoView({ block: "center", behavior: "smooth" })
      filesCard.classList.add("flash-card")
      setTimeout(() => filesCard.classList.remove("flash-card"), 2200)
    }, 200)
  } catch (e) {
    err.textContent = "Errore: " + (e.message || String(e))
    err.classList.remove("hidden")
    bundle = null
  } finally {
    $("drop-bundle-title").textContent = "Trascina il pacchetto .zip"
  }
}

function renderSummary() {
  const s = $("bundle-summary")
  const m = bundle.manifest
  const sealedItaly = new Date(m.sealedAt).toLocaleString("it-IT")
  const signed = bundle.sigStatus.state === "valid"

  // Use a neutral dot when the bundle is not signed by Svelio, to avoid the
  // green-tick misread on a hand-forged but math-valid svelio-integrity-v1
  // bundle.
  const head = el(
    "div",
    { class: "summary-head " + (signed ? "signed" : "unsigned") },
    el("div", { class: "dot" }, signed ? "✓" : "?"),
    signed ? "Pacchetto caricato e firmato da Svelio" : "Pacchetto caricato",
  )

  function entry(label, value, strong) {
    return el("div", {},
      el("dt", { text: label }),
      el("dd", {}, strong ? el("strong", { text: value }) : value),
    )
  }
  const grid = el("dl", { class: "summary-grid" },
    entry("Progetto", m.project?.title ?? "—", true),
    entry("Mittente", m.project?.sender ?? "—"),
    entry("Sigillato il", sealedItaly),
    entry("File nel sigillo", String(m.files.length)),
  )

  // Badges: "ok" (green) = validated by this verifier; "present" (neutral) =
  // file is in the bundle but cannot be fully checked in-browser (OTS/TSR need
  // CLI tools, see the "Verifiche manuali" section).
  function badge(label, state, title) {
    const node = el("span", { class: "badge " + state }, label)
    if (title) node.setAttribute("title", title)
    return node
  }
  const badges = el("div", { class: "summary-badges" },
    badge("manifest.json", "ok"),
    badge(
      "manifest.sig",
      bundle.sigStatus.state === "valid" ? "ok" : bundle.sigStatus.state === "missing" ? "absent" : "error",
    ),
    badge(
      "ots.bin",
      otsBadge(bundle.otsResult),
      "Verifica completa dell'ancoraggio Bitcoin in-browser",
    ),
    badge(
      "tsr.bin",
      tsrBadge(bundle.tsrResult),
      "Controllo messageImprint della marca RFC 3161 in-browser",
    ),
    badge("chiave pubblica", bundle.hasPubKey ? "ok" : "absent"),
  )

  // Put the signature verdict above the summary details: it is the most
  // consequential piece of information and must not be visually below a
  // bright green check that could be misread as "verified by Svelio".
  s.replaceChildren(
    head,
    renderSignatureVerdict(),
    renderOtsVerdict(),
    renderTsrVerdict(),
    grid,
    badges,
  )
  s.classList.remove("hidden")
}

function renderOtsVerdict() {
  const r = bundle.otsResult || { state: "absent" }
  if (r.state === "absent") return document.createTextNode("")
  const box = el("div", { class: "sig-box attest-box " + mapAttestState(r.state) })
  const icon = el("div", { class: "sig-dot" })
  const body = el("div", { class: "sig-body" })
  const title = el("div", { class: "sig-title" })
  if (r.state === "checking") {
    icon.textContent = "…"
    title.textContent = "Verifica Bitcoin in corso"
    body.textContent = "Chiediamo a mempool.space l'header del blocco dichiarato nel .ots."
  } else if (r.state === "confirmed") {
    icon.textContent = "✓"
    title.append(
      "Ancora Bitcoin verificata ",
      el("span", { class: "sig-key" }, "(blocco " + r.attestation.height + ")"),
    )
    const when = r.block.timestamp ? new Date(r.block.timestamp * 1000).toLocaleString("it-IT") : null
    body.append(
      "La Merkle root del blocco " + r.attestation.height + " contiene l'impronta di questo sigillo.",
      el("br"),
      el("small", { style: "color:var(--muted)" },
        "Verificato su " + r.block.explorer + (when ? " · blocco del " + when : ""),
      ),
      el("br"),
      el("a", {
        href: "https://mempool.space/block/" + r.block.blockHash,
        target: "_blank",
        rel: "noreferrer",
        style: "color:var(--blue); font-size:11px",
      }, "Apri il blocco su mempool.space ↗"),
    )
  } else if (r.state === "pending") {
    icon.textContent = "!"
    title.textContent = "Ancoraggio Bitcoin in attesa"
    body.textContent =
      "Il .ots contiene solo attestazioni calendar, non ancora ancorato in un blocco Bitcoin. " +
      "I calendar aggregano e scrivono su Bitcoin in batch — ricontrolla tra qualche ora."
  } else {
    icon.textContent = "✗"
    title.textContent = "Verifica Bitcoin fallita"
    body.textContent = r.error || "errore sconosciuto"
  }
  box.append(icon, el("div", { class: "sig-text" }, title, body))
  return box
}

function renderTsrVerdict() {
  const r = bundle.tsrResult || { state: "absent" }
  if (r.state === "absent") return document.createTextNode("")
  const box = el("div", { class: "sig-box attest-box " + mapAttestState(r.state) })
  const icon = el("div", { class: "sig-dot" })
  const body = el("div", { class: "sig-body" })
  const title = el("div", { class: "sig-title" })
  if (r.state === "checking") {
    icon.textContent = "…"
    title.textContent = "Verifica FreeTSA in corso"
  } else if (r.state === "fully-verified") {
    icon.textContent = "✓"
    title.append(
      "Marca temporale FreeTSA verificata ",
      r.genTimeRaw ? el("span", { class: "sig-key" }, "(" + formatGenTime(r) + ")") : null,
    )
    body.append(
      "Firma RSA SignerInfo valida + catena certificati verificata contro la CA FreeTSA pinnata. ",
      "La marca " + r.hashAlg + " RFC 3161 copre esattamente il manifest di questo pacchetto.",
      el("br"),
      el("small", { style: "color:var(--muted)" },
        "CA fingerprint SHA-256: " + (r.caFingerprint ? r.caFingerprint.slice(0, 16) + "…" : "?"),
      ),
    )
  } else if (r.state === "ok") {
    // Partial verification (CA PEM not loaded) — fallback path
    icon.textContent = "✓"
    title.append(
      "Marca temporale FreeTSA (parziale) ",
      r.genTimeRaw ? el("span", { class: "sig-key" }, "(" + formatGenTime(r) + ")") : null,
    )
    body.textContent =
      "messageImprint corrisponde al manifest, ma non abbiamo potuto caricare la CA per validare la firma. Ricarica la pagina."
  } else if (r.state === "ca-fingerprint-mismatch" || r.state === "cert-chain-invalid" || r.state === "signature-invalid") {
    icon.textContent = "✗"
    title.textContent = "Firma TSR non valida"
    body.textContent = r.error || "errore sconosciuto"
  } else if (r.state === "mismatch" || r.state === "error") {
    icon.textContent = "✗"
    title.textContent = "Marca temporale non valida"
    body.textContent = r.error || "errore sconosciuto"
  } else if (r.state === "unsupported") {
    icon.textContent = "!"
    title.textContent = "Algoritmo TSR non supportato"
    body.textContent = r.error
  }
  box.append(icon, el("div", { class: "sig-text" }, title, body))
  return box
}

function formatGenTime(r) {
  if (r.genTime instanceof Date && !isNaN(r.genTime)) {
    return r.genTime.toLocaleString("it-IT", { dateStyle: "medium", timeStyle: "medium" })
  }
  return r.genTimeRaw
}

function mapAttestState(s) {
  if (s === "confirmed" || s === "ok" || s === "fully-verified") return "valid"
  if (s === "pending" || s === "checking" || s === "unsupported") return "missing"
  return "invalid"
}
function otsBadge(r) {
  if (!r || r.state === "absent") return "absent"
  if (r.state === "confirmed") return "ok"
  if (r.state === "checking" || r.state === "pending") return "present"
  return "error"
}
function tsrBadge(r) {
  if (!r || r.state === "absent") return "absent"
  if (r.state === "fully-verified" || r.state === "ok") return "ok"
  if (r.state === "checking") return "present"
  return "error"
}

function renderSignatureVerdict() {
  const st = bundle.sigStatus
  const box = el("div", { class: "sig-box " + st.state })
  const icon = el("div", { class: "sig-dot" })
  let title, body
  if (st.state === "valid") {
    icon.textContent = "✓"
    title = el("div", { class: "sig-title" },
      "Firmato da Svelio ",
      el("span", { class: "sig-key" }, "(" + st.keyId + ")"),
    )
    body = el("div", { class: "sig-body" },
      "La firma Ed25519 del manifest è stata verificata con una chiave pubblica canonica di Svelio. Il pacchetto è stato emesso dai server Svelio.",
    )
  } else if (st.state === "invalid") {
    icon.textContent = "✗"
    title = el("div", { class: "sig-title" }, "Firma non valida")
    body = el("div", { class: "sig-body" },
      "La firma è presente ma non corrisponde a nessuna chiave pubblica canonica Svelio. ",
      st.reason ? "Dettaglio: " + st.reason + ". " : "",
      "Il pacchetto potrebbe essere stato manomesso o prodotto da un'altra fonte.",
    )
  } else {
    // missing
    icon.textContent = "!"
    title = el("div", { class: "sig-title" }, "Firma assente")
    body = el("div", { class: "sig-body" },
      "Questo pacchetto non include una firma Ed25519 del manifest. Il contenuto crittografico è comunque verificabile, ma l'attribuzione a Svelio non può essere confermata offline. Ri-scarica il pacchetto da ",
      el("code", { text: "svelio.app/v/<id>" }),
      " per ottenerne uno firmato.",
    )
  }
  box.append(icon, el("div", { class: "sig-text" }, title, body))
  return box
}

async function checkMerkleRoot() {
  const expected = bundle.manifest.merkleRoot
  const hashes = bundle.manifest.files.map((f) => f.sha256)
  const computed = await merkleRoot(hashes)
  $("root-expected").textContent = expected
  $("root-computed").textContent = computed
  const match = computed === expected
  const signed = bundle.sigStatus.state === "valid"
  const v = $("root-verdict")
  let cls, label, sym
  if (!match) {
    cls = "err"
    sym = "✗"
    label = "Mismatch: il manifest è stato manomesso o corrotto"
  } else if (signed) {
    cls = "ok"
    sym = "✓"
    label = "Integrità del manifest confermata (e firmata da Svelio)"
  } else {
    cls = "warn"
    sym = "!"
    label = "Il manifest è matematicamente coerente, ma non è firmato da Svelio"
  }
  v.className = "verdict " + cls
  v.replaceChildren(el("div", { class: "dot" }, sym), label)
  $("root-card").classList.remove("hidden")
}

async function verifyFiles(fileList) {
  if (!bundle) return
  $("drop-files-title").textContent = "Calcolo impronte…"
  const list = $("file-results")
  list.replaceChildren()
  const manifestByHash = new Map(bundle.manifest.files.map((f) => [f.sha256, f]))
  for (const f of fileList) {
    if (fileTooLarge(f)) {
      const title = el("div", { class: "title", text: f.name })
      const sub = el("div", { class: "sub" },
        `File troppo grande (${(f.size / 1024 / 1024).toFixed(0)} MB). Massimo ${MAX_FILE_BYTES / 1024 / 1024} MB per verifica via browser; usa shasum/Get-FileHash da CLI.`,
      )
      const li = el("li", { class: "err" },
        el("div", { class: "dot" }, "!"),
        el("div", { style: "flex:1;min-width:0" }, title, sub),
      )
      list.appendChild(li)
      continue
    }
    const buf = await f.arrayBuffer()
    const hash = await sha256Hex(buf)
    const matched = manifestByHash.get(hash)

    const title = el("div", { class: "title", text: f.name })
    const sub = el("div", { class: "sub" })
    if (matched) {
      sub.append(
        "Corrisponde al file ",
        el("strong", { text: matched.name }),
        " nel sigillo.",
      )
    } else {
      sub.textContent =
        "Non presente nel manifest. Il file è diverso o non fa parte della consegna."
    }
    const li = el(
      "li",
      { class: matched ? "ok" : "err" },
      el("div", { class: "dot" }, matched ? "✓" : "✗"),
      el("div", { style: "flex:1;min-width:0" }, title, sub),
    )
    list.appendChild(li)
  }
  $("drop-files-title").textContent = "Trascina uno o più file"
}

// ---------------------------------------------------------------------------
// Tutorial modal — mirrors the in-app VerifyTutorial component. Pure DOM,
// no innerHTML with dynamic data, CSP-compliant.
// ---------------------------------------------------------------------------
const TUTORIAL_SEEN_KEY = "svelio.verify.tutorial.seen.v1"
const TOTAL_SLIDES = 5

function markTutorialSeen() {
  try { localStorage.setItem(TUTORIAL_SEEN_KEY, "1") } catch {}
}

function openTutorial(initialStep = 1) {
  const root = $("tutorial-root")
  if (!root) return
  root.hidden = false
  root.setAttribute("aria-hidden", "false")
  document.body.classList.add("tutorial-open")
  setTutorialStep(initialStep)
  // Move focus to the modal for keyboard users.
  const closeBtn = root.querySelector(".tutorial-close")
  if (closeBtn) closeBtn.focus()
}

function closeTutorial() {
  const root = $("tutorial-root")
  if (!root) return
  root.hidden = true
  root.setAttribute("aria-hidden", "true")
  document.body.classList.remove("tutorial-open")
  markTutorialSeen()
}

function setTutorialStep(step) {
  const clamped = Math.max(1, Math.min(TOTAL_SLIDES, step))
  const root = $("tutorial-root")
  if (!root) return
  root.dataset.step = String(clamped)

  // toggle slides
  root.querySelectorAll(".tutorial-slide").forEach((el) => {
    const n = Number(el.getAttribute("data-slide"))
    el.hidden = n !== clamped
  })

  // dots
  root.querySelectorAll(".tutorial-dot").forEach((dot) => {
    const n = Number(dot.getAttribute("data-step"))
    dot.classList.toggle("active", n === clamped)
    dot.classList.toggle("past", n < clamped)
  })

  // step label
  const label = $("tutorial-step-label")
  if (label) label.textContent = `Passo ${clamped} di ${TOTAL_SLIDES}`

  // nav buttons — single "next" button that morphs into a close affordance
  // on the last slide.
  const back = root.querySelector("[data-tutorial-prev]")
  const next = root.querySelector("[data-tutorial-next]")
  if (back) back.disabled = clamped === 1
  if (next) {
    const isLast = clamped === TOTAL_SLIDES
    const label = next.querySelector(".tutorial-next-label")
    const arrow = next.querySelector(".tutorial-next-arrow")
    const check = next.querySelector(".tutorial-next-check")
    if (label) label.textContent = isLast ? "Chiudi" : "Avanti"
    if (arrow) arrow.hidden = isLast
    if (check) check.hidden = !isLast
    next.dataset.action = isLast ? "finish" : "next"
  }
}

function initTutorial() {
  const root = $("tutorial-root")
  if (!root) return

  // triggers
  const openBtn = $("open-tutorial")
  if (openBtn) openBtn.addEventListener("click", () => openTutorial(1))

  // close actions (backdrop + X button share [data-tutorial-close])
  root.querySelectorAll("[data-tutorial-close]").forEach((el) => {
    el.addEventListener("click", closeTutorial)
  })

  // nav
  root.querySelectorAll("[data-tutorial-prev]").forEach((el) => {
    el.addEventListener("click", () => {
      const cur = Number(root.dataset.step || "1")
      setTutorialStep(cur - 1)
    })
  })
  root.querySelectorAll("[data-tutorial-next]").forEach((el) => {
    el.addEventListener("click", () => {
      const cur = Number(root.dataset.step || "1")
      if (el.dataset.action === "finish") {
        closeTutorial()
        const target = $("drop-bundle")
        if (target) {
          setTimeout(() => {
            target.scrollIntoView({ block: "center", behavior: "smooth" })
            target.classList.add("flash")
            setTimeout(() => target.classList.remove("flash"), 2200)
          }, 180)
        }
      } else {
        setTutorialStep(cur + 1)
      }
    })
  })

  // dot direct-click
  root.querySelectorAll(".tutorial-dot").forEach((dot) => {
    dot.addEventListener("click", () => {
      const n = Number(dot.getAttribute("data-step"))
      if (n) setTutorialStep(n)
    })
  })

  // Esc + arrow keys
  document.addEventListener("keydown", (e) => {
    if (root.hidden) return
    if (e.key === "Escape") {
      e.preventDefault()
      closeTutorial()
    } else if (e.key === "ArrowRight") {
      const cur = Number(root.dataset.step || "1")
      setTutorialStep(cur + 1)
    } else if (e.key === "ArrowLeft") {
      const cur = Number(root.dataset.step || "1")
      setTutorialStep(cur - 1)
    }
  })

  // Auto-open on first visit
  try {
    if (!localStorage.getItem(TUTORIAL_SEEN_KEY)) {
      openTutorial(1)
    }
  } catch {
    // private mode / no localStorage — skip auto-open
  }
}

initTutorial()
