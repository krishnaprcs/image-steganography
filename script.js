/**
 * ============================================================================
 * Image Steganography — LSB + Optional Password Encryption (AES-256-GCM)
 * ============================================================================
 *
 * HOW THE ALGORITHM WORKS:
 *
 * 1. OPTIONAL PASSWORD ENCRYPTION:
 *    - If NO password is provided: the message is stored as plain UTF-8 bytes
 *      (mode = 0x00).
 *    - If a password IS provided:
 *        * Primary (Web Crypto API): Uses PBKDF2-SHA256 (100,000 iterations)
 *          with a random 16-byte salt to derive a 256-bit AES-GCM key, then
 *          encrypts the UTF-8 message with a random 12-byte IV (mode = 0x01).
 *          AES-GCM also includes an authentication tag so any wrong password
 *          fails cleanly instead of producing garbled text.
 *        * Fallback (pure JS, mode = 0x02): Used automatically only if a browser
 *          runs in a restricted non-secure file:// context without crypto.subtle.
 *
 * 2. PACKET FORMAT (9-BYTE HEADER + PAYLOAD):
 *    [Bytes 0..3] Magic Signature: "STEG" (0x53, 0x54, 0x45, 0x47)
 *    [Byte  4   ] Mode Flag:
 *                   0x00 = Unencrypted UTF-8
 *                   0x01 = AES-256-GCM Password Protected
 *                   0x02 = Fallback Keystream + Checksum Password Protected
 *    [Bytes 5..8] 32-bit big-endian payload byte length
 *    [Bytes 9..N] Payload bytes
 *
 * 3. LSB EMBEDDING & EXTRACTION:
 *    - Every pixel on an HTML5 <canvas> has 4 channels: [R, G, B, A].
 *    - We embed 3 bits per pixel (1 bit in R, 1 in G, 1 in B), skipping Alpha.
 *    - Encoding replaces the last bit of each channel: `(channel & 0xFE) | bit`.
 *    - Decoding reads the last bit of each channel: `channel & 1`.
 *    - Output is always saved as lossless PNG so compression never destroys bits.
 */

(function () {
  "use strict";

  const MAGIC_BYTES = [0x53, 0x54, 0x45, 0x47]; // "STEG"
  const HEADER_BYTE_LENGTH = 9; // 4 magic + 1 mode + 4 payload length

  const MODE_PLAIN = 0x00;
  const MODE_AES_GCM = 0x01;
  const MODE_FALLBACK_XOR = 0x02;

  const CRYPTO_OVERHEAD_BYTES = 16 + 12 + 16; // 16B salt + 12B IV + 16B AES-GCM tag

  function getSubtleCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto.subtle;
    }
    return null;
  }

  function getRandomBytes(length) {
    const buf = new Uint8Array(length);
    if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(buf);
    } else {
      for (let i = 0; i < length; i++) {
        buf[i] = Math.floor(Math.random() * 256);
      }
    }
    return buf;
  }

  // --------------------------------------------------------------------------
  // CRYPTO HELPERS (AES-256-GCM + PURE-JS FALLBACK)
  // --------------------------------------------------------------------------

  async function deriveAesKey(password, salt, usage) {
    const subtle = getSubtleCrypto();
    const enc = new TextEncoder();
    const keyMaterial = await subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      [usage]
    );
  }

  /** Encrypt UTF-8 message bytes with AES-256-GCM -> [16B salt][12B IV][ciphertext+tag]. */
  async function encryptWithAesGcm(messageBytes, password) {
    const subtle = getSubtleCrypto();
    const salt = getRandomBytes(16);
    const iv = getRandomBytes(12);
    const key = await deriveAesKey(password, salt, "encrypt");
    const cipherBuf = await subtle.encrypt({ name: "AES-GCM", iv }, key, messageBytes);
    const cipherBytes = new Uint8Array(cipherBuf);

    const out = new Uint8Array(16 + 12 + cipherBytes.length);
    out.set(salt, 0);
    out.set(iv, 16);
    out.set(cipherBytes, 28);
    return out;
  }

  /** Decrypt AES-256-GCM payload -> original UTF-8 bytes. */
  async function decryptWithAesGcm(payload, password) {
    if (payload.length <= 28) {
      throw new Error("Encrypted payload is corrupted or incomplete.");
    }
    const subtle = getSubtleCrypto();
    if (!subtle) {
      throw new Error("Web Crypto API is unavailable in this browser context. Open via localhost or HTTPS to decrypt.");
    }

    const salt = payload.slice(0, 16);
    const iv = payload.slice(16, 28);
    const cipherBytes = payload.slice(28);

    try {
      const key = await deriveAesKey(password, salt, "decrypt");
      const plainBuf = await subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
      return new Uint8Array(plainBuf);
    } catch {
      throw new Error("Incorrect password! Unable to unlock the hidden message.");
    }
  }

  /** Pure-JS FNV/xorshift stream + 8-byte tag fallback when subtle crypto is absent. */
  function fallbackKeystreamTransform(data, password, salt) {
    const pwdBytes = new TextEncoder().encode(password);
    let h1 = 0x811c9dc5;
    let h2 = 0x9e3779b9;
    for (let i = 0; i < pwdBytes.length; i++) {
      h1 ^= pwdBytes[i];
      h1 = Math.imul(h1, 0x01000193) >>> 0;
      h2 ^= pwdBytes[i] + i;
      h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
    }
    for (let i = 0; i < salt.length; i++) {
      h1 ^= salt[i];
      h1 = Math.imul(h1, 0x01000193) >>> 0;
      h2 ^= salt[i];
      h2 = Math.imul(h2, 0xc2b2ae35) >>> 0;
    }

    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      h1 ^= h1 << 13;
      h1 ^= h1 >>> 17;
      h1 ^= h1 << 5;
      h2 = (Math.imul(h2, 1664525) + 1013904223) >>> 0;
      const mask = ((h1 ^ h2) >>> ((i % 4) * 8)) & 0xff;
      out[i] = data[i] ^ mask;
    }
    return out;
  }

  function computeSimpleTag(bytes, password, salt) {
    const pwdBytes = new TextEncoder().encode(password);
    let a = 0xdeadbeef;
    let b = 0x41c6ce57;
    const mix = (byteVal) => {
      a = Math.imul(a ^ byteVal, 2654435761) >>> 0;
      b = Math.imul(b ^ byteVal, 1597334677) >>> 0;
    };
    pwdBytes.forEach(mix);
    salt.forEach(mix);
    bytes.forEach(mix);
    const tag = new Uint8Array(8);
    tag[0] = (a >>> 24) & 0xff;
    tag[1] = (a >>> 16) & 0xff;
    tag[2] = (a >>> 8) & 0xff;
    tag[3] = a & 0xff;
    tag[4] = (b >>> 24) & 0xff;
    tag[5] = (b >>> 16) & 0xff;
    tag[6] = (b >>> 8) & 0xff;
    tag[7] = b & 0xff;
    return tag;
  }

  function encryptWithFallback(messageBytes, password) {
    const salt = getRandomBytes(16);
    const tag = computeSimpleTag(messageBytes, password, salt);
    const cipher = fallbackKeystreamTransform(messageBytes, password, salt);
    const out = new Uint8Array(16 + 8 + cipher.length);
    out.set(salt, 0);
    out.set(tag, 16);
    out.set(cipher, 24);
    return out;
  }

  function decryptWithFallback(payload, password) {
    if (payload.length <= 24) {
      throw new Error("Encrypted payload is corrupted or incomplete.");
    }
    const salt = payload.slice(0, 16);
    const expectedTag = payload.slice(16, 24);
    const cipher = payload.slice(24);
    const plain = fallbackKeystreamTransform(cipher, password, salt);
    const actualTag = computeSimpleTag(plain, password, salt);

    for (let i = 0; i < 8; i++) {
      if (expectedTag[i] !== actualTag[i]) {
        throw new Error("Incorrect password! Unable to unlock the hidden message.");
      }
    }
    return plain;
  }

  // --------------------------------------------------------------------------
  // CORE LSB PACKET + BIT EMBEDDING / EXTRACTION
  // --------------------------------------------------------------------------

  /**
   * Build binary steganography packet (9-byte header + plain or encrypted payload).
   * @param {string} message
   * @param {string} [password=""]
   * @returns {Promise<{ packet: Uint8Array, mode: number, plainBytes: number }>}
   */
  async function buildStegoPacket(message, password = "") {
    const messageBytes = new TextEncoder().encode(message);
    let mode = MODE_PLAIN;
    let payload = messageBytes;

    if (password && password.length > 0) {
      if (getSubtleCrypto()) {
        mode = MODE_AES_GCM;
        payload = await encryptWithAesGcm(messageBytes, password);
      } else {
        mode = MODE_FALLBACK_XOR;
        payload = encryptWithFallback(messageBytes, password);
      }
    }

    const packet = new Uint8Array(HEADER_BYTE_LENGTH + payload.length);

    // Bytes 0..3: Magic signature "STEG"
    for (let i = 0; i < MAGIC_BYTES.length; i++) {
      packet[i] = MAGIC_BYTES[i];
    }

    // Byte 4: Mode flag (0x00 = plain, 0x01 = AES-GCM, 0x02 = fallback)
    packet[4] = mode;

    // Bytes 5..8: 32-bit big-endian payload byte length
    const len = payload.length;
    packet[5] = (len >>> 24) & 0xff;
    packet[6] = (len >>> 16) & 0xff;
    packet[7] = (len >>> 8) & 0xff;
    packet[8] = len & 0xff;

    packet.set(payload, HEADER_BYTE_LENGTH);
    return { packet, mode, plainBytes: messageBytes.length };
  }

  /**
   * Calculate how many payload bytes fit in an image of (width x height).
   * @param {number} width
   * @param {number} height
   * @param {boolean} [withPassword=false]
   * @returns {number}
   */
  function getMaxMessageBytes(width, height, withPassword = false) {
    const totalRgbBits = width * height * 3;
    const totalBytes = Math.floor(totalRgbBits / 8);
    const overhead = HEADER_BYTE_LENGTH + (withPassword ? CRYPTO_OVERHEAD_BYTES : 0);
    return Math.max(0, totalBytes - overhead);
  }

  /**
   * Embed a secret message (optionally encrypted with `password`) into RGBA pixels.
   * @param {Uint8ClampedArray} pixelData
   * @param {string} message
   * @param {string} [password=""]
   * @returns {Promise<{ bytesWritten: number, payloadBytes: number, bitsWritten: number, protected: boolean }>}
   */
  async function encodeMessageIntoPixels(pixelData, message, password = "") {
    if (!message || message.length === 0) {
      throw new Error("Please enter a secret message to hide.");
    }

    const { packet, mode, plainBytes } = await buildStegoPacket(message, password);
    const totalBitsNeeded = packet.length * 8;
    const totalPixels = pixelData.length / 4;
    const availableBits = totalPixels * 3;

    if (totalBitsNeeded > availableBits) {
      const maxPlain = getMaxMessageBytes(totalPixels, 1, Boolean(password));
      throw new Error(
        `Message is too large (${plainBytes} bytes) for this image (max ~${maxPlain} bytes). Use a larger image or shorter text.`
      );
    }

    let channelIndex = 0;
    for (let byteIdx = 0; byteIdx < packet.length; byteIdx++) {
      const currentByte = packet[byteIdx];
      for (let bitPos = 7; bitPos >= 0; bitPos--) {
        if (channelIndex % 4 === 3) {
          channelIndex++;
        }
        const bit = (currentByte >> bitPos) & 1;
        pixelData[channelIndex] = (pixelData[channelIndex] & 0xfe) | bit;
        channelIndex++;
      }
    }

    return {
      bytesWritten: plainBytes,
      payloadBytes: packet.length - HEADER_BYTE_LENGTH,
      bitsWritten: totalBitsNeeded,
      protected: mode !== MODE_PLAIN,
    };
  }

  /** Read `byteCount` bytes starting at `startByteIndex` from RGBA pixel LSBs. */
  function readBytesFromPixelLSBs(pixelData, startByteIndex, byteCount) {
    const result = new Uint8Array(byteCount);
    const startBitIndex = startByteIndex * 8;
    const pixelOffset = Math.floor(startBitIndex / 3);
    const rgbSubOffset = startBitIndex % 3;
    let channelIndex = pixelOffset * 4 + rgbSubOffset;

    for (let i = 0; i < byteCount; i++) {
      let byteValue = 0;
      for (let bitPos = 0; bitPos < 8; bitPos++) {
        if (channelIndex % 4 === 3) {
          channelIndex++;
        }
        if (channelIndex >= pixelData.length) {
          throw new Error("Image ended unexpectedly while reading hidden data.");
        }
        const lsb = pixelData[channelIndex] & 1;
        byteValue = (byteValue << 1) | lsb;
        channelIndex++;
      }
      result[i] = byteValue;
    }

    return result;
  }

  /**
   * Inspect header only so UI can detect if an uploaded PNG is locked with a password.
   * @param {Uint8ClampedArray} pixelData
   * @returns {{ hasStego: boolean, isProtected: boolean, mode: number, payloadLength: number }}
   */
  function inspectStegoHeader(pixelData) {
    const totalPixels = pixelData.length / 4;
    const availableBytes = Math.floor((totalPixels * 3) / 8);
    if (availableBytes < HEADER_BYTE_LENGTH) {
      return { hasStego: false, isProtected: false, mode: MODE_PLAIN, payloadLength: 0 };
    }

    const header = readBytesFromPixelLSBs(pixelData, 0, HEADER_BYTE_LENGTH);
    for (let i = 0; i < MAGIC_BYTES.length; i++) {
      if (header[i] !== MAGIC_BYTES[i]) {
        return { hasStego: false, isProtected: false, mode: MODE_PLAIN, payloadLength: 0 };
      }
    }

    const mode = header[4];
    const payloadLength =
      ((header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8]) >>> 0;
    const validMode = mode === MODE_PLAIN || mode === MODE_AES_GCM || mode === MODE_FALLBACK_XOR;
    const validLen = payloadLength > 0 && HEADER_BYTE_LENGTH + payloadLength <= availableBytes;

    return {
      hasStego: validMode && validLen,
      isProtected: mode !== MODE_PLAIN,
      mode,
      payloadLength,
    };
  }

  /**
   * Extract (and decrypt if password-protected) a hidden message from RGBA pixel data.
   * @param {Uint8ClampedArray} pixelData
   * @param {string} [password=""]
   * @returns {Promise<{ message: string, wasProtected: boolean }>}
   */
  async function decodeMessageFromPixels(pixelData, password = "") {
    const info = inspectStegoHeader(pixelData);
    if (!info.hasStego) {
      throw new Error(
        "No hidden message found in this image. Ensure it was encoded here and saved as PNG."
      );
    }

    const payloadBytes = readBytesFromPixelLSBs(
      pixelData,
      HEADER_BYTE_LENGTH,
      info.payloadLength
    );

    let plainBytes;
    if (info.mode === MODE_PLAIN) {
      plainBytes = payloadBytes;
    } else {
      if (!password || password.length === 0) {
        throw new Error(
          "This image is password-protected. Please enter the password to reveal the message."
        );
      }
      if (info.mode === MODE_AES_GCM) {
        plainBytes = await decryptWithAesGcm(payloadBytes, password);
      } else {
        plainBytes = decryptWithFallback(payloadBytes, password);
      }
    }

    try {
      const message = new TextDecoder("utf-8", { fatal: true }).decode(plainBytes);
      return { message, wasProtected: info.isProtected };
    } catch {
      throw new Error("Decoded data is not valid UTF-8 text.");
    }
  }

  // Export for Node.js automated tests
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      MODE_PLAIN,
      MODE_AES_GCM,
      MODE_FALLBACK_XOR,
      buildStegoPacket,
      getMaxMessageBytes,
      encodeMessageIntoPixels,
      inspectStegoHeader,
      decodeMessageFromPixels,
      encryptWithFallback,
      decryptWithFallback,
    };
  }

  if (typeof document === "undefined") {
    return;
  }

  // =========================================================================
  // BROWSER UI CONTROLLER
  // =========================================================================

  const statusBanner = document.getElementById("statusBanner");
  const statusIcon = document.getElementById("statusIcon");
  const statusText = document.getElementById("statusText");
  const dismissStatusBtn = document.getElementById("dismissStatusBtn");

  // Encode DOM references
  const encodeImageInput = document.getElementById("encodeImageInput");
  const encodeDropzone = document.getElementById("encodeDropzone");
  const encodeFileName = document.getElementById("encodeFileName");
  const useSampleBtn = document.getElementById("useSampleBtn");
  const secretMessageInput = document.getElementById("secretMessageInput");
  const capacityCounter = document.getElementById("capacityCounter");
  const capacityBarFill = document.getElementById("capacityBarFill");
  const encodePasswordInput = document.getElementById("encodePasswordInput");
  const toggleEncodePwdBtn = document.getElementById("toggleEncodePwdBtn");
  const passwordStrengthLabel = document.getElementById("passwordStrengthLabel");
  const passwordStrengthFill = document.getElementById("passwordStrengthFill");
  const encodeBtn = document.getElementById("encodeBtn");
  const downloadBtn = document.getElementById("downloadBtn");
  const sendToDecodeBtn = document.getElementById("sendToDecodeBtn");
  const resetEncodeBtn = document.getElementById("resetEncodeBtn");
  const originalPreview = document.getElementById("originalPreview");
  const originalPlaceholder = document.getElementById("originalPlaceholder");
  const originalMeta = document.getElementById("originalMeta");
  const encodedPreview = document.getElementById("encodedPreview");
  const encodedPlaceholder = document.getElementById("encodedPlaceholder");
  const encodedMeta = document.getElementById("encodedMeta");

  // Decode DOM references
  const decodeImageInput = document.getElementById("decodeImageInput");
  const decodeDropzone = document.getElementById("decodeDropzone");
  const decodeFileName = document.getElementById("decodeFileName");
  const decodeLockBadge = document.getElementById("decodeLockBadge");
  const decodePreview = document.getElementById("decodePreview");
  const decodePlaceholder = document.getElementById("decodePlaceholder");
  const decodeMeta = document.getElementById("decodeMeta");
  const decodePasswordInput = document.getElementById("decodePasswordInput");
  const toggleDecodePwdBtn = document.getElementById("toggleDecodePwdBtn");
  const decodePwdHint = document.getElementById("decodePwdHint");
  const decodeBtn = document.getElementById("decodeBtn");
  const copyDecodedBtn = document.getElementById("copyDecodedBtn");
  const resetDecodeBtn = document.getElementById("resetDecodeBtn");
  const decodedOutput = document.getElementById("decodedOutput");
  const decodedLengthInfo = document.getElementById("decodedLengthInfo");

  const workCanvas = document.getElementById("workCanvas");
  const workCtx = workCanvas.getContext("2d", { willReadFrequently: true });

  // Application state
  let loadedEncodeImage = null;
  let loadedEncodeBaseName = "secret-image";
  let encodedDataUrl = "";
  let loadedDecodeImage = null;

  function showStatus(type, message) {
    const icons = { success: "✓", error: "!", info: "i" };
    statusBanner.className = `status-banner ${type}`;
    statusIcon.textContent = icons[type] || "i";
    statusText.textContent = message;
  }

  function hideStatus() {
    statusBanner.classList.add("hidden");
  }

  dismissStatusBtn.addEventListener("click", hideStatus);

  function loadImageFromDataUrl(dataUrl) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error("Could not load this image."));
      img.src = dataUrl;
    });
  }

  function loadImageFile(file) {
    return new Promise((resolve, reject) => {
      if (!file) {
        reject(new Error("No file selected."));
        return;
      }
      const validTypes = ["image/png", "image/jpeg", "image/jpg"];
      if (file.type && !validTypes.includes(file.type.toLowerCase())) {
        reject(new Error("Please upload a valid PNG or JPG image."));
        return;
      }
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const img = await loadImageFromDataUrl(reader.result);
          resolve({ img, dataUrl: reader.result });
        } catch (e) {
          reject(e);
        }
      };
      reader.onerror = () => reject(new Error("Failed to read file from disk."));
      reader.readAsDataURL(file);
    });
  }

  function updateCapacityDisplay() {
    const msgBytes = new TextEncoder().encode(secretMessageInput.value).length;
    const hasPassword = encodePasswordInput.value.length > 0;

    if (!loadedEncodeImage) {
      capacityCounter.textContent = `${msgBytes} bytes typed (upload an image to check limit)`;
      capacityCounter.classList.remove("over-limit");
      capacityBarFill.style.width = "0%";
      capacityBarFill.classList.remove("over-limit");
      return;
    }

    const maxBytes = getMaxMessageBytes(
      loadedEncodeImage.width,
      loadedEncodeImage.height,
      hasPassword
    );
    const pct = maxBytes > 0 ? Math.min(100, (msgBytes / maxBytes) * 100) : 100;
    const over = msgBytes > maxBytes;

    capacityCounter.textContent = `${msgBytes.toLocaleString()} / ${maxBytes.toLocaleString()} bytes (${pct.toFixed(1)}%)`;
    capacityCounter.classList.toggle("over-limit", over);
    capacityBarFill.style.width = `${pct}%`;
    capacityBarFill.classList.toggle("over-limit", over);
  }

  function updatePasswordStrength() {
    const pwd = encodePasswordInput.value;
    passwordStrengthFill.className = "strength-fill";

    if (!pwd) {
      passwordStrengthLabel.textContent = "Leave blank for no password";
      return;
    }

    let score = 0;
    if (pwd.length >= 6) score++;
    if (pwd.length >= 10) score++;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
    if (/\d/.test(pwd) || /[^A-Za-z0-9]/.test(pwd)) score++;

    if (score <= 1) {
      passwordStrengthFill.classList.add("weak");
      passwordStrengthLabel.textContent = "Strength: Weak";
    } else if (score <= 3) {
      passwordStrengthFill.classList.add("medium");
      passwordStrengthLabel.textContent = "Strength: Medium";
    } else {
      passwordStrengthFill.classList.add("strong");
      passwordStrengthLabel.textContent = "Strength: Strong";
    }
  }

  function wirePasswordToggle(inputEl, btnEl) {
    btnEl.addEventListener("click", () => {
      const showing = inputEl.type === "text";
      inputEl.type = showing ? "password" : "text";
      btnEl.textContent = showing ? "Show" : "Hide";
    });
  }

  wirePasswordToggle(encodePasswordInput, toggleEncodePwdBtn);
  wirePasswordToggle(decodePasswordInput, toggleDecodePwdBtn);

  function attachDropzone(dropzoneEl, inputEl, onFileSelected) {
    ["dragenter", "dragover"].forEach((evtName) => {
      dropzoneEl.addEventListener(evtName, (e) => {
        e.preventDefault();
        dropzoneEl.classList.add("drag-over");
      });
    });

    ["dragleave", "drop"].forEach((evtName) => {
      dropzoneEl.addEventListener(evtName, (e) => {
        e.preventDefault();
        dropzoneEl.classList.remove("drag-over");
      });
    });

    dropzoneEl.addEventListener("drop", (e) => {
      const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) onFileSelected(file);
    });

    inputEl.addEventListener("change", () => {
      const file = inputEl.files && inputEl.files[0];
      if (file) onFileSelected(file);
    });
  }

  // -------------------------------------------------------------------------
  // ENCODE SECTION HANDLERS
  // -------------------------------------------------------------------------

  function setEncodeCoverImage(img, dataUrl, displayName, sizeText) {
    loadedEncodeImage = img;
    loadedEncodeBaseName = displayName.replace(/\.[^.]+$/, "") || "encoded-image";
    encodeFileName.textContent = `${displayName} (${img.width} × ${img.height} px)`;

    originalPreview.src = dataUrl;
    originalPreview.classList.remove("hidden");
    originalPlaceholder.classList.add("hidden");
    originalMeta.textContent = `${img.width} × ${img.height} px • ${sizeText}`;

    encodedDataUrl = "";
    encodedPreview.src = "";
    encodedPreview.classList.add("hidden");
    encodedPlaceholder.classList.remove("hidden");
    encodedMeta.textContent = "";
    downloadBtn.disabled = true;
    sendToDecodeBtn.disabled = true;

    updateCapacityDisplay();
  }

  async function handleEncodeFileSelect(file) {
    try {
      const { img, dataUrl } = await loadImageFile(file);
      setEncodeCoverImage(img, dataUrl, file.name, `${(file.size / 1024).toFixed(1)} KB`);
      showStatus("info", `Loaded "${file.name}". Enter your message and password, then click Encode Message.`);
    } catch (err) {
      showStatus("error", err.message);
    }
  }

  attachDropzone(encodeDropzone, encodeImageInput, handleEncodeFileSelect);

  useSampleBtn.addEventListener("click", async () => {
    workCanvas.width = 640;
    workCanvas.height = 480;
    const grad = workCtx.createLinearGradient(0, 0, 640, 480);
    grad.addColorStop(0, "#1d3557");
    grad.addColorStop(0.5, "#457b9d");
    grad.addColorStop(1, "#e76f51");
    workCtx.fillStyle = grad;
    workCtx.fillRect(0, 0, 640, 480);

    // Subtle geometric circles so image looks natural
    workCtx.fillStyle = "rgba(255, 255, 255, 0.16)";
    workCtx.beginPath();
    workCtx.arc(480, 150, 95, 0, Math.PI * 2);
    workCtx.fill();
    workCtx.beginPath();
    workCtx.arc(170, 350, 125, 0, Math.PI * 2);
    workCtx.fill();

    const sampleUrl = workCanvas.toDataURL("image/png");
    const img = await loadImageFromDataUrl(sampleUrl);
    setEncodeCoverImage(img, sampleUrl, "sample_cover.png", "Generated Sample");
    showStatus("info", "Loaded 640 × 480 sample cover image. Type your message and password, then click Encode Message.");
  });

  secretMessageInput.addEventListener("input", updateCapacityDisplay);
  encodePasswordInput.addEventListener("input", () => {
    updatePasswordStrength();
    updateCapacityDisplay();
  });

  encodeBtn.addEventListener("click", async () => {
    if (!loadedEncodeImage) {
      showStatus("error", "Please upload a cover image (or click Use Sample Image) first.");
      return;
    }

    const message = secretMessageInput.value;
    if (!message.trim()) {
      showStatus("error", "Please enter a secret message to hide.");
      secretMessageInput.focus();
      return;
    }

    const password = encodePasswordInput.value;

    try {
      encodeBtn.disabled = true;
      workCanvas.width = loadedEncodeImage.width;
      workCanvas.height = loadedEncodeImage.height;

      // Opaque backdrop prevents alpha-premultiplication from corrupting LSBs
      workCtx.fillStyle = "#ffffff";
      workCtx.fillRect(0, 0, workCanvas.width, workCanvas.height);
      workCtx.drawImage(loadedEncodeImage, 0, 0);

      const imageData = workCtx.getImageData(0, 0, workCanvas.width, workCanvas.height);
      const stats = await encodeMessageIntoPixels(imageData.data, message, password);

      workCtx.putImageData(imageData, 0, 0);
      encodedDataUrl = workCanvas.toDataURL("image/png");

      encodedPreview.src = encodedDataUrl;
      encodedPreview.classList.remove("hidden");
      encodedPlaceholder.classList.add("hidden");
      const lockLabel = stats.protected ? "Password Locked" : "No Password";
      encodedMeta.textContent = `${workCanvas.width} × ${workCanvas.height} px PNG • ${stats.bitsWritten.toLocaleString()} bits • ${lockLabel}`;

      downloadBtn.disabled = false;
      sendToDecodeBtn.disabled = false;

      showStatus(
        "success",
        stats.protected
          ? `Message encrypted with your password and hidden (${stats.bitsWritten} bits). Download the PNG or click "Test in Decoder".`
          : `Message hidden (${stats.bitsWritten} bits, no password). Download the PNG or click "Test in Decoder".`
      );
    } catch (err) {
      showStatus("error", err.message);
    } finally {
      encodeBtn.disabled = false;
    }
  });

  downloadBtn.addEventListener("click", () => {
    if (!encodedDataUrl) {
      showStatus("error", "Encode a message into an image first.");
      return;
    }
    const link = document.createElement("a");
    link.href = encodedDataUrl;
    link.download = `${loadedEncodeBaseName}_encoded.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showStatus("success", `Downloaded "${loadedEncodeBaseName}_encoded.png".`);
  });

  // Load encoded output directly into the Reveal Message card for quick testing
  sendToDecodeBtn.addEventListener("click", async () => {
    if (!encodedDataUrl) return;
    try {
      const img = await loadImageFromDataUrl(encodedDataUrl);
      setDecodeTargetImage(img, encodedDataUrl, `${loadedEncodeBaseName}_encoded.png`, "From Encoder");
      decodePasswordInput.value = "";
      decodePasswordInput.focus();
      showStatus("info", "Loaded encoded image into Reveal Message. Enter the password and click Decode Message.");
    } catch (err) {
      showStatus("error", err.message);
    }
  });

  resetEncodeBtn.addEventListener("click", () => {
    loadedEncodeImage = null;
    encodedDataUrl = "";
    encodeImageInput.value = "";
    secretMessageInput.value = "";
    encodePasswordInput.value = "";
    encodeFileName.textContent = 'Supports PNG, JPG / JPEG — or click "Use Sample Image"';

    originalPreview.src = "";
    originalPreview.classList.add("hidden");
    originalPlaceholder.classList.remove("hidden");
    originalMeta.textContent = "";

    encodedPreview.src = "";
    encodedPreview.classList.add("hidden");
    encodedPlaceholder.classList.remove("hidden");
    encodedMeta.textContent = "";

    downloadBtn.disabled = true;
    sendToDecodeBtn.disabled = true;
    updatePasswordStrength();
    updateCapacityDisplay();
    capacityCounter.textContent = "Upload an image to view capacity";
    hideStatus();
  });

  // -------------------------------------------------------------------------
  // DECODE SECTION HANDLERS
  // -------------------------------------------------------------------------

  function setDecodeTargetImage(img, dataUrl, displayName, sizeText) {
    loadedDecodeImage = img;
    decodeFileName.textContent = `${displayName} (${img.width} × ${img.height} px)`;

    decodePreview.src = dataUrl;
    decodePreview.classList.remove("hidden");
    decodePlaceholder.classList.add("hidden");
    decodeMeta.textContent = `${img.width} × ${img.height} px • ${sizeText}`;

    decodedOutput.value = "";
    decodedLengthInfo.textContent = "";
    copyDecodedBtn.disabled = true;

    // Inspect header right away so we can tell the user if a password is required
    workCanvas.width = img.width;
    workCanvas.height = img.height;
    workCtx.clearRect(0, 0, workCanvas.width, workCanvas.height);
    workCtx.drawImage(img, 0, 0);
    const headerCheck = inspectStegoHeader(
      workCtx.getImageData(0, 0, workCanvas.width, workCanvas.height).data
    );

    decodeLockBadge.classList.remove("hidden", "unlocked");
    if (!headerCheck.hasStego) {
      decodeLockBadge.classList.add("hidden");
      decodePwdHint.textContent = "No hidden message header detected yet";
    } else if (headerCheck.isProtected) {
      decodeLockBadge.textContent = "Password Protected";
      decodePwdHint.textContent = "Password required to unlock this image";
    } else {
      decodeLockBadge.textContent = "No Password Needed";
      decodeLockBadge.classList.add("unlocked");
      decodePwdHint.textContent = "This image is not password-locked";
    }
  }

  async function handleDecodeFileSelect(file) {
    try {
      const { img, dataUrl } = await loadImageFile(file);
      setDecodeTargetImage(img, dataUrl, file.name, `${(file.size / 1024).toFixed(1)} KB`);
      showStatus("info", `Loaded "${file.name}". Enter the password (if locked) and click Decode Message.`);
    } catch (err) {
      showStatus("error", err.message);
    }
  }

  attachDropzone(decodeDropzone, decodeImageInput, handleDecodeFileSelect);

  decodeBtn.addEventListener("click", async () => {
    if (!loadedDecodeImage) {
      showStatus("error", "Please upload an encoded PNG image first.");
      return;
    }

    try {
      decodeBtn.disabled = true;
      workCanvas.width = loadedDecodeImage.width;
      workCanvas.height = loadedDecodeImage.height;
      workCtx.clearRect(0, 0, workCanvas.width, workCanvas.height);
      workCtx.drawImage(loadedDecodeImage, 0, 0);

      const imageData = workCtx.getImageData(0, 0, workCanvas.width, workCanvas.height);
      const result = await decodeMessageFromPixels(imageData.data, decodePasswordInput.value);

      decodedOutput.value = result.message;
      decodedLengthInfo.textContent = `${result.message.length.toLocaleString()} characters recovered`;
      copyDecodedBtn.disabled = false;

      showStatus(
        "success",
        result.wasProtected
          ? "Password verified! Hidden secret message unlocked and displayed."
          : "Hidden message successfully extracted from the image!"
      );
    } catch (err) {
      decodedOutput.value = "";
      decodedLengthInfo.textContent = "";
      copyDecodedBtn.disabled = true;
      if (/password/i.test(err.message)) {
        decodePasswordInput.focus();
      }
      showStatus("error", err.message);
    } finally {
      decodeBtn.disabled = false;
    }
  });

  copyDecodedBtn.addEventListener("click", async () => {
    if (!decodedOutput.value) return;
    try {
      await navigator.clipboard.writeText(decodedOutput.value);
      showStatus("success", "Decoded message copied to clipboard.");
    } catch {
      decodedOutput.select();
      document.execCommand("copy");
      showStatus("success", "Decoded message copied to clipboard.");
    }
  });

  resetDecodeBtn.addEventListener("click", () => {
    loadedDecodeImage = null;
    decodeImageInput.value = "";
    decodePasswordInput.value = "";
    decodeFileName.textContent = "Use the downloaded PNG image";
    decodeLockBadge.classList.add("hidden");
    decodePwdHint.textContent = "Required if message was locked";

    decodePreview.src = "";
    decodePreview.classList.add("hidden");
    decodePlaceholder.classList.remove("hidden");
    decodeMeta.textContent = "";

    decodedOutput.value = "";
    decodedLengthInfo.textContent = "";
    copyDecodedBtn.disabled = true;
    hideStatus();
  });
})();
