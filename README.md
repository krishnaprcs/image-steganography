# Image Steganography — Hide Secret Text in Images

A beginner-friendly **client-side web application** that hides secret text messages inside PNG or JPG images using the **Least Significant Bit (LSB)** steganography technique — with optional **AES-256-GCM password encryption** — running completely in the browser with no backend or database.

---

## Features
- **Hide Message (Encoding):**
  - Upload any **PNG or JPG** cover image (drag-and-drop or file picker) or click **Use Sample Image** to test immediately.
  - Enter a **Secret Message** with a live UTF-8 byte counter and capacity progress bar.
  - Enter a **Password** (with Show/Hide toggle and password strength meter) to lock the message with **AES-256-GCM** before embedding.
  - Side-by-side **Before Encoding** and **After Encoding** previews.
  - **Download Encoded PNG** (lossless) or click **Test in Decoder** to verify decoding immediately.
- **Reveal Message (Decoding):**
  - Upload an encoded PNG image — automatically detects whether the image is password-protected (`Password Protected` badge).
  - Enter the **Password** and click **Decode Message** to decrypt and reveal the secret text.
  - Rejects missing or wrong passwords with clear error notifications.
  - One-click **Copy Text** button.

---

## How to Run
- Open [index.html](index.html) in any modern browser, **or** serve the folder with a local server (`python -m http.server 8090`).

---

## How Encoding & Decoding Work

### 1. Optional Password Encryption (`PBKDF2` + `AES-256-GCM`)
When a password is entered, `PBKDF2` (100,000 SHA-256 iterations) derives a 256-bit key from your password and a random 16-byte salt. The UTF-8 message is encrypted using **AES-256-GCM** with a random 12-byte IV. Because AES-GCM is authenticated, an incorrect password fails cleanly instead of producing garbled characters.

### 2. LSB Pixel Embedding
The packet starts with a 9-byte header (`"STEG"` magic signature + encryption mode flag + 32-bit payload byte length) followed by the plain or encrypted bytes. Each bit is embedded into the **Least Significant Bit** of consecutive Red, Green, and Blue pixel channels on an HTML5 `<canvas>`:
```js
pixelData[i] = (pixelData[i] & 0xFE) | bit;
```

### 3. Decoding & Unlocking
The decoder reads `pixelData[i] & 1` from consecutive RGB channels, checks the `"STEG"` header and mode flag, asks for/verifies the password if locked, and restores the original UTF-8 secret text.
