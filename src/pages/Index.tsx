import { useState, useCallback } from "react";

type Algorithm = "ECDSA" | "ED25519" | "RSA";
type ECDSASize = "256" | "384" | "521";
type RSASize = "1024" | "2048" | "4096";

const ecdsaCurveMap: Record<ECDSASize, string> = {
  "256": "P-256",
  "384": "P-384",
  "521": "P-521",
};

const sshCurveNames: Record<ECDSASize, string> = {
  "256": "nistp256",
  "384": "nistp384",
  "521": "nistp521",
};

const Index = () => {
  const [algorithm, setAlgorithm] = useState<Algorithm>("ECDSA");
  const [ecdsaSize, setEcdsaSize] = useState<ECDSASize>("256");
  const [rsaSize, setRsaSize] = useState<RSASize>("2048");
  const [sshFormat, setSshFormat] = useState(false);
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState("");

  const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  const formatPEM = (base64: string, type: "PUBLIC" | "PRIVATE"): string => {
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${type} KEY-----\n${lines.join("\n")}\n-----END ${type} KEY-----`;
  };

  // Helper to encode a string as SSH wire format (length-prefixed)
  const encodeSSHString = (str: string): Uint8Array => {
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);
    const result = new Uint8Array(4 + strBytes.length);
    const view = new DataView(result.buffer);
    view.setUint32(0, strBytes.length, false);
    result.set(strBytes, 4);
    return result;
  };

  // Helper to encode bytes as SSH wire format (length-prefixed)
  const encodeSSHBytes = (bytes: Uint8Array): Uint8Array => {
    const result = new Uint8Array(4 + bytes.length);
    const view = new DataView(result.buffer);
    view.setUint32(0, bytes.length, false);
    result.set(bytes, 4);
    return result;
  };

  // Helper to encode a BigInt as SSH mpint
  const encodeSSHMpint = (bytes: Uint8Array): Uint8Array => {
    // Add leading zero if high bit is set (to indicate positive number)
    if (bytes[0] & 0x80) {
      const padded = new Uint8Array(bytes.length + 1);
      padded[0] = 0;
      padded.set(bytes, 1);
      bytes = padded;
    }
    return encodeSSHBytes(bytes);
  };

  const formatSSHPublicKey = async (
    publicKey: CryptoKey,
    algo: Algorithm,
    curveSize: ECDSASize
  ): Promise<string> => {
    if (algo === "RSA") {
      const jwk = await crypto.subtle.exportKey("jwk", publicKey);
      const e = new Uint8Array(
        atob(jwk.e!.replace(/-/g, "+").replace(/_/g, "/"))
          .split("")
          .map((c) => c.charCodeAt(0))
      );
      const n = new Uint8Array(
        atob(jwk.n!.replace(/-/g, "+").replace(/_/g, "/"))
          .split("")
          .map((c) => c.charCodeAt(0))
      );

      const keyType = encodeSSHString("ssh-rsa");
      const eEncoded = encodeSSHMpint(e);
      const nEncoded = encodeSSHMpint(n);

      const blob = new Uint8Array(keyType.length + eEncoded.length + nEncoded.length);
      blob.set(keyType, 0);
      blob.set(eEncoded, keyType.length);
      blob.set(nEncoded, keyType.length + eEncoded.length);

      return `ssh-rsa ${arrayBufferToBase64(blob.buffer)}`;
    } else if (algo === "ECDSA") {
      const jwk = await crypto.subtle.exportKey("jwk", publicKey);
      const x = new Uint8Array(
        atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/"))
          .split("")
          .map((c) => c.charCodeAt(0))
      );
      const y = new Uint8Array(
        atob(jwk.y!.replace(/-/g, "+").replace(/_/g, "/"))
          .split("")
          .map((c) => c.charCodeAt(0))
      );

      const curveName = sshCurveNames[curveSize];
      const keyType = `ecdsa-sha2-${curveName}`;
      
      // Uncompressed point format: 0x04 || x || y
      const point = new Uint8Array(1 + x.length + y.length);
      point[0] = 0x04;
      point.set(x, 1);
      point.set(y, 1 + x.length);

      const keyTypeEncoded = encodeSSHString(keyType);
      const curveEncoded = encodeSSHString(curveName);
      const pointEncoded = encodeSSHBytes(point);

      const blob = new Uint8Array(keyTypeEncoded.length + curveEncoded.length + pointEncoded.length);
      blob.set(keyTypeEncoded, 0);
      blob.set(curveEncoded, keyTypeEncoded.length);
      blob.set(pointEncoded, keyTypeEncoded.length + curveEncoded.length);

      return `${keyType} ${arrayBufferToBase64(blob.buffer)}`;
    } else {
      // ED25519
      const raw = await crypto.subtle.exportKey("raw", publicKey);
      const rawBytes = new Uint8Array(raw);
      
      const keyType = encodeSSHString("ssh-ed25519");
      const keyData = encodeSSHBytes(rawBytes);

      const blob = new Uint8Array(keyType.length + keyData.length);
      blob.set(keyType, 0);
      blob.set(keyData, keyType.length);

      return `ssh-ed25519 ${arrayBufferToBase64(blob.buffer)}`;
    }
  };

  const generateKeys = useCallback(async () => {
    setIsGenerating(true);
    setError("");
    setPublicKey("");
    setPrivateKey("");

    try {
      let keyPair: CryptoKeyPair;

      if (algorithm === "ECDSA") {
        keyPair = await crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: ecdsaCurveMap[ecdsaSize] },
          true,
          ["sign", "verify"]
        );
      } else if (algorithm === "ED25519") {
        keyPair = await crypto.subtle.generateKey(
          { name: "Ed25519" },
          true,
          ["sign", "verify"]
        );
      } else {
        keyPair = await crypto.subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: parseInt(rsaSize),
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          true,
          ["encrypt", "decrypt"]
        );
      }

      // Export private key (always PEM format)
      const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      const privateKeyBase64 = arrayBufferToBase64(privateKeyBuffer);
      setPrivateKey(formatPEM(privateKeyBase64, "PRIVATE"));

      // Export public key
      if (sshFormat) {
        const sshPublicKey = await formatSSHPublicKey(keyPair.publicKey, algorithm, ecdsaSize);
        setPublicKey(sshPublicKey);
      } else {
        const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
        setPublicKey(formatPEM(publicKeyBase64, "PUBLIC"));
      }
    } catch (err) {
      console.error(err);
      if (algorithm === "ED25519") {
        setError("ED25519 is not supported in this browser. Try Chrome 113+ or Edge 113+.");
      } else {
        setError(`Failed to generate keys: ${err instanceof Error ? err.message : "Unknown error"}`);
      }
    } finally {
      setIsGenerating(false);
    }
  }, [algorithm, ecdsaSize, rsaSize, sshFormat]);

  return (
    <div className="min-h-screen relative overflow-hidden flex items-center justify-center p-4">
      {/* Background orbs */}
      <div
        className="floating-orb w-96 h-96 bg-primary -top-48 -left-48"
        style={{ animationDelay: "0s" }}
      />
      <div
        className="floating-orb w-80 h-80 bg-accent -bottom-40 -right-40"
        style={{ animationDelay: "2s" }}
      />
      <div
        className="floating-orb w-64 h-64 bg-primary top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        style={{ animationDelay: "4s" }}
      />

      {/* Main card */}
      <div className="glass-card glow-border p-8 md:p-10 w-full max-w-2xl relative z-10">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 mb-4">
            <div className="w-3 h-3 rounded-full bg-primary animate-pulse-glow" />
            <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-medium">
              Cryptographic Toolkit
            </span>
          </div>
          <h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-primary via-foreground to-accent bg-clip-text text-transparent">
            Key Generator
          </h1>
          <p className="text-muted-foreground mt-2">
            Generate secure cryptographic key pairs using Web Crypto API
          </p>
        </div>

        {/* Controls */}
        <div className="space-y-6 mb-8">
          {/* Algorithm selection */}
          <div>
            <label className="label-text">Algorithm</label>
            <select
              className="cyber-select"
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
            >
              <option value="ECDSA">ECDSA (Elliptic Curve)</option>
              <option value="ED25519">ED25519 (Edwards Curve)</option>
              <option value="RSA">RSA</option>
            </select>
          </div>

          {/* Key size selection */}
          <div>
            <label className="label-text">Key Size</label>
            {algorithm === "ED25519" ? (
              <div className="cyber-select bg-muted/30 cursor-not-allowed text-muted-foreground">
                256-bit (Fixed)
              </div>
            ) : algorithm === "ECDSA" ? (
              <select
                className="cyber-select"
                value={ecdsaSize}
                onChange={(e) => setEcdsaSize(e.target.value as ECDSASize)}
              >
                <option value="256">256-bit (P-256 / secp256r1)</option>
                <option value="384">384-bit (P-384 / secp384r1)</option>
                <option value="521">521-bit (P-521 / secp521r1)</option>
              </select>
            ) : (
              <select
                className="cyber-select"
                value={rsaSize}
                onChange={(e) => setRsaSize(e.target.value as RSASize)}
              >
                <option value="1024">1024-bit</option>
                <option value="2048">2048-bit (Recommended)</option>
                <option value="4096">4096-bit</option>
              </select>
          )}
          </div>

          {/* SSH Format checkbox */}
          <label className="flex items-center gap-3 cursor-pointer group">
            <div className="relative">
              <input
                type="checkbox"
                checked={sshFormat}
                onChange={(e) => setSshFormat(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-5 h-5 border-2 border-border rounded bg-input peer-checked:bg-primary peer-checked:border-primary transition-all duration-200 flex items-center justify-center">
                {sshFormat && (
                  <svg className="w-3 h-3 text-primary-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </div>
            </div>
            <span className="text-sm text-foreground group-hover:text-primary transition-colors">
              Generate SSH format public key
            </span>
          </label>

          {/* Generate button */}
          <button
            className="cyber-button w-full"
            onClick={generateKeys}
            disabled={isGenerating}
          >
            {isGenerating ? (
              <span className="flex items-center justify-center gap-2">
                <svg
                  className="animate-spin h-5 w-5"
                  viewBox="0 0 24 24"
                  fill="none"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Generating...
              </span>
            ) : (
              "Generate Key Pair"
            )}
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-destructive text-sm">
            {error}
          </div>
        )}

        {/* Output textareas */}
        <div className="space-y-6">
          <div>
            <label className="label-text flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              Public Key
            </label>
            <textarea
              className="cyber-textarea h-32"
              readOnly
              value={publicKey}
              placeholder="Public key will appear here..."
            />
          </div>

          <div>
            <label className="label-text flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              Private Key
            </label>
            <textarea
              className="cyber-textarea h-32"
              readOnly
              value={privateKey}
              placeholder="Private key will appear here..."
            />
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 pt-6 border-t border-border/50 text-center">
          <p className="text-xs text-muted-foreground">
            Keys are generated locally in your browser using{" "}
            <code className="text-primary/80">crypto.subtle</code>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Index;
