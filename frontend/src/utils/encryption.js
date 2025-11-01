// src/utils/encryption.js - Client-side Encryption Utilities
import CryptoJS from "crypto-js";

/**
 * Encrypts a message using AES-256-CBC encryption
 * @param {string} message - Plain text message to encrypt
 * @param {string} key - 256-bit encryption key in hex format
 * @returns {Object} - Encrypted data with iv and hmac
 */
export const encryptMessage = (message, key) => {
  try {
    // Generate random 128-bit (16 bytes) initialization vector
    const iv = CryptoJS.lib.WordArray.random(16);

    // Encrypt using AES-256-CBC
    const encrypted = CryptoJS.AES.encrypt(
      message,
      CryptoJS.enc.Hex.parse(key),
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );

    // Convert to hex strings
    const encryptedHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    const ivHex = iv.toString(CryptoJS.enc.Hex);

    // Generate HMAC-SHA256 for message integrity
    const hmac = CryptoJS.HmacSHA256(
      encryptedHex + ivHex,
      CryptoJS.enc.Hex.parse(key)
    );

    return {
      encrypted: encryptedHex,
      iv: ivHex,
      hmac: hmac.toString(CryptoJS.enc.Hex),
      timestamp: Date.now(),
    };
  } catch (error) {
    console.error("Encryption error:", error);
    throw new Error("Failed to encrypt message: " + error.message);
  }
};

/**
 * Decrypts a message and verifies its integrity
 * @param {Object} encryptedData - Object containing encrypted, iv, and hmac
 * @param {string} key - 256-bit decryption key in hex format
 * @returns {string} - Decrypted plain text message
 * @throws {Error} - If HMAC verification fails or decryption fails
 */
export const decryptMessage = (encryptedData, key) => {
  try {
    const { encrypted, iv, hmac: receivedHmac } = encryptedData;

    // Step 1: Verify HMAC for message integrity
    const calculatedHmac = CryptoJS.HmacSHA256(
      encrypted + iv,
      CryptoJS.enc.Hex.parse(key)
    );

    if (calculatedHmac.toString(CryptoJS.enc.Hex) !== receivedHmac) {
      throw new Error(
        "Message integrity check failed - message may have been tampered with!"
      );
    }

    // Step 2: Decrypt the message
    const decrypted = CryptoJS.AES.decrypt(
      {
        ciphertext: CryptoJS.enc.Hex.parse(encrypted),
      },
      CryptoJS.enc.Hex.parse(key),
      {
        iv: CryptoJS.enc.Hex.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );

    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

    if (!decryptedText) {
      throw new Error("Decryption resulted in empty message");
    }

    return decryptedText;
  } catch (error) {
    console.error("Decryption error:", error);
    throw new Error("Failed to decrypt message: " + error.message);
  }
};

/**
 * Generates a random encryption key (for testing purposes)
 * @returns {string} - 256-bit key in hex format
 */
export const generateKey = () => {
  return CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);
};

/**
 * Validates encryption key format
 * @param {string} key - Key to validate
 * @returns {boolean} - True if key is valid
 */
export const validateKey = (key) => {
  return (
    typeof key === "string" && key.length === 64 && /^[0-9a-f]+$/i.test(key)
  );
};

export default {
  encryptMessage,
  decryptMessage,
  generateKey,
  validateKey,
};
