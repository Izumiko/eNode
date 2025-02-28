import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import { isProtocol } from './misc.js'

export interface RC4Key {
  cipher: ReturnType<typeof createCipheriv>
  dropBytes: number
}

/**
 * Creates a RC4 key
 *
 * @param key - The encryption key
 * @param drop - Whether to drop first 1024 bytes
 * @returns RC4 key object
 */
export const RC4CreateKey = (key: Buffer, drop: boolean): RC4Key => {
  const cipher = createCipheriv('rc4', key, '')
  return {
    cipher,
    dropBytes: drop ? 1024 : 0
  }
}

/**
 * Encrypt/Decrypt using RC4 algorithm
 *
 * @param data - Data to process (null to just drop bytes)
 * @param length - Number of bytes to process
 * @param key - RC4 key object
 * @returns Processed data or null
 */
export const RC4Crypt = (
  data: Buffer | null,
  length: number,
  key: RC4Key
): Buffer | null => {
  if (!key) return null

  // Create dummy buffer for dropping bytes
  const dropBuffer = Buffer.alloc(key.dropBytes)
  key.cipher.update(dropBuffer)
  key.dropBytes = 0 // Only drop once

  if (!data) return null

  const output = Buffer.alloc(length)
  const processed = key.cipher.update(data.subarray(0, length))
  processed.copy(output)
  return output
}

/**
 * Calculates a md5 hash
 *
 * @param {Buffer} buffer input data
 * @returns {Buffer} Output data
 */
export const md5 = function (buffer: Buffer): Buffer {
  const md5 = createHash('md5')
  md5.update(buffer.toString('binary'))
  return Buffer.from(md5.digest('binary'), 'binary')
}

/**
 * Returns random value between 0 and n (both included)
 *
 * @param {Integer} n
 * @returns {Integer} pseudo-random number (0..n)
 */
export const rand = function (n: number): number {
  return Math.round(Math.random() * n)
}

/**
 * Returns a buffer filled with random data
 *
 * @param {Integer} length of the returned buffer
 * @returns {Buffer} random data
 */
export const randBuf = function (length: number): Buffer {
  return randomBytes(length)
}

/**
 * Returns an invalid random protocol code.
 *
 * @returns {Integer}
 */
export const randProtocol = function (): number {
  var p = 0xff
  var i = 5
  while (i--) {
    p = exports.rand(0xff)
    if (!isProtocol(p)) break
  }
  return p
}
