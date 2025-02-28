import { hexy } from 'hexy'
import ipaddr from 'ipaddr.js'
import { pino } from 'pino'
import { PR_ED2K, PR_EMULE, PR_ZLIB } from './op.js'

const logger = pino({
  name: 'misc',
  level: 'info'
})

/**
 * Prints an hexadecimal dump in console
 */
export const hexDump = function (data: Buffer) {
  console.log(hexy(data))
}

export const IPv6BinaryStringToString = function (str: string) {
  return ipaddr
    .fromByteArray(BufferToBytesArray(IPv6BinaryStringToBuffer(str)))
    .toString()
}

export const IPv6BufferToString = function (buffer: Buffer) {
  return ipaddr.fromByteArray(BufferToBytesArray(buffer)).toString()
}

export const IPv6StringToBinaryString = function (str: string) {
  return IPv6StringToBuffer(str).toString('binary')
}

export const IPv6StringToBuffer = function (str: string) {
  return Buffer.from(ipaddr.parse(str).toByteArray())
}

export const IPv6BinaryStringToBuffer = function (str: string) {
  return Buffer.from(str, 'binary')
}

export const BufferToBytesArray = function (buffer: Buffer) {
  return Array.prototype.slice.call(buffer, 0)
}

export const IsValidIpv6 = function (str: string) {
  return ipaddr.isValid(str)
}

/**
 * Get file extension
 *
 * @param {String} name Filename
 * @returns {String} Extension (without the dot)
 */
export const getExt = function (name: string): string {
  if (!name || name.indexOf('.') === -1) return ''
  const ext = name
    .substring(name.lastIndexOf('.') + 1, name.length)
    .toLowerCase()
  if (ext.length > 8) {
    return ''
  }
  return ext
}

export const BigIntToBuffer = (bn: bigint): Buffer => {
  const hex = bn.toString(16);
  
  // Ensure an even number of hex digits so that Buffer.from works correctly.
  const evenHex = hex.length % 2 ? '0' + hex : hex;
  
  return Buffer.from(evenHex, 'hex');
}

export const BufferToBigInt = (buf: Buffer): bigint => {
  return BigInt('0x' + buf.toString('hex'))
}

export const hex = function (n: Buffer, len: number) {
  if (!Buffer.isBuffer(n)) {
    throw new Error('Invalid input: expected n to be a Buffer.')
  }
  if (typeof len !== 'number' || len < 0) {
    throw new Error('Invalid length: expected len to be a non-negative number.')
  }
  const num = BufferToBigInt(n)
  let hexStr = num.toString(16)
  hexStr = hexStr.padStart(len, '0')
  return hexStr
}

export const IPv4toInt32LE = function (IPv4: string) {
  const parts = IPv4.split('.')
  if (parts.length !== 4) {
    logger.error(`Invalid IPv4 format: ${IPv4}`)
  }
  const octets = parts.map((part, index) => {
    const num = Number(part)
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      logger.error(`Invalid octet at index ${index}: ${part}`)
    }
    return num
  })
  const ipNum =
    octets[0] + (octets[1] << 8) + (octets[2] << 16) + (octets[3] << 24)
  if (ipNum < 0) logger.error(`Conversion resulted in negative value: ${ipNum}`)
  return ipNum >>> 0
}

/**
 * Get file type based on file extension. The file type can be one on these:
 * 'video', 'audio', 'image', 'pro'.
 *
 * @param {String} name Filename
 * @returns {String} File type
 */
export const getFileType = function (name: string): string {
  var extensions = {
    video:
      '3gp,aaf,asf,avchd,avi,fla,flv,m1v,m2v,m4v,mp4,mpg,mpe,mpeg,mov,mkv,mp4,' +
      'ogg,rm,svi'.split(','),
    audio:
      'aiff,au,wav,flac,la,pac,m4a,ape,rka,shn,tta,wv,wma,brstm,amr,mp2,mp3,' +
      'ogg,aac,m4a,mpc,ra,ots,vox,voc,mid,mod,s3m,xm,it,asf'.split(','),
    image:
      'cr2,pdn,pgm,pict,bmp,png,dib,djvu,gif,psd,pdd,icns,ico,rle,tga,jpeg,' +
      'jpg,tiff,tif,jp2,jps,mng,xbm,xcf,pcx'.split(','),
    pro:
      '7z,ace,arc,arj,bzip2,cab,gzip,rar,tar,zip,iso,nrg,img,adf,dmg,cue,bin,' +
      'cif,ccd,sub,raw'.split(',')
  }
  if (typeof name !== 'string') {
    return ''
  }
  var ext = getExt(name)
  if (extensions.video.indexOf(ext) >= 0) return 'Video'
  if (extensions.audio.indexOf(ext) >= 0) return 'Audio'
  if (extensions.image.indexOf(ext) >= 0) return 'Image'
  if (extensions.pro.indexOf(ext) >= 0) return 'Pro'
  return ''
}

/**
 * Returns true if the given parameter is valid eD2K/eMule protocol number
 *
 * @param {Integer} protocol
 * @returns {Boolean}
 */
export const isProtocol = function (protocol: number): boolean {
  return protocol == PR_ED2K || protocol == PR_EMULE || protocol == PR_ZLIB
}

export const isFunction = function (something: any) {
  return typeof something == 'function'
}

/**
 * Draws an ASCII box around some text
 */
export const box = function (text: string) {
  var l = text.length + 2
  var s = ''
  while (l--) s += '-'
  s = '+' + s + '+'
  return s + '\n' + '| ' + text + ' |' + '\n' + s
}

/**
 * Returns a UNIX timestamp
 */
export const unixTimestamp = function () {
  return Math.round(new Date().getTime() / 1000)
}

/**
 * compute b^e % p of BigInt
 */
export const modPow = (base: bigint, exp: bigint, mod: bigint) => {
  if (mod === 1n) return 0n
  let result = 1n
  base = base % mod

  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod
    }
    base = (base * base) % mod
    exp = exp / 2n
  }
  return result
}

