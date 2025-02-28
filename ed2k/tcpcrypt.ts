import conf from '../enode.config.js'
import { pino } from 'pino'
import { hexy } from 'hexy'
import { Packet } from './packet.js'
import {
  CRYPT_DHA_SIZE,
  CRYPT_PRIME,
  CRYPT_PRIME_SIZE,
  CS_ENCRYPTING,
  CS_NEGOTIATING,
  CS_NONE,
  CS_UNKNOWN,
  EM_OBFUSCATE,
  EM_PREFERRED,
  EM_SUPPORTED,
  PS_CRYPT_NEGOTIATING,
  PS_NEW
} from './op.js'
import { md5, rand, randBuf, RC4CreateKey, RC4Crypt, RC4Key } from './crypt.js'
import { Ed2kBuffer } from './buffer.js'
import { BigIntToBuffer, BufferToBigInt, modPow } from './misc.js'
// var crypt = require('./crypt')

const MAGICVALUE_SYNC = 0x835e6fc4
const MAGICVALUE_SERVER = 203
const MAGICVALUE_REQUESTER = 34

const logger = pino({
  name: 'tcp_crypt',
  level: 'info'
})

export class TcpCrypt {
  packet: Packet
  status: number
  sendKey?: RC4Key
  recvKey?: RC4Key

  constructor(_packet: Packet) {
    logger.trace('TCP Crypt init')
    this.packet = _packet
    this.status = conf.supportCrypt ? CS_UNKNOWN : CS_NONE
  }

  process(buffer: Ed2kBuffer) {
    this.packet.data = buffer.get()
    switch (this.status) {
      case CS_NONE:
        logger.warn('crypt.process: Obfuscation disabled')
        break
      case CS_UNKNOWN:
        logger.trace('TcpCrypt.process: Negotiation start')
        this.negotiate()
        this.packet.status = PS_CRYPT_NEGOTIATING
        this.status = CS_NEGOTIATING
        break
      case CS_NEGOTIATING:
        logger.trace('TcpCrypt.process: Negotiation response')
        const that = this
        this.handshake(
          buffer,
          (err, data) => {
            if (err != false) {
              logger.error(err)
              that.packet.client.end()
            } else {
              that.status = CS_ENCRYPTING
              that.packet.status = PS_NEW
              if (data) that.packet.init(data)
            }
          }
        )
        break
      default:
        logger.error("TcpCrypt.process: I shouldn't be here!")
        console.trace()
    }
  }

  negotiate() {
    const g = BigInt(2)
    const p = BufferToBigInt(CRYPT_PRIME)
    var A = BufferToBigInt(
      this.packet.data.get(CRYPT_PRIME_SIZE).internalBuffer
    )
    var b = BufferToBigInt(randBuf(CRYPT_DHA_SIZE))
    var B = BigIntToBuffer(modPow(g, b, p))
    var K = BigIntToBuffer(modPow(A, b, p))

    var padSize = this.packet.data.getUInt8()
    var pad = this.packet.data.get(padSize)
    // log.debug('Excess (should be 0): '+
    // (this.packet.data.length-this.packet.data.pos()))
    var buf = new Ed2kBuffer(CRYPT_PRIME_SIZE + 1)

    buf.putBuffer(K)

    // create RC4 send key
    buf.putUInt8(MAGICVALUE_SERVER)
    this.sendKey = RC4CreateKey(md5(buf.internalBuffer), true)

    // create RC4 receive key
    buf.set(CRYPT_PRIME_SIZE, MAGICVALUE_REQUESTER)
    this.recvKey = RC4CreateKey(md5(buf.internalBuffer), true)

    var padSize = rand(16)
    var rc4Buf = new Ed2kBuffer(4 + 1 + 1 + 1 + padSize)
    var packet = new Ed2kBuffer(CRYPT_PRIME_SIZE + rc4Buf.length)

    rc4Buf.putUInt32LE(MAGICVALUE_SYNC)
    rc4Buf.putUInt8(EM_SUPPORTED)
    rc4Buf.putUInt8(EM_PREFERRED)
    rc4Buf.putUInt8(padSize)
    rc4Buf.putBuffer(randBuf(padSize))

    packet.putBuffer(B)
    packet.putBuffer(
      RC4Crypt(rc4Buf.internalBuffer, rc4Buf.length, this.sendKey)!
    )

    this.packet.client.write(packet.internalBuffer, (err: any) => {
      if (err)
        logger.error(
          'TcpCrypt.negotiate Client write failed: ' + JSON.stringify(err)
        )
    })
  }

  /**
   * Reads the handshake response from client, checks the MAGICVALUE_SYNC
   * constant and checks the encryption method selected by client.
   *
   * @param {Buffer} buffer Incoming data
   * @param {Function} callback(err, data)
   * @returns {Boolean} True on correct handshake or False on error.
   */
  handshake(
    buffer: Ed2kBuffer,
    callback: (err: false | { message: string }, data?: Ed2kBuffer) => void
  ) {
    if (this.status == CS_NEGOTIATING) {
      const data = new Ed2kBuffer(
        RC4Crypt(buffer.internalBuffer, buffer.length, this.recvKey!)!
      )
      if (data.getUInt32LE() != MAGICVALUE_SYNC) {
        callback({ message: 'Wrong MAGICVALUE_SYNC' })
        return
      }
      if (data.getUInt8() != EM_OBFUSCATE) {
        callback({ message: 'encryption method not supported' })
        return
      }
      data.get(data.getUInt8()) // discard pad bytes
      callback(false, data.get())
      return
    } else {
      callback({ message: 'bad crypt status' })
    }
  }

  /**
   * Decrypt buffer when needed
   *
   * @param {Buffer} buffer
   * @returns {Buffer} data
   */
  decrypt(buffer: Ed2kBuffer): Buffer {
    if (this.status == CS_ENCRYPTING) {
      return RC4Crypt(buffer.internalBuffer, buffer.length, this.recvKey!)
    } else {
      return buffer
    }
  }
}
