import { Socket } from 'node:net'
import { EventEmitter } from 'node:events'
import { pino } from 'pino'
import conf from '../enode.config.js'
import { Packet } from './packet.js'
import { hexDump, IPv4toInt32LE } from './misc.js'
import {
  rand,
  randBuf,
  md5,
  RC4CreateKey,
  RC4Crypt,
  randProtocol,
  RC4Key
} from './crypt.js'
import {
  CS_UNKNOWN,
  CS_NONE,
  CS_NEGOTIATING,
  CS_ENCRYPTING,
  EM_SUPPORTED,
  EM_PREFERRED,
  PR_ED2K,
  OP_HELLOANSWER,
  OP_HELLO,
  TYPE_UINT8,
  TYPE_HASH,
  TYPE_UINT32,
  TYPE_UINT16,
  TYPE_TAGS,
  TYPE_STRING,
  TAG_NAME,
  TAG_VERSION,
  ENODE_NAME,
  ENODE_VERSIONINT
} from './op.js'
import { Ed2kBuffer } from './buffer.js'

// Constants
const MAGICVALUE_SYNC = 0x835e6fc4
const MAGICVALUE_203 = 203
const MAGICVALUE_34 = 34

const logger = pino({
  name: 'client',
  level: 'info'
})

interface ClientCryptState {
  status: number
  method?: number
}

interface HelloAnswerInfo {
  hash: Ed2kBuffer
  id: number
  port: number
  serverAddress: number
  serverPort: number
  [key: string]: any
}

type TimeoutType = 'handshake' | 'connection' | 'hello'

/**
 * Very basic eD2K client for sending/receiving HELLO packets.
 *
 * Events: error, timeout, connected, data, ophelloanswer, handshake
 */
export class Client extends EventEmitter {
  private socket: Socket
  public crypt: ClientCryptState
  private sendKey?: RC4Key
  private recvKey?: RC4Key
  private hash?: Buffer
  private handshakeTimeout?: NodeJS.Timeout
  private opHelloTimeout?: NodeJS.Timeout

  constructor() {
    super()
    this.socket = new Socket()
    this.crypt = {
      status: conf.enableCrypt ? CS_UNKNOWN : CS_NONE
    }

    this.setupSocketListeners()
  }

  /**
   * Set up all socket event listeners
   */
  private setupSocketListeners(): void {
    this.socket.on('data', (data: Buffer) => {
      const decrypted = this._decrypt(data)
      if (decrypted === false) return

      const protocol = decrypted.getUInt8()
      if (protocol === PR_ED2K) {
        const size = decrypted.getUInt32LE()
        const payload = decrypted.get(size)
        const opcode = payload.getUInt8()

        switch (opcode) {
          case OP_HELLOANSWER:
            if (this.opHelloTimeout) {
              clearTimeout(this.opHelloTimeout)
            }
            this.emit('ophelloanswer', this.readOpHelloAnswer(payload))
            break
          default:
            logger.warn(`Client.on data: bad opcode: 0x${opcode.toString(16)}`)
        }
      } else {
        logger.error(`Client.on data: bad protocol: 0x${protocol.toString(16)}`)
      }
    })

    this.socket.on('error', (err: Error) => {
      this.emit('error', err)
    })

    this.socket.setTimeout(conf.tcp.connectionTimeout, () => {
      this.emit('timeout', 'connection' as TimeoutType)
    })
  }

  /**
   * Perform cryptographic handshake
   */
  public handshake(): void {
    if (!this.hash) {
      throw new Error('Cannot handshake without a hash - call connect first')
    }

    const padLength = rand(0xff)
    const randomKey = rand(0xffffffff)
    const key = new Ed2kBuffer(21)
    let enc = new Ed2kBuffer(4 + 1 + 1 + 1 + padLength)
    const buf = new Ed2kBuffer(1 + 4 + 4 + 1 + 1 + 1 + padLength)

    // Calculate the keys
    const sendKey = md5(
      key.putHash(this.hash).putUInt8(MAGICVALUE_34).putUInt32LE(randomKey)
        .internalBuffer
    )
    const recvKey = md5(key.pos(16).putUInt8(MAGICVALUE_203).internalBuffer)

    this.sendKey = RC4CreateKey(sendKey, true)
    this.recvKey = RC4CreateKey(recvKey, true)

    // The encoded part of the packet
    enc.putUInt32LE(MAGICVALUE_SYNC)
    enc.putUInt8(EM_SUPPORTED).putUInt8(EM_PREFERRED)
    enc.putUInt8(padLength).putBuffer(randBuf(padLength))
    enc = new Ed2kBuffer(
      RC4Crypt(enc.internalBuffer, enc.length, this.sendKey)!
    )

    buf
      .putUInt8(randProtocol())
      .putUInt32LE(randomKey)
      .putBuffer(enc.internalBuffer)

    this.crypt.status = CS_NEGOTIATING
    this.handshakeTimeout = setTimeout(() => {
      this.emit('timeout', 'handshake' as TimeoutType)
    }, conf.tcp.connectionTimeout)

    this.socket.write(buf.internalBuffer, (err) => {
      if (err) this.emit('error', err)
    })
  }

  /**
   * Decrypt incoming data based on current crypto status
   * @param data - Buffer to decrypt
   * @returns Decrypted buffer or false if no further processing needed
   */
  private _decrypt(data: Buffer): Ed2kBuffer | false {
    switch (this.crypt.status) {
      case CS_ENCRYPTING:
        logger.trace('Client._decrypt: decrypting')
        return new Ed2kBuffer(RC4Crypt(data, data.length, this.recvKey!)!)

      case CS_NEGOTIATING:
        const decrypted = new Ed2kBuffer(
          RC4Crypt(data, data.length, this.recvKey!)!
        )

        if (decrypted.getUInt32LE() === MAGICVALUE_SYNC) {
          if (this.handshakeTimeout) {
            clearTimeout(this.handshakeTimeout)
          }

          logger.trace('Client._decrypt: negotiation response Ok.')
          this.crypt.method = decrypted.getUInt8() // should be == EM_OBFUSCATE
          decrypted.get(decrypted.getUInt8()) // skip padding

          this.crypt.status = CS_ENCRYPTING

          if (decrypted.pos() < decrypted.length) {
            logger.warn('Client._decrypt: there is more unhandled data!')
            hexDump(decrypted.get().internalBuffer)
          }

          this.emit('handshake', false)
          return false
        } else {
          this.crypt.status = CS_NONE
          this.emit('handshake', new Error('Bad handshake answer received'))
        }
        return decrypted

      case CS_NONE:
        return new Ed2kBuffer(data)

      case CS_UNKNOWN:
      default:
        logger.error("Client._decrypt: we shouldn't be here")
        return false
    }
  }

  /**
   * Connect to a server
   * @param host - Server hostname or IP
   * @param port - Server port
   * @param hash - Client hash
   * @returns this - For chaining
   */
  public connect(host: string, port: number, hash: Buffer): this {
    this.hash = hash

    this.socket.connect({ port, host, localAddress: conf.address }, () => {
      this.emit('connected')
    })

    return this
  }

  /**
   * Submit raw data to the server
   * @param data - Data to send
   * @param callback - Callback when data is sent
   */
  public submit(data: Buffer, callback: (err?: any) => void): void {
    if (this.crypt.status === CS_ENCRYPTING) {
      logger.trace('Client.submit: encrypt')
      data = RC4Crypt(data, data.length, this.sendKey!) as Buffer
    }

    logger.trace('Client.submit: send data')
    this.socket.write(data, callback)
  }

  /**
   * write raw data to the server
   * @param data - Data to send
   * @param callback - Callback when data is sent
   */
  public write(data: Buffer, callback: (err?: any) => void): void {
    logger.trace('Client.write: send data')
    this.socket.write(data, callback)
  }

  /**
   * Send operation to server
   * @param operation - Operation code
   * @param info - Operation info (unused in current implementation)
   * @param callback - Callback when operation is sent
   */
  public send(
    operation: number,
    info: any,
    callback: (err?: any) => void
  ): void {
    const pack: any[][] = [[TYPE_UINT8, operation]]

    switch (operation) {
      case OP_HELLO:
        pack.push([TYPE_UINT8, 16]) // should be 16
        pack.push([TYPE_HASH, conf.hash])
        pack.push([TYPE_UINT32, IPv4toInt32LE(conf.address)])
        pack.push([TYPE_UINT16, conf.tcp.port])
        pack.push([
          TYPE_TAGS,
          [
            [TYPE_STRING, TAG_NAME, ENODE_NAME],
            [TYPE_UINT32, TAG_VERSION, ENODE_VERSIONINT]
          ]
        ])
        pack.push([TYPE_UINT32, IPv4toInt32LE(conf.address)])
        pack.push([TYPE_UINT16, conf.tcp.port])

        this.opHelloTimeout = setTimeout(() => {
          this.emit('timeout', 'hello' as TimeoutType)
        }, conf.tcp.connectionTimeout)

        this.submit(Packet.make(PR_ED2K, pack), callback)
        break
    }
  }

  /**
   * Close the connection
   */
  public end(): void {
    this.socket.destroy()
  }

  /**
   * Parse HELLO answer from server
   * @param data - Data buffer
   * @returns Parsed information
   */
  private readOpHelloAnswer(data: Ed2kBuffer): HelloAnswerInfo {
    const info: HelloAnswerInfo = {
      hash: data.get(16),
      id: data.getUInt32LE(),
      port: data.getUInt16LE(),
      serverAddress: 0,
      serverPort: 0
    }

    const tags = data.getTags()
    if (Array.isArray(tags)) {
      tags.forEach((v) => {
        info[v.tag_name] = v.tag_value
      })
    }

    info.serverAddress = data.getUInt32LE()
    info.serverPort = data.getUInt16LE()

    if (data.pos() < data.length) {
      logger.warn(
        `readOpHelloAnswer excess: ${data.get().internalBuffer.toString('hex')}`
      )
    }

    return info
  }
}
