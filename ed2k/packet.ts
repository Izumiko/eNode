import { pino } from 'pino'
import conf from '../enode.config.js'
import { hexy } from 'hexy'
import { Ed2kBuffer } from './buffer.js'
// var tagsLength = require('../ed2k/buffer').tagsLength
import {
  PS_NEW,
  PS_READY,
  PS_WAITING_DATA,
  PS_CRYPT_NEGOTIATING,
  TYPE_UINT8,
  TYPE_UINT16,
  TYPE_UINT32,
  TYPE_STRING,
  TYPE_HASH,
  TYPE_TAGS,
  TAG_NAME,
  TAG_SIZE,
  TAG_TYPE,
  TAG_SOURCES,
  TAG_COMPLETE_SOURCES,
  TAG_SIZE_HI,
  TAG_MEDIA_TITLE,
  TAG_MEDIA_ARTIST,
  TAG_MEDIA_ALBUM,
  TAG_MEDIA_LENGTH,
  TAG_MEDIA_BITRATE,
  TAG_MEDIA_CODEC,
  CS_UNKNOWN,
  CS_NEGOTIATING,
  PR_ED2K,
  PR_ZLIB,
  PR_EMULE
} from './op.js'
import { Client } from './client.js'

const tagsLength = Ed2kBuffer.tagsLength

const logger = pino({
  name: 'packet',
  level: 'info'
})

export class Packet {
  protocol = 0
  size = 0
  code = 0
  status = PS_NEW
  data = new Ed2kBuffer(0)
  client: Client
  hasExcess: boolean
  excess: any

  constructor(_client: Client) {
    this.client = _client
  }

  // TODO: handle multipart packets sends
  // TODO: gzip compression on sending
  // TODO: Rewrite this
  make(protocol: number, items) {
    let size = 0
    items.forEach(function (v) {
      switch (v[0]) {
        case TYPE_UINT8:
          size += 1
          break
        case TYPE_UINT16:
          size += 2
          break
        case TYPE_UINT32:
          size += 4
          break
        case TYPE_STRING:
          size += 2 + Buffer.byteLength(v[1])
          break
        case TYPE_HASH:
          size += 16
          break
        case TYPE_TAGS:
          size += tagsLength(v[1])
          break
      }
    })
    const buf = new Ed2kBuffer(5 + size)
    buf.putUInt8(protocol)
    buf.putUInt32LE(size)
    items.forEach(function (v) {
      //log.trace(v);
      switch (v[0]) {
        case TYPE_UINT8:
          buf.putUInt8(v[1])
          break
        case TYPE_UINT16:
          buf.putUInt16LE(v[1])
          break
        case TYPE_UINT32:
          buf.putUInt32LE(v[1])
          break
        case TYPE_STRING:
          buf.putString(v[1])
          break
        case TYPE_HASH:
          buf.putHash(v[1])
          break
        case TYPE_TAGS:
          buf.putTags(v[1])
          break
      }
    })
    return buf.pos(0)
  }

  //TODO: rewrite this...
  //The same as TCP but without the size
  makeUDP(protocol: number, items) {
    var size = 0
    items.forEach(function (v) {
      switch (v[0]) {
        case TYPE_UINT8:
          size += 1
          break
        case TYPE_UINT16:
          size += 2
          break
        case TYPE_UINT32:
          size += 4
          break
        case TYPE_STRING:
          size += 2 + Buffer.byteLength(v[1])
          break
        case TYPE_HASH:
          size += 16
          break
        case TYPE_TAGS:
          size += Buffer.tagsLength(v[1])
          break
      }
    })
    const buf = new Ed2kBuffer(1 + size)
    buf.putUInt8(protocol)
    items.forEach(function (v) {
      //log.trace(v);
      switch (v[0]) {
        case TYPE_UINT8:
          buf.putUInt8(v[1])
          break
        case TYPE_UINT16:
          buf.putUInt16LE(v[1])
          break
        case TYPE_UINT32:
          buf.putUInt32LE(v[1])
          break
        case TYPE_STRING:
          buf.putString(v[1])
          break
        case TYPE_HASH:
          buf.putHash(v[1])
          break
        case TYPE_TAGS:
          buf.putTags(v[1])
          break
      }
    })
    return buf.pos(0)
  }

  addFile(packet, file) {
    const size = BigInt(file.size)
    const mod = BigInt(0x100000000)
    var tags = [
      [TYPE_STRING, TAG_NAME, file.name],
      [TYPE_UINT32, TAG_SIZE, Number(size % mod)],
      [TYPE_STRING, TAG_TYPE, file.type],
      [TYPE_UINT32, TAG_SOURCES, file.sources],
      [TYPE_UINT32, TAG_COMPLETE_SOURCES, file.completed]
    ]
    if (size >= mod) tags.push([TYPE_UINT32, TAG_SIZE_HI, Number(size / mod)])
    if (file.title != '') tags.push([TYPE_STRING, TAG_MEDIA_TITLE, file.title])
    if (file.artist != '')
      tags.push([TYPE_STRING, TAG_MEDIA_ARTIST, file.artist])
    if (file.album != '') tags.push([TYPE_STRING, TAG_MEDIA_ALBUM, file.album])
    if (file.runtime > 0)
      tags.push([TYPE_UINT32, TAG_MEDIA_LENGTH, file.runtime])
    if (file.bitrate > 0)
      tags.push([TYPE_UINT32, TAG_MEDIA_BITRATE, file.bitrate])
    if (file.codec != '') tags.push([TYPE_STRING, TAG_MEDIA_CODEC, file.codec])
    packet.push([TYPE_HASH, file.hash])
    packet.push([TYPE_UINT32, file.source_id])
    packet.push([TYPE_UINT16, file.source_port])
    packet.push([TYPE_TAGS, tags])
  }

  init(buffer: Ed2kBuffer) {
    //log.trace('Packet.init: buffer.length: '+buffer.length);
    this.hasExcess = false
    this.protocol = buffer.getUInt8()
    if (
      this.protocol == PR_ED2K ||
      this.protocol == PR_ZLIB ||
      this.protocol == PR_EMULE
    ) {
      this.size = buffer.getUInt32LE() - 1
      this.code = buffer.getUInt8()
      // log.trace('Packet init: protocol: 0x'+this.protocol.toString(16)+
      //   ' data size (header): '+this.size+' opcode: 0x'+this.code.toString(16));
      //TODO do checkings here
      this.data = new Ed2kBuffer(this.size)
      this.append(buffer.get())
    } else {
      if (
        this.client.crypt &&
        (this.client.crypt.status == CS_UNKNOWN ||
          this.client.crypt.status == CS_NEGOTIATING)
      ) {
        this.client.crypt.process(buffer)
      } else {
        logger.warn(
          'Packet.init: unknown protocol: 0x' + this.protocol.toString(16)
        )
        //console.log(hexDump(buffer));
      }
    }
    //return this;
  }

  append(buffer) {
    // try {
    //log.trace('packet.append');
    var received = this.data.pos()
    this.data.putBuffer(buffer)
    received += buffer.length
    if (received == this.size) {
      this.status = PS_READY
      this.hasExcess = false
    } else if (received < this.data.length) {
      this.status = PS_WAITING_DATA
      this.hasExcess = false
    } else {
      // if (received > this.size) {
      this.status = PS_READY
      this.hasExcess = true
      var excess = received - this.size
      this.excess = buffer.slice(buffer.length - excess)
    }
    // } catch (err) {
    //   log.error('packet.append: '+err);
    //   log.text(hexDump(buffer.slice(0,32)));
    //   this.status = PS_NEW;
    // }
    // return this;
  }
}
