import {
  TYPE_HASH,
  TYPE_STRING,
  TYPE_UINT8,
  TYPE_UINT16,
  TYPE_UINT32,
  TAG_NAME,
  TAG_SIZE,
  TAG_SIZE_HI,
  TAG_TYPE,
  TAG_FORMAT,
  TAG_VERSION,
  TAG_PORT,
  TAG_SOURCES,
  TAG_MULEVERSION,
  TAG_FLAGS,
  TAG_RATING,
  TAG_MEDIA_ARTIST,
  TAG_MEDIA_ALBUM,
  TAG_MEDIA_TITLE,
  TAG_MEDIA_LENGTH,
  TAG_MEDIA_BITRATE,
  TAG_MEDIA_CODEC,
  TAG_SEARCHTREE,
  TAG_EMULE_UDPPORTS,
  TAG_EMULE_OPTIONS1,
  TAG_EMULE_OPTIONS2,
  VAL_PARTIAL_ID,
  VAL_PARTIAL_PORT,
  VAL_COMPLETE_ID,
  VAL_COMPLETE_PORT,
  TAG_IPV6,
  ED2K_Publishing
} from './op.js'
import { FileType } from './bean/File.js'
import { pino } from 'pino'
import conf from '../enode.config.js'

const logger = pino({
  name: 'buffer',
  level: 'info'
})

interface Tag {
  type: number
  code: number
  data: string | number | Buffer
}

interface TagValue {
  tag_name: string
  tag_value: string | number | boolean
}

interface FileInfo {
  hash: Ed2kBuffer
  complete: number
  name?: string
  size?: bigint
  type?: number
  sizehi?: number
}

export class Ed2kBuffer {
  private buffer: Buffer
  private _pointer: number = 0

  constructor(buffer: Buffer | number) {
    if (typeof buffer === 'number') {
      this.buffer = Buffer.alloc(buffer)
    } else {
      this.buffer = buffer
    }
  }

  get internalBuffer(): Buffer {
    return this.buffer
  }

  get length(): number {
    return this.buffer.length
  }

  set(pos: number, val: number) {
    this.buffer[pos] = val
  }

  pos(): number
  pos(pos: number): this
  pos(pos?: number): this | number {
    if (typeof pos === 'number') {
      this._pointer = pos
      if (this._pointer > this.length) {
        this._pointer = this.length
      }
      return this
    }
    return this._pointer
  }

  getUInt8(): number {
    const r = this.buffer.readUInt8(this._pointer)
    this._pointer++
    return r
  }

  putUInt8(value: number): this {
    this.buffer.writeUInt8(value, this._pointer)
    this._pointer++
    return this
  }

  getUInt16LE(): number {
    const r = this.buffer.readUInt16LE(this._pointer)
    this._pointer += 2
    return r
  }

  putUInt16LE(n: number): this {
    this.buffer.writeUInt16LE(n, this._pointer)
    this._pointer += 2
    return this
  }

  getUInt32LE(): number {
    const r = this.buffer.readUInt32LE(this._pointer)
    this._pointer += 4
    return r
  }

  getUInt64LE(): bigint {
    const lo = BigInt(this.buffer.readUInt32LE(this._pointer))
    const hi = BigInt(this.buffer.readUInt32LE(this._pointer + 4))
    this._pointer += 8
    return lo + (hi << 32n)
  }

  putUInt32LE(value: number): this {
    this.buffer.writeUInt32LE(value, this._pointer)
    this._pointer += 4
    return this
  }

  getString(length?: number): string {
    if (length === undefined) {
      length = this.getUInt16LE()
    }
    return this.get(length).toString()
  }

  putString(str: string): this {
    const len = Buffer.byteLength(str)
    this.putUInt16LE(len)
    this.buffer.write(str, this._pointer)
    this._pointer += len
    return this
  }

  putBuffer(buffer: Buffer): this {
    buffer.copy(this.buffer, this._pointer)
    this._pointer += buffer.length
    if (this._pointer > this.length) {
      this._pointer = this.length
    }
    return this
  }

  putHash(hash: string | Buffer | ArrayBuffer): this {
    if (hash instanceof Buffer && hash.length === 16) {
      this.putBuffer(hash)
    } else if (typeof hash === 'string' && hash.length === 32) {
      this.putBuffer(Buffer.from(hash, 'hex'))
    } else if (hash instanceof ArrayBuffer) {
      this.putBuffer(Buffer.from(hash))
    } else {
      logger.error(`putHash: Unsupported input. Type: ${typeof hash}`)
    }
    return this
  }

  get(len?: number): Ed2kBuffer {
    if (len === 0) return new Ed2kBuffer(0)
    if (len === undefined) {
      const r = this.buffer.subarray(this._pointer)
      this._pointer = this.length
      return new Ed2kBuffer(r)
    }
    const end = this._pointer + len > this.length ? this.length : this._pointer + len
    const r = this.buffer.subarray(
      this._pointer,
      end
    )
    this._pointer = end
    return new Ed2kBuffer(r)
  }

  static tagsLength(tags: Tag[]): number {
    let len = 4 // tags count <u32>
    for (const t of tags) {
      len += 4 // tag header (t[0] type <u8>).(length <u16>).(t[1] code<u8>)
      switch (t.type) {
        case TYPE_STRING:
          len += 2 + Buffer.byteLength(t.data as string)
          break
        case TYPE_UINT8:
          len += 1
          break
        case TYPE_UINT16:
          len += 2
          break
        case TYPE_UINT32:
          len += 4
          break
        default:
          logger.error(
            `Buffer.tagsLength: Unhandled tag type: 0x${t.type.toString(16)}`
          )
      }
    }
    return len
  }

  putTag(tag: Tag): this {
    this.putUInt8(tag.type).putUInt16LE(1).putUInt8(tag.code)
    switch (tag.type) {
      case TYPE_STRING:
        this.putString(tag.data as string)
        break
      case TYPE_UINT8:
        this.putUInt8(tag.data as number)
        break
      case TYPE_UINT16:
        this.putUInt16LE(tag.data as number)
        break
      case TYPE_UINT32:
        this.putUInt32LE(tag.data as number)
        break
      case TYPE_HASH:
        this.putHash(tag.data as Buffer)
        break
      default:
        logger.error(
          `Buffer.putTag: Unhandled tag type: 0x${tag.type.toString(16)}`
        )
    }
    return this
  }

  putTags(tags: Tag[]): this {
    this.putUInt32LE(tags.length)
    for (const tag of tags) {
      this.putTag(tag)
    }
    return this
  }

  getTagValue(type: number): string | number | false {
    switch (type) {
      case TYPE_STRING:
        return this.getString()
      case TYPE_UINT8:
        return this.getUInt8()
      case TYPE_UINT16:
        return this.getUInt16LE()
      case TYPE_UINT32:
        return this.getUInt32LE()
      default:
        logger.error(`Unknown tag type: 0x${type.toString(16)}`)
        return false
    }
  }

  getTag(): TagValue | false {
    const type = this.getUInt8()
    let code: number
    if (type & 0x80) {
      // Lugdunum extended tag
      code = this.getUInt8()
      const tagType = type & 0x7f
      if (tagType >= 0x10) {
        const length = tagType - 0x10
        this.pos(this.pos() - 2)
        this.buffer.writeUInt16LE(length, this.pos())
      }
    } else {
      const length = this.getUInt16LE()
      if (length === 1) {
        code = this.getUInt8()
      } else {
        logger.warn(`Unhandled tag. Length: ${length.toString(16)}`)
        return false
      }
    }

    const value = this.getTagValue(type)
    if (value === false) return false

    switch (code!) {
      case TAG_NAME:
        return { tag_name: 'name', tag_value: value }
      case TAG_SIZE:
        return { tag_name: 'size', tag_value: value }
      case TAG_SIZE_HI:
        return { tag_name: 'sizehi', tag_value: value }
      case TAG_TYPE:
        return { tag_name: 'type', tag_value: value }
      case TAG_FORMAT:
        return { tag_name: 'format', tag_value: value }
      case TAG_VERSION:
        return { tag_name: 'version', tag_value: value }
      case TAG_PORT:
        return { tag_name: 'port2', tag_value: value }
      case TAG_SOURCES:
        return { tag_name: 'sources', tag_value: value }
      case TAG_MULEVERSION:
        return { tag_name: 'muleversion', tag_value: value }
      case TAG_FLAGS:
        return { tag_name: 'flags', tag_value: value }
      case TAG_RATING:
        return { tag_name: 'rating', tag_value: value }
      case TAG_MEDIA_ARTIST:
        return { tag_name: 'artist', tag_value: value }
      case TAG_MEDIA_ALBUM:
        return { tag_name: 'album', tag_value: value }
      case TAG_MEDIA_TITLE:
        return { tag_name: 'title', tag_value: value }
      case TAG_MEDIA_LENGTH:
        return { tag_name: 'length', tag_value: value }
      case TAG_MEDIA_BITRATE:
        return { tag_name: 'bitrate', tag_value: value }
      case TAG_MEDIA_CODEC:
        return { tag_name: 'codec', tag_value: value }
      case TAG_SEARCHTREE:
        return { tag_name: 'searchtree', tag_value: value }
      case TAG_EMULE_UDPPORTS:
        return { tag_name: 'udpports', tag_value: value }
      case TAG_EMULE_OPTIONS1:
        return { tag_name: 'options1', tag_value: value }
      case TAG_EMULE_OPTIONS2:
        return { tag_name: 'options2', tag_value: value }
      case TAG_IPV6:
        return { tag_name: 'ipv6', tag_value: value }
      case ED2K_Publishing.CT_FILENAME:
        return { tag_name: 'filename', tag_value: value }
      case ED2K_Publishing.CT_FILESIZE:
        return { tag_name: 'filesize', tag_value: value }
      case ED2K_Publishing.CT_FILETYPE:
        return { tag_name: 'filetype', tag_value: value }
      default:
        return { tag_name: code!.toString(), tag_value: value }
    }
  }

  getTags(): Array<TagValue> | TagValue {
    const count = this.getUInt32LE()
    const tags: Array<TagValue> = []
    for (let i = 0; i < count; i++) {
      const tag = this.getTag()
      if (tag === false) return { tag_name: 'TAGERROR', tag_value: true }
      tags.push(tag)
    }
    return tags
  }

  getFileList(callback?: (file: FileInfo) => void): number {
    const count = this.getUInt32LE()
    for (let i = 0; i < count; i++) {
      const file: FileInfo = {
        hash: this.get(16),
        complete: 1
      }
      const id = this.getUInt32LE()
      const port = this.getUInt16LE()
      const tags = this.getTags()

      if (Array.isArray(tags)) {
        const name = tags.find((x) => x.tag_name === 'name')
        if (name) file.name = name.tag_value as string

        const size = tags.find((x) => x.tag_name === 'size')
        if (size) file.size = BigInt(size.tag_value as number)

        const type = tags.find((x) => x.tag_name === 'type')
        if (type) file.type = type.tag_value as number

        const sizehi = tags.find((x) => x.tag_name === 'sizehi')
        if (sizehi) file.sizehi = sizehi.tag_value as number

        if (id === VAL_PARTIAL_ID && port === VAL_PARTIAL_PORT) {
          file.complete = 0
        } else if (id === VAL_COMPLETE_ID && port === VAL_COMPLETE_PORT) {
          file.complete = 1
        }

        if (file.sizehi && file.size) {
          file.size += BigInt(file.sizehi) * BigInt(0x100000000)
        } else {
          file.sizehi = 0
        }

        if (callback) callback(file)
      }
    }
    return count
  }
}
