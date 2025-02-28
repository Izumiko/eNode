import {
  OP_HELLO,
  PS_NEW,
  PS_WAITING_DATA,
  PS_CRYPT_NEGOTIATING,
  PS_READY,
  PR_ED2K,
  PR_ZLIB,
  PR_EMULE,
  OP_LOGINREQUEST,
  OP_OFFERFILES,
  OP_GETSERVERLIST,
  OP_GETSOURCES_OBFU,
  OP_GETSOURCES,
  OP_SEARCHREQUEST,
  OP_CALLBACKREQUEST,
  ENODE_VERSIONSTR,
  ENODE_NAME,
  CS_ENCRYPTING,
  TYPE_UINT8,
  OP_FOUNDSOURCES,
  TYPE_HASH,
  TYPE_UINT32,
  TYPE_UINT16,
  OP_SEARCHRESULT,
  OP_SERVERLIST,
  OP_SERVERSTATUS,
  OP_IDCHANGE,
  OP_CALLBACKFAILED,
  OP_SERVERIDENT,
  TYPE_TAGS,
  TYPE_STRING,
  TAG_SERVER_NAME,
  TAG_SERVER_DESC,
  OP_SERVERMESSAGE,
  OP_CALLBACKREQUESTED
} from './op.js'
import conf from '../enode.config.js'
import { pino } from 'pino'
import net, { Socket } from 'node:net'
import { lowIdClients } from './lowidclients.js'
import { Packet } from './packet.js'
import { unzip } from 'node:zlib'
import { Client } from './client.js'
import db from '../storage/storage'
import { TcpCrypt } from './tcpcrypt.js'
import { Ed2kBuffer } from './buffer.js'
import { hexDump, IPv6BufferToString, IPv6StringToBuffer, IsValidIpv6 } from './misc.js'

// var crypt = require('./crypt')
// var eD2KClient = require('./client').Client

const logger = pino({
  name: 'tcp_operations',
  level: 'info'
})

export interface TcpClient extends Socket {
  info: {
    hash: Buffer
    id: number
    port: number
    tags: Tag[]
    ipv6?: number
    ipv4: number
    logged: boolean
    storageId: number
    hasLowId: boolean
  }
  packet: Packet
  crypt: TcpCrypt | false
}

/**
 * Checks if a client is firewalled
 *
 * @param {Socket} client
 * @param {Object} client.info Client information
 * @param {Integer} client.info.port Port to check
 * @param {Function} callback(isFirewalled) Callback argument is boolean. True if firewalled.
 */
const isFirewalled = (client: TcpClient, crypted: boolean, callback): void => {
  logger.info('Checking if firewalled')
  const testClient = new Client()

  testClient.on('connected', () => {
    if (crypted) {
      logger.trace('isFirewalled: Sending handshake to ' + client.remoteAddress)
      testClient.handshake()
    } else {
      logger.trace(
        'isFirewalled: Send HELLO to ' +
          client.remoteAddress +
          ':' +
          client.info.port
      )
      testClient.send(OP_HELLO, null, function (err) {})
    }
  })

  testClient.on('error', (err) => {
    logger.error(err)
    testClient.end()
    callback(true)
  })

  testClient.on('timeout', (sender) => {
    logger.trace('isFirewalled: Got timeout from: ' + sender)
    switch (sender) {
      case 'connection':
      case 'hello':
        testClient.end()
        callback(true)
        break
      case 'handshake':
        testClient.end()
        isFirewalled(client, false, callback)
        break
    }
  })

  testClient.on('handshake', (err) => {
    if (err == false) {
      logger.trace(
        'isFirewalled: send HELLO (crypted) to ' +
          client.remoteAddress +
          ':' +
          client.info.port
      )
      testClient.send(OP_HELLO, null, (err) => {
        if (err) logger.error('isFirewalled: sending crypted hello')
      })
    }
    // else do nothing because we will get a handshake timeout
  })

  testClient.on('ophelloanswer', (info) => {
    logger.trace('isFirewalled: Received hello answer!')
    console.dir(info)
    testClient.end()
    callback(false)
  })

  testClient.connect(client.remoteAddress!, client.info.port, client.info.hash)
}

/**
 * Processes incoming TCP data
 *
 * @param {Buffer} data Incoming data
 * @param {Socket} client The client who sends the data
 * @param {Packet} client.packet Packet object from client
 */
export const processData = (data: Ed2kBuffer, client: TcpClient) => {
  // process incoming data
  switch (client.packet.status) {
    case PS_NEW:
      //log.trace('tcpops.processData: New')
      client.packet.init(data)
      break
    case PS_WAITING_DATA:
      //log.trace('tcpops.processData: Waiting data...')
      client.packet.append(data)
      break
    case PS_CRYPT_NEGOTIATING:
      //log.trace('tcpops.processData: Negotiation response')
      if (client.crypt) client.crypt.process(data)
      break
    default:
      //log.error('tcpops.processData 1: unexpected Packet Status')
      console.dir(client.packet)
      return
  }
  // execute action
  switch (client.packet.status) {
    case PS_READY:
      parse(client.packet)
      break
    default:
  }
}

/**
 * Parses a clients packet and depending on it's header takes action
 *
 * @param {Socket} client
 * @param {Packet} client.packet Packet object from client
 */
const parse = (packet: Packet) => {
  //log.trace('TCP op.receive.parse')
  //log.trace(client.info)
  switch (packet.protocol) {
    case PR_ED2K:
      ed2k(packet.client)
      break
    case PR_ZLIB:
      unzip(packet.data.internalBuffer, (err, buffer) => {
        if (!err) {
          packet.data = new Ed2kBuffer(buffer)
          ed2k(packet.client)
        } else {
          logger.error('Cannot unzip: operation 0x' + packet.code.toString(16))
        }
      })
      break
    case PR_EMULE:
      logger.warn(
        'TCP: Unsupported protocol: PR_EMULE (0x' +
          packet.protocol.toString(16) +
          ')'
      )
      break
    default:
      logger.warn('TCP: Unknown protocol: 0x' + packet.protocol.toString(16))
      hexDump(packet.data.internalBuffer)
    // if (this.packet.crypt.status == CS_NONE) {
    //   log.warn('Encription is disabled!')
    // }
    // else if (this.packet.crypt.status == CS_UNKNOWN) {
    //   log.info('Incoming possible obfuscated data. Start negotiation.')
    //   this.packet.crypt.init(packet.data.get())
    // }
  }
  packet.status = PS_NEW
  if (packet.hasExcess) {
    processData(packet.excess, packet.client)
  }
}

/**
 * Error handler for socket.write operations
 *
 * @param err Information about the error or false if there isn't.
 */
const writeError = (err: any) => {
  if (err) {
    logger.error('Socket write error: ' + JSON.stringify(err))
  }
}

/**
 * Executes an eD2K operation
 *
 * @param {net.Socket} client
 * @param {Packet} client.packet
 */
const ed2k = (client: TcpClient) => {
  client.packet.data.pos(0)
  switch (client.packet.code) {
    case OP_LOGINREQUEST:
      receive.loginRequest(client)
      break
    case OP_OFFERFILES:
      receive.offerFiles(client)
      break
    case OP_GETSERVERLIST:
      receive.getServerList(client)
      break
    case OP_GETSOURCES_OBFU:
    case OP_GETSOURCES:
      receive.getSources(client)
      break
    case OP_SEARCHREQUEST:
      receive.searchRequest(client)
      break
    case OP_CALLBACKREQUEST:
      receive.callbackRequest(client)
      break
    default:
      logger.warn(
        'ed2k: Unhandled opcode: 0x' + client.packet.code.toString(16)
      )
  }
}

const receive = {
  handShake: (client: TcpClient) => {
    db.clients.connect(client.info, function (err, storageId) {
      if (!err) {
        client.info.logged = true
        logger.info('Storage ID: ' + storageId)
        client.info.storageId = storageId
        send.serverMessage(conf.messageLogin, client)
        send.serverMessage(
          'server version ' + ENODE_VERSIONSTR + ' (' + ENODE_NAME + ')',
          client
        )
        send.serverStatus(client)
        send.idChange(client.info.id, client)
        send.serverIdent(client)
      } else {
        logger.error(err)
        //send.serverMessage(clientStorage.message, client)
        logger.todo('handShake: send reject command')
        //client.end()
      }
    })
  },

  loginRequest: (client: TcpClient) => {
    logger.debug('LOGINREQUEST < ' + client.info.ipv4)
    const data: Ed2kBuffer = client.packet.data
    client.info.hash = data.get(16)
    client.info.id = data.getUInt32LE()
    client.info.port = data.getUInt16LE()
    client.info.tags = data.getTags()
    client.info.ipv6 = null

    const ipv6 = client.info.tags.find((x) => x[0] === 'ipv6')
    if (ipv6 && IsValidIpv6(ipv6[1])) {
      client.info.ipv6 = IPv6StringToBuffer(ipv6[1])
      logger.trace('ipv6: ' + IPv6BufferToString(client.info.ipv6))
    }
    db.clients.isConnected(client.info, function (err, connected) {
      if (err) {
        logger.error('loginRequest: ' + err)
        client.end()
        return
      }
      if (connected) {
        logger.error('loginRequest: already connected')
        client.end()
        return
      }
      isFirewalled(client, conf.supportCrypt, function (firewalled) {
        if (firewalled) {
          client.info.hasLowId = true
          send.serverMessage(conf.messageLowID, client)
          client.info.id = lowIdClients.add(client)
          if (client.info.id != false) {
            receive.handShake(client)
            logger.info('Assign LowId: ' + client.info.id)
          } else {
            client.end()
          }
        } else {
          client.info.hasLowId = false
          client.info.id = client.info.ipv4
          client.info.hasLowId = false
          receive.handShake(client)
          logger.info('Assign HighID: ' + client.info.id)
        }
      })
    })
  },

  offerFiles: function (client) {
    logger.debug('OFFERFILES < ' + client.info.storageId)
    var count = client.packet.data.getFileList(function (file) {
      logger.trace(
        file.name + ' ' + file.size + ' ' + file.hash.toString('hex')
      )
      db.files.add(file, client.info)
    })
    logger.trace(
      'Got ' +
        count +
        ' files from ' +
        client.remoteAddress +
        ' Total files: ' +
        db.files.getCount()
    )
  },

  getServerList: function (client) {
    logger.debug('GETSERVERLIST < ' + client.info.storageId)
    send.serverList(client)
    send.serverIdent(client)
  },

  getSources: function (client) {
    logger.debug('GETSOURCES < ' + client.info.storageId)
    var file = {
      hash: client.packet.data.get(16),
      size: client.packet.data.getUInt32LE(),
      sizehi: 0
    }
    if (file.size == 0) {
      // large file, read 64bits
      file.size = client.packet.data.getUInt32LE()
      file.size += client.packet.data.getUInt32LE() * 0x100000000
    }
    db.files.getSources(file.hash, function (sources) {
      logger.trace(
        'Got ' +
          sources.length +
          ' sources for file: ' +
          file.hash.toString('hex')
      )
      send.foundSources(file.hash, sources, client)
    })
  },

  searchRequest: function (client) {
    logger.info('SEARCHREQUEST < ' + client.info.storageId)
    //log.text(hexDump(client.packet.data))
    db.files.find(client.packet.data, function (files) {
      send.searchResult(files, client)
    })
  },

  //
  // Client A (High ID)    Server          Client B (Low ID)
  //  |>---CallbackRequest---->|              |
  //  |            |>---CallbackRequested---->|
  //  |<----------------------------------Connect--------<|
  //  :            :              :
  //  |<----CallbackFailed----<|              |

  callbackRequest: function (client) {
    logger.info('CALLBACKREQUEST < ' + client.info.storageId)
    var lowId = client.packet.data.getUInt32LE() // properties are hex strings
    let clientWithLowId = lowIdClients.get(lowId)
    if (clientWithLowId != false) {
      send.callbackRequested(clientWithLowId, client)
    } else {
      logger.debug('CallbackRequest failed: LowId client is not connected')
      send.callbackFailed(client)
    }
  }
}

var submit = function (data, client, errCallback?) {
  if (client.crypt.status == CS_ENCRYPTING) {
    //log.trace('*** Encrypting packet')
    data = crypt.RC4Crypt(data, data.length, client.crypt.sendKey)
  }
  if (errCallback == undefined) {
    errCallback = writeError
  }
  client.write(data, errCallback)
}

var send = {
  foundSources: function (fileHash, sources, client) {
    logger.debug('FOUNDSOURCES > ' + client.info.storageId)
    logger.todo(
      'OP_FOUNDSOURCES_OBFU: add client crypt info. See PartFile.cpp CPartFile::AddSources'
    )
    var pack = [
      [TYPE_UINT8, OP_FOUNDSOURCES],
      [TYPE_HASH, fileHash]
    ]
    const ipv4Source = sources
    // const ipv4Source = sources.filter(x => !x.ipv6);
    pack.push([TYPE_UINT8, ipv4Source.length])
    ipv4Source.forEach(function (src) {
      pack.push([TYPE_UINT32, src.id])
      pack.push([TYPE_UINT16, src.port])
    })
    const ipv6Source = sources.filter((x) => x.ipv6)
    pack.push([TYPE_UINT16, ipv6Source.length])
    ipv6Source.forEach((src) => {
      pack.push([TYPE_HASH, src.ipv6])
      pack.push([TYPE_UINT16, src.port])
    })
    submit(Packet.make(PR_ED2K, pack), client)
  },

  searchResult: function (files, client) {
    logger.debug('SEARCHRESULT > ' + client.info.storageId)
    var pack = [
      [TYPE_UINT8, OP_SEARCHRESULT],
      [TYPE_UINT32, files.length]
    ]
    files.forEach(function (file) {
      Packet.addFile(pack, file)
    })
    submit(Packet.make(PR_ED2K, pack), client)
  },

  serverList: function (client) {
    logger.debug('SERVERLIST > ' + client.info.storageId)
    var pack = [
      [TYPE_UINT8, OP_SERVERLIST],
      [TYPE_UINT8, db.servers.getCount()]
    ]
    db.servers.all().forEach(function (v) {
      logger.trace(v.ip + ':' + v.port)
      pack.push([TYPE_UINT32, misc.IPv4toInt32LE(v.ip)])
      pack.push([TYPE_UINT16, v.port])
    })
    submit(Packet.make(PR_ED2K, pack), client)
  },

  serverStatus: function (client) {
    logger.debug(
      'SERVERSTATUS > ' +
        client.info.storageId +
        ' clients: ' +
        db.clients.getCount() +
        ' files: ' +
        db.files.getCount()
    )
    var pack = [
      [TYPE_UINT8, OP_SERVERSTATUS],
      [TYPE_UINT32, db.clients.getCount()],
      [TYPE_UINT32, db.files.getCount()]
    ]
    submit(Packet.make(PR_ED2K, pack), client)
  },

  idChange: function (id, client) {
    logger.debug('IDCHANGE > ' + client.info.storageId + ' id: ' + id)
    var pack = [
      [TYPE_UINT8, OP_IDCHANGE],
      [TYPE_UINT32, id],
      [TYPE_UINT32, conf.tcp.flags]
    ]
    submit(Packet.make(PR_ED2K, pack), client)
  },

  callbackFailed: function (client) {
    logger.debug('CALLBACKFAILED > ' + client.info.storageId)
    var pack = [[TYPE_UINT8, OP_CALLBACKFAILED]]
    submit(Packet.make(PR_ED2K, pack), client)
  },

  serverIdent: function (client) {
    logger.debug('SERVERIDENT > ' + client.info.storageId)
    var pack = [
      [TYPE_UINT8, OP_SERVERIDENT],
      [TYPE_HASH, conf.hash],
      [TYPE_UINT32, misc.IPv4toInt32LE(conf.address)],
      [TYPE_UINT16, conf.tcp.port],
      [
        TYPE_TAGS,
        [
          [TYPE_STRING, TAG_SERVER_NAME, conf.name],
          [TYPE_STRING, TAG_SERVER_DESC, conf.description]
        ]
      ]
    ]
    submit(Packet.make(PR_ED2K, pack), client)
  },

  serverMessage: function (message, client) {
    logger.debug('SERVERMESSAGE > ' + client.info.storageId + ' ' + message)
    var pack = [
      [TYPE_UINT8, OP_SERVERMESSAGE],
      [TYPE_STRING, message.toString()]
    ]
    submit(Packet.make(PR_ED2K, pack), client)
  },

  callbackRequested: function (clientWithLowId, client) {
    // TODO: TEST
    logger.info('CALLBACKREQUESTED > ' + clientWithLowId.info.id)
    var pack = [
      [TYPE_UINT8, OP_CALLBACKREQUESTED],
      [TYPE_UINT32, client.info.ipv4],
      [TYPE_UINT16, client.info.port]
    ]
    submit(Packet.make(PR_ED2K, pack), clientWithLowId, function (err) {
      if (err) {
        writeError(err)
        send.callbackFailed(client)
      }
    })
  }
}
