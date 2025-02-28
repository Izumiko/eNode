import conf from '../enode.config.js'
import { Client } from './client.js'

interface LowClient {
  [key: number]: Client
}

export const lowIdClients = {
  _min: 1,
  _max: 0xffffff,
  _count: 0,
  _next: 1,
  _clients: {} as LowClient,

  _nextId: (): number | false => {
    if (!conf.tcp.allowLowIDs) return false
    if (lowIdClients._count >= lowIdClients._max - lowIdClients._min + 1) {
      return false
    }
    const r = lowIdClients._next
    lowIdClients._next++
    while (lowIdClients._clients.hasOwnProperty(lowIdClients._next)) {
      lowIdClients._next++
      if (lowIdClients._next > lowIdClients._max) {
        lowIdClients._next = lowIdClients._min
      }
    }
    return r
  },

  count: () => lowIdClients._count,

  add: (client: Client): number | false => {
    const id = lowIdClients._nextId()
    if (id) {
      lowIdClients._clients[id] = client
    }
    return id
  },

  get: (id: number) => {
    if (lowIdClients._clients.hasOwnProperty(id)) {
      return lowIdClients._clients[id]
    } else {
      return false
    }
  },

  remove: (id: number) => {
    lowIdClients._count--
    delete lowIdClients._clients[id]
  }
}
