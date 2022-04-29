import room from './room'
import {
  encodeBytes,
  entries,
  events,
  fromEntries,
  genId,
  initGuard,
  initPeer,
  libName,
  mkErr,
  noOp,
  selfId,
  values
} from './utils'
import {genKey, encrypt, sign, verify, decrypt} from './crypto'

const occupiedRooms = {}
const sockets = {}
const socketListeners = {}
const hashLimit = 20
const offerPoolSize = 10
const defaultRedundancy = 2
const defaultAnnounceSecs = 33
const maxAnnounceSecs = 120
const trackerAction = 'announce'
const defaultTrackerUrls = [
  'wss://tracker.openwebtorrent.com',
  'wss://tracker.btorrent.xyz',
  'wss://tracker.files.fm:7073/announce',
  'wss://spacetradersapi-chatbox.herokuapp.com:443/announce'
]

export const joinRoom = initGuard(occupiedRooms, (config, ns) => {
  const connectedPeers = {}
  const key = config.password && genKey(config.password, ns)
  const trackerUrls = (config.trackerUrls || defaultTrackerUrls).slice(
    0,
    config.trackerUrls
      ? config.trackerUrls.length
      : config.trackerRedundancy || defaultRedundancy
  )

  if (!trackerUrls.length) {
    throw mkErr('trackerUrls is empty')
  }

  const infoHashP = crypto.subtle
    .digest('SHA-1', encodeBytes(`${libName}:${config.appId}:${ns}`))
    .then(buffer =>
      Array.from(new Uint8Array(buffer))
        .map(b => b.toString(36))
        .join('')
        .slice(0, hashLimit)
    )

  const makeOffers = () =>
    fromEntries(
      new Array(offerPoolSize).fill().map(() => {
        const peer = initPeer(true, false, config.rtcConfig)

        return [
          genId(hashLimit),
          {peer, offerP: new Promise(res => peer.once(events.signal, res))}
        ]
      })
    )

  const onSocketMessage = async (socket, e) => {
    const infoHash = await infoHashP
    let val

    try {
      val = JSON.parse(e.data)
    } catch (e) {
      console.error(`${libName}: received malformed SDP JSON`)
      return
    }

    if (val.info_hash !== infoHash || (val.peer_id && val.peer_id === selfId)) {
      return
    }

    const failure = val['failure reason']

    if (failure) {
      console.warn(`${libName}: torrent tracker failure (${failure})`)
      return
    }

    if (
      val.interval &&
      val.interval > announceSecs &&
      val.interval <= maxAnnounceSecs
    ) {
      clearInterval(announceInterval)
      announceSecs = val.interval
      announceInterval = setInterval(announceAll, announceSecs * 1000)
    }

    if (val.offer && val.offer_id) {
      if (connectedPeers[val.peer_id] || handledOffers[val.offer_id]) {
        return
      }

      handledOffers[val.offer_id] = true

      const peer = initPeer(false, false, config.rtcConfig)

      peer.once(events.signal, async answer =>
        socket.send(
          JSON.stringify({
            answer: {...answer, sdp: await sign(config.signing_key, answer.sdp)},
            action: trackerAction,
            info_hash: infoHash,
            peer_id: selfId,
            to_peer_id: val.peer_id,
            offer_id: val.offer_id
          })
        )
      )
      peer.on(events.connect, () => onConnect(peer, val.peer_id))
      peer.on(events.close, () => onDisconnect(val.peer_id))

      const verification_result = await verify(val.offer.sdp);

      if (verification_result.verified) {
        peer.signal(
          {...val.offer, sdp: verification_result.sdp}
        );

        console.log(`Verified ${val.peer_id}`);
        peer.key = verification_result.key;
      } else {
        console.warn(`Peer ${val.peer_id} sent a SDP that failed verification.`);
      }

      return
    }

    if (val.answer) {
      if (connectedPeers[val.peer_id] || handledOffers[val.offer_id]) {
        return
      }

      const offer = offerPool[val.offer_id]

      if (offer) {
        const {peer} = offer

        if (peer.destroyed) {
          return
        }

        handledOffers[val.offer_id] = true
        peer.on(events.connect, () =>
          onConnect(peer, val.peer_id, val.offer_id)
        )
        peer.on(events.close, () => onDisconnect(val.peer_id))

        const verification_result = await verify(val.answer.sdp);

        if (verification_result.verified) {
          peer.signal(
            {...val.answer, sdp: verification_result.sdp}
          );

          console.log(`Verified ${val.peer_id}`);
          peer.key = verification_result.key;
        } else {
          console.warn(`Peer ${val.peer_id} sent a SDP that failed verification.`);
        }
      }
    }
  }

  const announce = async (socket, infoHash) =>
    socket.send(
      JSON.stringify({
        action: trackerAction,
        info_hash: infoHash,
        numwant: offerPoolSize,
        peer_id: selfId,
        offers: await Promise.all(
          entries(offerPool).map(async ([id, {offerP}]) => {
            const offer = await offerP

            return {
              offer_id: id,
              offer: {...offer, sdp: await sign(config.signing_key, offer.sdp)}
            }
          })
        )
      })
    )

  const makeSocket = (url, infoHash, forced) => {
    if (forced || !sockets[url]) {
      socketListeners[url] = {
        ...socketListeners[url],
        [infoHash]: onSocketMessage
      }
      sockets[url] = new Promise(res => {
        const socket = new WebSocket(url)
        socket.onopen = res.bind(null, socket)
        socket.onmessage = e =>
          values(socketListeners[url]).forEach(f => f(socket, e))
      })
    } else {
      socketListeners[url][infoHash] = onSocketMessage
    }

    return sockets[url]
  }

  const announceAll = async () => {
    const infoHash = await infoHashP

    if (offerPool) {
      cleanPool()
    }

    offerPool = makeOffers()

    trackerUrls.forEach(async url => {
      const socket = await makeSocket(url, infoHash)

      if (socket.readyState === WebSocket.OPEN) {
        announce(socket, infoHash)
      } else if (socket.readyState !== WebSocket.CONNECTING) {
        announce(await makeSocket(url, infoHash, true), infoHash)
      }
    })
  }

  const cleanPool = () => {
    entries(offerPool).forEach(([id, {peer}]) => {
      if (!handledOffers[id] && !connectedPeers[id]) {
        peer.destroy()
      }
    })

    handledOffers = {}
  }

  const onConnect = (peer, id, offerId) => {
    onPeerConnect(peer, id)
    connectedPeers[id] = true

    if (offerId) {
      connectedPeers[offerId] = true
    }
  }

  const onDisconnect = id => delete connectedPeers[id]

  let announceSecs = defaultAnnounceSecs
  let announceInterval = setInterval(announceAll, announceSecs * 1000)
  let onPeerConnect = noOp
  let handledOffers = {}
  let offerPool

  occupiedRooms[ns] = true
  announceAll()

  return room(
    f => (onPeerConnect = f),
    async () => {
      const infoHash = await infoHashP

      trackerUrls.forEach(url => delete socketListeners[url][infoHash])
      delete occupiedRooms[ns]
      clearInterval(announceInterval)
      cleanPool()
    }
  )
})

export {selfId} from './utils'
