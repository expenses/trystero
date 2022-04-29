import {encodeBytes, decodeBytes} from './utils'

const algo = 'AES-CBC'

const ecdsa_params = {
  name: 'ECDSA',
  hash: {name: "SHA-384"},
}

const ecdsa_import_params = {
  name: 'ECDSA',
  namedCurve: 'P-384'
};

const pack = buff =>
  window.btoa(String.fromCharCode.apply(null, new Uint8Array(buff)))

const unpack = packed => {
  const str = window.atob(packed)

  return new Uint8Array(str.length).map((_, i) => str.charCodeAt(i)).buffer
}

export const genKey = async (secret, ns) =>
  crypto.subtle.importKey(
    'raw',
    await crypto.subtle.digest(
      {name: 'SHA-256'},
      encodeBytes(`${secret}:${ns}`)
    ),
    {name: algo},
    false,
    ['encrypt', 'decrypt']
  )

export const encrypt = async (keyP, plaintext) => {
  const iv = crypto.getRandomValues(new Uint8Array(16))

  return JSON.stringify({
    c: pack(
      await crypto.subtle.encrypt(
        {name: algo, iv},
        await keyP,
        encodeBytes(plaintext),
        plaintext
      )
    ),
    iv: [...iv]
  })
}

export const decrypt = async (keyP, raw) => {
  const {c, iv} = JSON.parse(raw)

  return decodeBytes(
    await crypto.subtle.decrypt(
      {name: algo, iv: new Uint8Array(iv)},
      await keyP,
      unpack(c)
    )
  )
}

export const sign = async (key_pair, sdp) => {
  const encoder = new TextEncoder();
  const encoded_sdp = encoder.encode(sdp);
  const signature = await crypto.subtle.sign(ecdsa_params, key_pair.privateKey, encoded_sdp);
  const exported_key = await crypto.subtle.exportKey('jwk', key_pair.publicKey);

  return JSON.stringify({
    sdp: sdp,
    signature: pack(signature),
    key: exported_key,
  });
}

export const verify = async (string) => {
  const data = JSON.parse(string);
  const imported_key = await crypto.subtle.importKey('jwk', data.key, ecdsa_import_params, true, ['verify']);

  const encoder = new TextEncoder();
  const encoded_sdp = encoder.encode(data.sdp);

  const signature = unpack(data.signature);
  const verified = await window.crypto.subtle.verify(ecdsa_params, imported_key, signature, encoded_sdp);

  return {
    sdp: data.sdp,
    verified: verified,
    key: imported_key,
  };
}
