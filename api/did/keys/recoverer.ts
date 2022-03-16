import { CONFIG, KEY_TYPE, OPERATION } from '../../consts'
import axios from 'axios'
import { CryptoHelper as RsaHelper } from '../../utils/rsa-CrytoHelper'
import { CryptoHelper as EcdsaHelper } from '../../utils/ecdsa-CryptoHelper'

const genEcdsaKeys = (count: number) => {
  const result = []
  for (let i = 0; i < count; i++) {
    result.push(EcdsaHelper.genKeys())
  }
  return result
}

const genRsaKeys = (count: number) => {
  const result = []
  for (let i = 0; i < count; i++) {
    result.push(RsaHelper.genKeys())
  }
  return result
}

const genAddRecovererMessage = (obj: {
  did_address: string, recoverer: string, nonce: string
}) => {
  return {
    operation: OPERATION.DID_RECOVERER_ADD,
    did_address: obj.did_address,
    recoverer: obj.recoverer,
    nonce: obj.nonce
  }
}

const genResetKeyMessage = (obj: {
  did_address: string, request_did: string, public_key: string, signature: string,
  controller: string, key_type: string, nonce: string
}) => {
  return {
    operation: OPERATION.DID_KEY_RESET,
    did_address: obj.did_address,
    request_did: obj.request_did,
    new_key: {
      public_key: obj.public_key,
      signature: obj.signature,
      controller: obj.controller,
      key_type: obj.key_type
    },
    nonce: obj.nonce
  }
}

const genRequestData = (private_key: string, message: any) => {
  const messageData = RsaHelper.encodeBase64(JSON.stringify(message))
  return {
    data: {
      message: messageData
    },
    headers: {
      'x-signature': RsaHelper.sign(private_key, messageData)
    }
  }
}

export class Recoverer {

  static async Add (didAddress: string, didKey: any, recovererDid: string, nonce: string) {
    const message = genAddRecovererMessage({
      did_address: didAddress,
      recoverer: recovererDid,
      nonce: nonce
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: Add recoverer: ', JSON.stringify(message, null, 2))
    console.log('headers: Add recoverer', JSON.stringify(res.headers, null, 2))
    console.log('body: Add recoverer', JSON.stringify(res.data, null, 2))
    return await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/recoverer/register`,
      res.data, { headers: res.headers })
  }

  static async ResetKey (recovererDid: string, didKey: any,
    requestToDid: string, controller: string, keyType: string, nonce: string) {
    let newKey: any
    if (keyType == KEY_TYPE.EcdsaSecp256r1VerificationKey2019) {
      newKey = genEcdsaKeys(1)
    } else {
      newKey = genRsaKeys(1)
    }
    const new_key = newKey[0].public_key
    const new_key_signature = RsaHelper.sign(newKey[0].private_key, new_key)
    const message = genResetKeyMessage({
      did_address: recovererDid,
      request_did: requestToDid,
      public_key: new_key,
      signature: new_key_signature,
      controller: controller,
      key_type: keyType,
      nonce: nonce
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: Reset key: ', JSON.stringify(message, null, 2))
    console.log('headers: Reset key: ', JSON.stringify(res.headers, null, 2))
    console.log('body: Reset key: ', JSON.stringify(res.data, null, 2))
    return {
      request: await axios.post(`${CONFIG.BASE_URL}/did/${recovererDid}/keys/reset`,
        res.data, { headers: res.headers }),
      newKey
    }
  }
}
