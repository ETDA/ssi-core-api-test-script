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

const genAddKeyMessage = (obj: {
  did_address: string, nonce: string, key_pem: string, signature: string,
  key_type: string, controller: string
}) => {
  const new_key_data = {
    public_key: obj.key_pem,
    signature: obj.signature,
    key_type: obj.key_type,
    controller: obj.controller,
  }
  return {
    operation: OPERATION.DID_KEY_ADD,
    did_address: obj.did_address,
    new_key: new_key_data,
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

export class DIDKey {

  static async AddKey (didAddress: string, didKey: any, keyType:
    string, nonce: string, controller: string) {
    let newKey: any
    if (keyType == KEY_TYPE.EcdsaSecp256r1VerificationKey2019) {
      newKey = genEcdsaKeys(1)
    } else {
      newKey = genRsaKeys(1)
    }

    const new_key = newKey[0].public_key
    const new_key_signature = RsaHelper.sign(newKey[0].private_key, new_key)
    const message = genAddKeyMessage({
      did_address: didAddress,
      key_pem: new_key,
      signature: new_key_signature,
      key_type: keyType,
      nonce: nonce,
      controller: controller
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: DID Add key', JSON.stringify(message, null, 2))
    console.log('headers: DID Add key', JSON.stringify(res.headers, null, 2))
    console.log('body: DID Add key', JSON.stringify(res.data, null, 2))

    return {
      request: await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/keys`,
        res.data, { headers: res.headers }),
      newKey
    }
  }

  static async AddKeyWithSpecificKey (didAddress: string, didKey: any, newKey: any,keyType:
    string, nonce: string, controller: string) {
    const new_key = newKey[0].public_key
    const new_key_signature = RsaHelper.sign(newKey[0].private_key, new_key)
    const message = genAddKeyMessage({
      did_address: didAddress,
      key_pem: new_key,
      signature: new_key_signature,
      key_type: keyType,
      nonce: nonce,
      controller: controller
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: DID Add key', JSON.stringify(message, null, 2))
    console.log('headers: DID Add key', JSON.stringify(res.headers, null, 2))
    console.log('body: DID Add key', JSON.stringify(res.data, null, 2))

    return {
      request: await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/keys`,
        res.data, { headers: res.headers }),
      newKey
    }
  }

  static async AddKeyWithIncorrectKey (didAddress: string, didKey: any, keyType: string, nonce: string, controller:string) {
    const new_key = 'public_key'
    const new_key_signature = 'public_key'
    const message = genAddKeyMessage({
      did_address: didAddress,
      key_pem: new_key,
      signature: new_key_signature,
      key_type: keyType,
      nonce: nonce,
      controller: controller
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: DID Add key', JSON.stringify(message, null, 2))

    return await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/keys`,
      res.data, { headers: res.headers })
  }

  static async AddKeyWithoutKey (didAddress: string, didKey: any, keyType: string, nonce: string, controller: string) {
    const new_key = ''
    const new_key_signature = ''
    const message = genAddKeyMessage({
      did_address: didAddress,
      key_pem: new_key,
      signature: new_key_signature,
      key_type: keyType,
      nonce: nonce,
      controller: controller
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: DID Add key', JSON.stringify(message, null, 2))

    return await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/keys`,
      res.data, { headers: res.headers })
  }
}
