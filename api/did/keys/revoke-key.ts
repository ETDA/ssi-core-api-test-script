import { CONFIG, OPERATION } from '../../consts'
import axios from 'axios'
import { CryptoHelper } from '../../utils/rsa-CrytoHelper'

const genKeyRevokeMessage = (obj: {
  did_address: string,
  key_id: string
  nonce: string
}) => {
  return {
    operation: OPERATION.DID_KEY_REVOKE,
    key_id : obj.key_id,
    did_address: obj.did_address,
    nonce: obj.nonce
  }
}

const genRequestData = (private_key: string, message: any) => {
  const messageData = CryptoHelper.encodeBase64(JSON.stringify(message))
  return {
    data: {
      message: messageData
    },
    headers: {
      'x-signature': CryptoHelper.sign(private_key, messageData)
    }
  }
}

export class DIDKeyRevoke {
  static async RevokeKey (didAddress: string, didKey: any, keyId: string, nonce: string) {
    const message = genKeyRevokeMessage({
      did_address: didAddress,
      key_id: keyId,
      nonce: nonce
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: DID Key revoke',JSON.stringify(message, null, 2))
    console.log('headers: DID Key revoke',JSON.stringify(res.headers,null, 2))
    console.log('body: DID Key revoke',JSON.stringify(res.data,null, 2))
    return await axios.post(`${CONFIG.BASE_URL}/did/${didAddress}/keys/${keyId}/revoke`,
      res.data, { headers: res.headers })
  }
}
