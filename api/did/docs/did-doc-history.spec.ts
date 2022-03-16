import { DID } from '../register/did-register'
import { KEY_TYPE } from '../../consts'
import { DIDNonce } from '../register/nonce'
import { DIDKey } from '../keys/add-key'
import { DIDDoc } from './doc'

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  didKey4: [],
  data: {
    did: '',
    nonce: ''
  },
  didId: '',
  vc: {
    version1: '',
    version2: ''
  }
})

describe('DID Document', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() => {
    state.didKey1 = []
  })

  test('Get DID Document', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      expect(didDocHistory1.data.did_document[0].id).toBe(state.data.did)
      expect(didDocHistory1.data.did_document[0].verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
      state.vc.version1 = didDocHistory1.data.did_document[0].version

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null,2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id
      state.didKey2 = addKey.newKey

      const didDocHistory2 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History2 : ', JSON.stringify(didDocHistory2.data, null, 2))
      expect(didDocHistory2.status).toEqual(200)
      expect(didDocHistory2.data.did_document[1].id).toBe(state.data.did)
      expect(didDocHistory2.data.did_document[1].verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
      expect(didDocHistory2.data.did_document[1].version).not.toBe(state.vc.version1)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
