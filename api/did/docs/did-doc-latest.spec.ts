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
  didId: ''
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

      const didDoc1 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc1 : ', JSON.stringify(didDoc1.data, null, 2))
      expect(didDoc1.status).toEqual(200)
      expect(didDoc1.data.id).toBe(state.data.did)
      expect(didDoc1.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null,2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.didKey2 = addKey.newKey
      state.keyId = addKey.request.data.verificationMethod[1].id

      const didDoc2 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc2 : ', JSON.stringify(didDoc2.data, null, 2))
      expect(didDoc2.status).toEqual(200)
      expect(didDoc2.data.id).toBe(state.data.did)
      expect(didDoc2.data.verificationMethod[1].id).toBe(state.keyId)
      expect(didDoc2.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
