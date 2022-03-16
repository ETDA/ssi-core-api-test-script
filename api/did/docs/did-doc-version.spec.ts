import { DID } from '../register/did-register'
import { KEY_TYPE } from '../../consts'
import { DIDNonce } from '../register/nonce'
import { DIDKey } from '../keys/add-key'
import { DIDDoc } from './doc'
import { v4 as uuidv4 } from 'uuid'

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

  test('Get DID Document by version', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id
      state.didKey2 = addKey.newKey

      const didDoc = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc: ', JSON.stringify(didDoc.data, null, 2))
      expect(didDoc.status).toEqual(200)
      state.vc.version1 = didDoc.data.did_document[0].version
      state.vc.version2 = didDoc.data.did_document[1].version

      const didDocVer1 = await DIDDoc.GetVersion(state.data.did, state.vc.version1)
      console.log('DID Doc ver1: ', JSON.stringify(didDocVer1.data, null, 2))
      expect(didDocVer1.status).toEqual(200)
      expect(didDocVer1.data.id).toBe(state.data.did)
      expect(didDocVer1.data.verificationMethod[0].id).not.toBe(state.keyId)
      expect(didDocVer1.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
      expect(didDocVer1.data.version).toBe(state.vc.version1)

      const didDocVer2 = await DIDDoc.GetVersion(state.data.did, state.vc.version2)
      console.log('DID Doc ver2: ', JSON.stringify(didDocVer2.data, null, 2))
      expect(didDocVer2.status).toEqual(200)
      expect(didDocVer2.data.id).toBe(state.data.did)
      expect(didDocVer2.data.verificationMethod[0].id).not.toBe(state.keyId)
      expect(didDocVer2.data.verificationMethod[1].id).toBe(state.keyId)
      expect(didDocVer2.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
      expect(didDocVer2.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
      expect(didDocVer2.data.version).toBe(state.vc.version2)

    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Get DID Document with incorrect version', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const dummyVcVersion = uuidv4()
      const didDocVer1 = await DIDDoc.GetVersion(state.data.did, dummyVcVersion)
      console.log('DID Doc ver1: ', JSON.stringify(didDocVer1.data, null, 2))
      expect(didDocVer1.status).not.toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(404)
    }
  })
})
