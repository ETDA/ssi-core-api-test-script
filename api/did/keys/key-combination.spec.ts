import { DID } from '../register/did-register'
import { KEY_TYPE } from '../../consts'
import { DIDNonce } from '../register/nonce'
import { DIDKey } from './add-key'
// import { Mobile } from './mobile'
import { Recoverer } from './recoverer'
import { DIDDoc } from '../docs/doc'

let getInitState: any = () => ({
  didKey1: [],
  didKey2: [],
  didKey3: [],
  recovererKey1: [],
  controllerKey1: [],
  keyId:'',
  data: {
    did: '',
    nonce: ''
  },
  recoverer: {
    did: '',
    nonce:''
  },
  controller:{
    did: ''
  }
})

describe('Key combinations', () => {
  const state = getInitState()
  jest.setTimeout(60000)

  beforeEach(() => {
    state.didKey1 = []
    state.didKey2 = []
    state.didKey3 = []
    state.recovererKey1 = []
  })

  test('Use ECDSA key to add ECDSA key', async () => {
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
      state.didKey2 = addKey.newKey
      expect(addKey.request.status).toEqual(201)
      expect(addKey.request.data.id).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
    } catch (err) {
      console.log(err.response)
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use ECDSA key to add RSA key', async () => {
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
        KEY_TYPE.RsaVerificationKey2018, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      state.didKey2 = addKey.newKey
      expect(addKey.request.status).toEqual(201)
      expect(addKey.request.data.id).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
    } catch (err) {
      console.log(err.response)
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use RSA key to add RSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
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
        KEY_TYPE.RsaVerificationKey2018, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      state.didKey2 = addKey.newKey
      expect(addKey.request.status).toEqual(201)
      expect(addKey.request.data.id).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
    } catch (err) {
      console.log(err.response)
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use RSA key to add ECDSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
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
      state.didKey2 = addKey.newKey
      expect(addKey.request.status).toEqual(201)
      expect(addKey.request.data.id).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
    } catch (err) {
      console.log(err.response)
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use ECDSA key to reset key then add ECDSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Controller Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(200)

      const didDoc1 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc1: ', JSON.stringify(didDoc1.data, null, 2))
      expect(didDoc1.status).toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use ECDSA key to reset key then add RSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Controller Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.RsaVerificationKey2018,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(200)

      const didDoc1 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc1 : ', JSON.stringify(didDoc1.data, null, 2))
      expect(didDoc1.status).toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use RSA key to reset key then add RSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const controllerRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('Controller Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const recovererRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.RsaVerificationKey2018,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(200)

      const didDoc1 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc1 : ', JSON.stringify(didDoc1.data, null, 2))
      expect(didDoc1.status).toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Use RSA key to reset key then add ECDSA key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const controllerRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('Controller Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const recovererRegister = await DID.Register(KEY_TYPE.RsaVerificationKey2018)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(200)

      const didDoc1 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc1 : ', JSON.stringify(didDoc1.data, null, 2))
      expect(didDoc1.status).toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
