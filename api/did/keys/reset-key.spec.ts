import { DID } from '../register/did-register'
import { ERR_NOT_MATCH, ERR_REQUIRE, ERROR, INVALID, KEY_TYPE } from '../../consts'
import { DIDNonce } from '../register/nonce'
import { Recoverer } from './recoverer'
import { v4 as uuidv4 } from 'uuid'
import { VC } from '../../vc/register/vc'
// import { Mobile } from './mobile'
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

describe('Reset key', () => {

  const state = getInitState()
  jest.setTimeout(60000)

  beforeEach(() => {
    state.didKey1 = []
    state.didKey2 = []
    state.didKey3 = []
    state.recovererKey1 = []
  })

  test('Reset key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

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

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      state.didKey2 = resetKey.newKey
      expect(resetKey.request.status).toEqual(200)
      expect(resetKey.request.data.id).toBe(state.data.did)
      expect(resetKey.request.data.controller).toBe(state.data.did)
      expect(resetKey.request.data.verificationMethod[0].controller).toBe(state.controller.did)
      expect(resetKey.request.data.verificationMethod[0].publicKeyPem).toBe(state.didKey2[0].public_key)

      const didDoc2 = await DIDDoc.Get(state.data.did)
      console.log('DID Doc2 : ', JSON.stringify(didDoc2.data, null, 2))
    } catch (err) {
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Reset key - Send request with incorrect did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const dummyDid = `did:idin:${uuidv4()}`
      const resetKey = await Recoverer.ResetKey(dummyDid, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.did_address.code).toBe(ERROR.DID_ADDRESS.CODE)
      expect(err.response.data.fields.did_address.message).toBe(ERROR.DID_ADDRESS.MESSAGE)
    }
  })

  test('Reset key - Send request with incorrect request_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const dummyDid = `did:idin:${uuidv4()}`
      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        dummyDid,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019,
        state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response.data)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.request_did.code).toBe(ERROR.REQUEST_DID.CODE)
      expect(err.response.data.fields.request_did.message).toBe(ERROR.REQUEST_DID.MESSAGE)
    }
  })

  test('Reset key - Send request with incorrect signature', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.didKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.SIGNATURE.CODE)
      expect(err.response.data.message).toBe(INVALID.SIGNATURE.MESSAGE)
    }
  })

  test('Reset key - Send request with incorrect key_type', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,'key_type', state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['new_key.key_type'].code).toBe(INVALID.NEW_KEY_TYPE.CODE)
      expect(err.response.data.fields['new_key.key_type'].message).toBe(INVALID.NEW_KEY_TYPE.MESSAGE)
    }
  })

  test('Reset key - Send request with incorrect controller', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const dummyDid = `did:idin:${uuidv4()}`
      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,dummyDid,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data,null,2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['new_key.controller'].code).toBe(ERROR.CONTROLLER.CODE)
      expect(err.response.data.fields['new_key.controller'].message).toBe(ERROR.CONTROLLER.MESSAGE)
    }
  })

  test('Reset key - Send request with incorrect nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const dummyNonce = uuidv4()
      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, dummyNonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.nonce.code).toBe(ERROR.NONCE.CODE)
      expect(err.response.data.fields.nonce.message).toBe(ERROR.NONCE.MESSAGE)
    }
  })

  test('Reset key - Send request without did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey('', state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.did_address.code).toBe(ERR_REQUIRE.DID_ADDRESS.CODE)
      expect(err.response.data.fields.did_address.message).toBe(ERR_REQUIRE.DID_ADDRESS.MESSAGE)
    }
  })

  test('Reset key - Send request without request_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        '',state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data,null, 2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.request_did.code).toBe(ERR_REQUIRE.REQUEST_DID.CODE)
      expect(err.response.data.fields.request_did.message).toBe(ERR_REQUIRE.REQUEST_DID.MESSAGE)
    }
  })

  test('Reset key - Send request without key_type', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,'', state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response.data)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['new_key.key_type'].code).toBe(INVALID.NEW_KEY_TYPE.CODE)
      expect(err.response.data.fields['new_key.key_type'].message).toBe(INVALID.NEW_KEY_TYPE.MESSAGE)
    }
  })

  test('Reset key - Send request without controller', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,'',KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['new_key.controller'].code).toBe(INVALID.CONTROLLER.CODE)
      expect(err.response.data.fields['new_key.controller'].message).toBe(INVALID.CONTROLLER.MESSAGE)
    }
  })

  test('Reset key - Send request without nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, '')
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data,null, 2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.nonce.code).toBe(ERR_REQUIRE.NONCE.CODE)
      expect(err.response.data.fields.nonce.message).toBe(ERR_REQUIRE.NONCE.MESSAGE)
    }
  })

  test('Reset key - Reset to someone that non recoverer', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data,null,2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.request_did.code).toBe(ERR_NOT_MATCH.REQUEST_DID.CODE)
      expect(err.response.data.fields.request_did.message).toBe(ERR_NOT_MATCH.REQUEST_DID.MESSAGE)
    }
  })

  // test('Reset key - Reset to same key', async () => {
  //   try {
  //     const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
  //     console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
  //     expect(didRegister.request.status).toEqual(201)
  //     state.data.did = didRegister.request.data.id
  //     state.didKey1 = didRegister.didKey1
  //     state.didKey2 = didRegister.didKey2
  //
  //     const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
  //     console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
  //     expect(recovererRegister.request.status).toEqual(201)
  //     state.recoverer.did = recovererRegister.request.data.id
  //     state.recovererKey1 = recovererRegister.didKey1
  //
  //     const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
  //     console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
  //     expect(didRegister.request.status).toEqual(201)
  //     state.controller.did = controllerRegister.request.data.id
  //     state.controllerKey1 = controllerRegister.didKey1
  //
  //     const nonce = await DIDNonce.getDIDNonce(state.data.did)
  //     console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
  //     expect(nonce.status).toEqual(200)
  //     state.data.nonce = nonce.data.nonce
  //
  //     const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
  //     console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
  //     expect(recovererNonce.status).toEqual(200)
  //     state.recoverer.nonce = recovererNonce.data.nonce
  //
  //     const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
  //     console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
  //     expect(addRecoverer.status).toEqual(201)
  //
  //     const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
  //       state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
  //     console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
  //     expect(resetKey.request.status).toEqual(400)
  //   } catch (err) {
  //     console.log(err.response)
  //     expect(err).toBeTruthy()
  //     expect(err.response.status).toEqual(400)
  //   }
  // })

  test('Reset key - Reset & use new key after reset', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      state.didKey2 = resetKey.newKey
      expect(resetKey.request.status).toEqual(200)

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister = await VC.Register(state.data.did, state.didKey2, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Reset key - Should cannot use old key after reset', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(recovererRegister.request.status).toEqual(201)
      state.recoverer.did = recovererRegister.request.data.id
      state.recovererKey1 = recovererRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controllerKey1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const recovererNonce = await DIDNonce.getDIDNonce(state.recoverer.did)
      console.log('Recoverer Nonce : ', JSON.stringify(recovererNonce.data, null, 2))
      expect(recovererNonce.status).toEqual(200)
      state.recoverer.nonce = recovererNonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)

      const resetKey = await Recoverer.ResetKey(state.recoverer.did, state.recovererKey1,
        state.data.did,state.controller.did,KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.recoverer.nonce)
      console.log('Reset key: ',JSON.stringify(resetKey.request.data,null, 2))
      expect(resetKey.request.status).toEqual(200)

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
    }
  })
})
