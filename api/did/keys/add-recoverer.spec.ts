import { DID } from '../register/did-register'
import { ERR_REQUIRE, ERROR, INVALID, KEY_TYPE } from '../../consts'
import { DIDNonce } from '../register/nonce'
import { Recoverer } from './recoverer'
import { v4 as uuidv4 } from 'uuid'
// import { Mobile } from './mobile'

let getInitState: any = () => ({
  didKey1: [],
  didKey2: [],
  didKey3: [],
  recovererKey1: [],
  data: {
    did: '',
    nonce: ''
  },
  recoverer: {
    did: ''
  }
})

describe('Recoverer', () => {

  const state = getInitState()
  jest.setTimeout(60000)

  beforeEach(() => {
    state.didKey1 = []
    state.didKey2 = []
    state.didKey3 = []
    state.recovererKey1 = []
  })

  test('Add recoverer', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)
      expect(addRecoverer.data.id).toBe(state.data.did)
      expect(addRecoverer.data.controller).toBe(state.data.did)
      expect(addRecoverer.data.verificationMethod[0].controller).toBe(state.data.did)
      expect(addRecoverer.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)

    } catch (err) {
      console.log(err.response.data)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add recoverer - Send request with incorrect did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const dummyDid = `did:idin:${uuidv4()}`
      const addRecoverer = await Recoverer.Add(dummyDid, state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(400)
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

  test('Add recoverer - Send request with incorrect recoverer', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const dummyDid = `did:idin:${uuidv4()}`
      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, dummyDid, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.recoverer.code).toBe(ERROR.RECOVERER.CODE)
      expect(err.response.data.fields.recoverer.message).toBe(ERROR.RECOVERER.MESSAGE)
    }
  })

  test('Add recoverer - Send request with incorrect nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const dummyNonce = uuidv4()
      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, dummyNonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(400)
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

  test('Add recoverer - Send request without did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add('', state.didKey1, state.recoverer.did, state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(400)
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

  test('Add recoverer - Send request without recoverer', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, '', state.data.nonce)
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data,null, 2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.recoverer.code).toBe(ERR_REQUIRE.RECOVERER.CODE)
      expect(err.response.data.fields.recoverer.message).toBe(ERR_REQUIRE.RECOVERER.MESSAGE)
    }
  })

  test('Add recoverer - Send request without nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      // const getRecovererDid = await Mobile.GetRecovererDid()
      // console.log('GET Recoverer DID: ', JSON.stringify(getRecovererDid.data, null, 2))
      // state.recoverer.did = getRecovererDid.data.did_address
      const recovererRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Recoverer Register: ', JSON.stringify(recovererRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.recoverer.did = didRegister.request.data.id

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addRecoverer = await Recoverer.Add(state.data.did, state.didKey1, state.recoverer.did, '')
      console.log('Add recoverer: ', JSON.stringify(addRecoverer.data, null, 2))
      expect(addRecoverer.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.nonce.code).toBe(ERR_REQUIRE.NONCE.CODE)
      expect(err.response.data.fields.nonce.message).toBe(ERR_REQUIRE.NONCE.MESSAGE)
    }
  })
})
