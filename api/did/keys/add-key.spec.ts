import { DID } from '../register/did-register'
import { ERR_REQUIRE, ERROR, INVALID, KEY_TYPE } from '../../consts'
import { DIDKey } from './add-key'
import { DIDNonce } from '../register/nonce'
import { v4 as uuidv4 } from 'uuid'
import { DIDKeyRevoke } from './revoke-key'
import { DIDDoc } from '../docs/doc'

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  controller1: [],
  data: {
    did: '',
    nonce: ''
  },
  controller:{
    did:''
  },
  didId: ''
})

describe('DID Add key', () => {

  const state = getInitState()
  jest.setTimeout(60000)

  beforeEach(() => {
    state.didKey1 = []
    state.didKey2 = []
    state.didKey3 = []
    state.controller1 = []
  })

  test('Add key', async () => {
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

  test('Add key - Send request with incorrect did_address', async () => {
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

      const dummyDid = `did:idin:${uuidv4()}`
      // @ts-ignore
      const addKey = await DIDKey.AddKey(dummyDid, state.didKey1, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey, null, 2))
      expect(addKey.request.status).toEqual(400)
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

  test('Add key - Send request with incorrect new_key format', async () => {
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
      const addKey = await DIDKey.AddKeyWithIncorrectKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response.data)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.new_key.code).toBe(INVALID.SIGNATURE.CODE)
      expect(err.response.data.fields.new_key.message).toBe(INVALID.SIGNATURE.MESSAGE)
    }
  })

  test('Add key - Send request with incorrect nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const dummyNonce = uuidv4()
      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, dummyNonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
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

  test('Add key - Send request without did_address', async () => {
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

      // @ts-ignore
      const addKey = await DIDKey.AddKey('', state.didKey1, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
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

  test('Add key - Send request without new_key', async () => {
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
      const addKey = await DIDKey.AddKeyWithoutKey(state.data.did, state.didKey1,
        '', state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['new_key.key_type'].code).toBe(INVALID.NEW_KEY_TYPE.CODE)
      expect(err.response.data.fields['new_key.key_type'].message).toBe(INVALID.NEW_KEY_TYPE.MESSAGE)
      expect(err.response.data.fields['new_key.public_key'].code).toBe(ERR_REQUIRE.NEW_KEY.CODE)
      expect(err.response.data.fields['new_key.public_key'].message).toBe(ERR_REQUIRE.NEW_KEY.MESSAGE)
      expect(err.response.data.fields['new_key.signature'].code).toBe(ERR_REQUIRE.NEW_KEY_SIGNATURE.CODE)
      expect(err.response.data.fields['new_key.signature'].message).toBe(ERR_REQUIRE.NEW_KEY_SIGNATURE.MESSAGE)
    }
  })

  test('Add key - Send request without nonce', async () => {
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

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, '')
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
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

  test('Add key again by using new key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey1 = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 1: ', JSON.stringify(addKey1.request.data, null, 2))
      expect(addKey1.request.status).toEqual(201)
      state.didKey2 = addKey1.newKey

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      // @ts-ignore
      const addKey2 = await DIDKey.AddKey(state.data.did, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 2: ', JSON.stringify(addKey2.request.data, null, 2))
      state.didKey3 = addKey2.newKey
      expect(addKey2.request.status).toEqual(201)
      expect(addKey2.request.data.id).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
      expect(addKey2.request.data.verificationMethod[2].controller).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[2].publicKeyPem).toBe(state.didKey3[0].public_key)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add key again by using same key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2
      state.didKey3 = didRegister.didKey3

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey1 = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 1: ', JSON.stringify(addKey1.request.data, null, 2))
      expect(addKey1.request.status).toEqual(201)
      state.didKey2 = addKey1.newKey

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      // @ts-ignore
      const addKey2 = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 2: ', JSON.stringify(addKey2.request.data, null, 2))
      state.didKey3 = addKey2.newKey
      expect(addKey2.request.status).toEqual(201)
      expect(addKey2.request.data.id).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[1].controller).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)
      expect(addKey2.request.data.verificationMethod[2].controller).toBe(state.data.did)
      expect(addKey2.request.data.verificationMethod[2].publicKeyPem).toBe(state.didKey3[0].public_key)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add key again by revoked key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey1 = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 1: ', JSON.stringify(addKey1.request.data, null, 2))
      expect(addKey1.request.status).toEqual(201)
      state.keyId = addKey1.request.data.verificationMethod[1].id
      state.didKey2 = addKey1.newKey

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).toEqual(200)

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      // @ts-ignore
      const addKey2 = await DIDKey.AddKey(state.data.did, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 2: ', JSON.stringify(addKey2.request.data, null, 2))
      state.didKey3 = addKey2.newKey
      expect(addKey2.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.SIGNATURE.CODE)
      expect(err.response.data.message).toBe(INVALID.SIGNATURE.MESSAGE)
    }
  })

  test('Add key again by the same new_key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey1 = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 1: ', JSON.stringify(addKey1.request.data, null, 2))
      expect(addKey1.request.status).toEqual(201)
      state.didKey2 = addKey1.newKey

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      // @ts-ignore
      const addKey2 = await DIDKey.AddKeyWithSpecificKey(state.data.did, state.didKey1, state.didKey2,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key 2: ', JSON.stringify(addKey2.request.data, null, 2))
      expect(addKey2.request.status).toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add key to controller', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(controllerRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controller1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce,state.controller.did)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      state.didKey2 = addKey.newKey
      expect(addKey.request.status).toEqual(201)
      expect(addKey.request.data.id).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[0].controller).toBe(state.data.did)
      expect(addKey.request.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
      expect(addKey.request.data.verificationMethod[1].controller).toBe(state.controller.did)
      expect(addKey.request.data.verificationMethod[1].publicKeyPem).toBe(state.didKey2[0].public_key)

      const didDocHistory = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History: ', JSON.stringify(didDocHistory.data, null, 2))
      expect(didDocHistory.status).toEqual(200)
      expect(didDocHistory.data.did_document[1].verificationMethod[0].controller).toBe(state.data.did)
      expect(didDocHistory.data.did_document[1].verificationMethod[1].controller).toBe(state.controller.did)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add key to controller with unknown controller_did', async () => {
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

      const dummyDid = `did:idin:${uuidv4()}`
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce,dummyDid)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
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

  test('Add key to controller without controller_did', async () => {
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

      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce,'')
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(400)
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
})
