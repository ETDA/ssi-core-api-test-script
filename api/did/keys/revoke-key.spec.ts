import { DID } from '../register/did-register'
import { DIDNonce } from '../register/nonce'
import { ERR_REQUIRE, ERROR, INVALID, KEY_TYPE } from '../../consts'
import { DIDKey } from './add-key'
import { DIDKeyRevoke } from './revoke-key'
import { v4 as uuidv4 } from 'uuid'

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  didKey4: [],
  data: {
    did: '',
    did2: '',
    nonce: '',
    nonce2: ''
  },
  controller:{
    did:''
  }
})

describe('Revoke key', () => {
  jest.setTimeout(60000)

  const state = getInitState()

  beforeEach(() => {
    state.didKey1 = []
    state.didKey2 = []
    state.didKey3 = []
    state.didKey4 = []
  })

  test('Revoke key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).toEqual(200)
      expect(revokeKey.data.id).toBe(state.data.did)
      expect(revokeKey.data.verificationMethod[0].id).not.toBe(state.keyId)
      expect(revokeKey.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Revoke key - Send request with incorrect did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const dummyDid = `did:idin:${uuidv4()}`
      const revokeKey = await DIDKeyRevoke.RevokeKey(dummyDid, state.didKey1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
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

  test('Revoke key - Send request with incorrect key_id', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const dummyKeyId = uuidv4()
      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, dummyKeyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.key_id.code).toBe(ERROR.KEY_ID.CODE)
      expect(err.response.data.fields.key_id.message).toBe(ERROR.KEY_ID.MESSAGE)
    }
  })

  test('Revoke key - Send request with incorrect nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
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

  test('Revoke key - Send request without did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey('', state.didKey1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
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

  test('Revoke key - Send request without key_id', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, '', state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.key_id.code).toBe(ERR_REQUIRE.KEY_ID.CODE)
      expect(err.response.data.fields.key_id.message).toBe(ERR_REQUIRE.KEY_ID.MESSAGE)
    }
  })

  test('Revoke key - Send request without nonce', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey1, state.keyId, '')
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
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

  test('Revoke key - Key should cannot revoke themself', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did, state.didKey2, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
    }
  })

  test('Revoke key - Key should cannot revoke by the other', async () => {
    try {
      const didRegister1 = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register1: ', JSON.stringify(didRegister1.request.data, null, 2))
      expect(didRegister1.request.status).toEqual(201)
      state.data.did = didRegister1.request.data.id
      state.didKey1 = didRegister1.didKey1
      state.didKey2 = didRegister1.didKey2

      const didRegister2 = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register2: ', JSON.stringify(didRegister2.request.data, null, 2))
      expect(didRegister2.request.status).toEqual(201)
      state.data.did2 = didRegister2.request.data.id
      state.didKey3 = didRegister2.didKey1
      state.didKey4 = didRegister2.didKey2

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1, KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did2)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce2 = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.data.did2, state.didKey3, state.keyId, state.data.nonce2)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).not.toEqual(200)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data, null, 2))
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.key_id.code).toBe(ERROR.KEY_ID.CODE)
      expect(err.response.data.fields.key_id.message).toBe(ERROR.KEY_ID.MESSAGE)
    }
  })

  test('Revoke key by controller', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const controllerRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(controllerRegister.request.data, null, 2))
      expect(controllerRegister.request.status).toEqual(201)
      state.controller.did = controllerRegister.request.data.id
      state.controller1 = controllerRegister.didKey1

      const nonce = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce : ', JSON.stringify(nonce.data, null, 2))
      expect(nonce.status).toEqual(200)
      state.data.nonce = nonce.data.nonce

      // @ts-ignore
      const addKey = await DIDKey.AddKey(state.data.did, state.didKey1,
        KEY_TYPE.EcdsaSecp256r1VerificationKey2019, state.data.nonce,state.controller.did)
      console.log('Add key: ', JSON.stringify(addKey.request.data, null, 2))
      expect(addKey.request.status).toEqual(201)
      state.keyId = addKey.request.data.verificationMethod[1].id

      const nonce2 = await DIDNonce.getDIDNonce(state.controller.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const revokeKey = await DIDKeyRevoke.RevokeKey(state.controller.did, state.controller1, state.keyId, state.data.nonce)
      console.log('Key revoke : ', JSON.stringify(revokeKey.data, null, 2))
      expect(revokeKey.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
    }
  })
})
