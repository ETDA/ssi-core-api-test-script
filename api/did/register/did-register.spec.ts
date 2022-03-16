import { ERR_REQUIRE, INVALID, KEY_TYPE } from '../../consts'
import { DID } from './did-register'

let getInitState: any = () => ({
  didKey1: []
  })

describe('DID Register', () => {

  const state = getInitState()

  beforeEach(() => {
    state.didKey1 = []

  })

  test('Register DID', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      state.didKey1 = didRegister.didKey1
      expect(didRegister.request.status).toEqual(201)
      expect(didRegister.request.data.id).toContain('did:idin:')
      expect(didRegister.request.data.verificationMethod[0].publicKeyPem).toBe(state.didKey1[0].public_key)
      expect(didRegister.request.data.verificationMethod[0].type).toBe(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      expect(didRegister.request.data.verificationMethod[0].controller).toContain('did:idin:')
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Register DID - Send request with incorrect public_key format', async () => {
    try {
      const didRegister = await DID.RegisterWithIncorrectKey(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister, null, 2))
      expect(didRegister.request.status).not.toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.SIGNATURE.CODE)
      expect(err.response.data.message).toBe(INVALID.SIGNATURE.MESSAGE)
    }
  })

  test('Register DID - Send request with incorrect key_type', async () => {
    try {
      const didRegister = await DID.Register('key_type')
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.key_type.code).toBe(INVALID.KEY_TYPE.CODE)
      expect(err.response.data.fields.key_type.message).toBe(INVALID.KEY_TYPE.MESSAGE)
    }
  })

  test('Register DID - Send request without public_key', async () => {
    try {
      const didRegister = await DID.RegisterWithoutKey(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister, null, 2))
      expect(didRegister.request.status).not.toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
    }
  })

  test('Register DID - Send request without key_type', async () => {
    try {
      const didRegister = await DID.Register('')
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.key_type.code).toBe(ERR_REQUIRE.KEY_TYPE.CODE)
      expect(err.response.data.fields.key_type.message).toBe(ERR_REQUIRE.KEY_TYPE.MESSAGE)
    }
  })
})
