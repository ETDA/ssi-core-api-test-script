import { DID } from '../../did/register/did-register'
import { ERR_REQUIRE, ERROR, INVALID, KEY_TYPE, VC_STATUS } from '../../consts'
import { DIDNonce } from '../../did/register/nonce'
import { VC } from '../register/vc'
import { VCStatus } from './status'
import { v4 as uuidv4 } from 'uuid'
import { Gen } from '../../verification/vc-vp-verify/gen-vc-vp'

const faker = require('faker')

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  didKey4: [],
  issuanceDate: '',
  data: {
    did: '',
    nonce: '',
    did2: '',
    nonce2: ''
  },
  issuer: {
    did: ''
  },
  didId: '',
  vc: {
    version: '',
    version2: ''
  }
})
describe('Add VC Status', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() => {
    state.didKey1 = []
    state.issuerKey1 = []
  })

  test('Add VC Status to active', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1
      state.keyId = issRegister.request.data.verificationMethod[0].id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.issuer.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)
      expect(vcAddStatus.data.cid).toBe(state.cid)
      expect(vcAddStatus.data.did_address).toBe(state.issuer.did)
      expect(vcAddStatus.data.status).toBe(VC_STATUS.ACTIVE)
      expect(vcAddStatus.data.vc_hash).toBe(jwtVc)

      const vcGetStatus2 = await VCStatus.Get(state.cid)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      expect(vcGetStatus2.data.cid).toBe(state.cid)
      expect(vcGetStatus2.data.status).toBe(VC_STATUS.ACTIVE)
      expect(vcGetStatus2.data.did_address).toBe(state.issuer.did)
      expect(vcGetStatus2.data.revoked_at).toBe(null)
      // expect(vcGetStatus2.data.expired_at).toBe(null)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Add VC Status to revoke', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.REVOKE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
    } catch (err) {
      console.log(err.response.data)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.status.code).toBe(INVALID.INVALID_ADD_VC_TYPE.CODE)
      expect(err.response.data.fields.status.message).toBe(INVALID.INVALID_ADD_VC_TYPE.MESSAGE)
    }
  })

  test('Add VC Status - Send request with incorrect did_address', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const dummyDid = `did:idin:${uuidv4()}`
      const vcAddStatus = await VCStatus.Add(state.cid, dummyDid, VC_STATUS.REVOKE, state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
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

  test('Add VC Status - Send request with incorrect status', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, 'status',
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.status.code).toBe(INVALID.INVALID_ADD_VC_TYPE.CODE)
      expect(err.response.data.fields.status.message).toBe(INVALID.INVALID_ADD_VC_TYPE.MESSAGE)
    }
  })

  test('Add VC Status - Send request with incorrect nonce', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.REVOKE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
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

  test('Add VC Status - Send request with incorrect cid', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const dummyCid = uuidv4()
      const vcAddStatus = await VCStatus.Add(dummyCid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.cid.code).toBe(ERROR.CID.CODE)
      expect(err.response.data.fields.cid.message).toBe(ERROR.CID.MESSAGE)
    }
  })

  test('Add VC Status - Send request without did_address', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, '', VC_STATUS.REVOKE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
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

  test('Add VC Status - Send request without status', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, '',
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.status.code).toBe(ERR_REQUIRE.VC_STATUS.CODE)
      expect(err.response.data.fields.status.message).toBe(ERR_REQUIRE.VC_STATUS.MESSAGE)
    }
  })

  test('Add VC Status - Send request without nonce', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const vcGetStatus1 = await VCStatus.Get(state.cid)
      console.log('Get VC Status1: ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      expect(vcGetStatus1.data.status).toBe(null)
      state.issuanceDate = vcGetStatus1.data.created_at
      // state.issuanceDate = ''

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.REVOKE,
        state.issuerKey1, '', jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
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

  test('Add VC Status - Send request without cid', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add('', state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields.cid.code).toBe(ERR_REQUIRE.CID.CODE)
      expect(err.response.data.fields.cid.message).toBe(ERR_REQUIRE.CID.MESSAGE)
    }
  })

  test('Add VC Status - Send request by other person', async () => {
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

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did2)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce2 = nonce2.data.nonce

      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, schemaType, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did2, VC_STATUS.ACTIVE,
        state.didKey3, state.data.nonce2, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(404)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(404)
    }
  })
})
