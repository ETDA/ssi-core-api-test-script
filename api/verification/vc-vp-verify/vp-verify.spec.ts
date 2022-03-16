import { DID } from '../../did/register/did-register'
import { ERR_REQUIRE, INVALID, KEY_TYPE, VC_STATUS } from '../../consts'
import { DIDNonce } from '../../did/register/nonce'
import { Verify } from './verify'
import { VC } from '../../vc/register/vc'
import { v4 as uuidv4 } from 'uuid'
import { DIDDoc } from '../../did/docs/doc'
import { VCStatus } from '../../vc/status/status'
import { Gen } from './gen-vc-vp'
import { EXAMPLE_VP } from './example-vc-vp'
import { SchemaBody } from '../schema-body'
import { Schema } from '../schema'

const faker = require('faker')

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  issuerKey1: [],
  data: {
    did: '',
    nonce: ''
  },
  issuer: {
    did: ''
  },
  audience: {
    did: ''
  },
  didId: '',
  cid: ''
})

describe('VP Verify', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() => {
    state.didKey1 = []
    state.issuerKey1 = []
  })

  test('Verify VP', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.id).toBe(state.cid)
      expect(vpVerify.data.audience).toBe(state.audience.did)
      expect(vpVerify.data.issuer).toBe(state.data.did)
      expect(vpVerify.data.expiration_date).toBe(null)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
      expect(vpVerify.data.vc[0].cid).toBe(state.cid)
      expect(vpVerify.data.vc[0].status).toBe(VC_STATUS.ACTIVE)
      expect(vpVerify.data.vc[0].type[1]).toBe(schemaType)
      expect(vpVerify.data.vc[0].issuer).toBe(state.data.did)
      expect(vpVerify.data.vc[0].holder).toBe(state.data.did)
    } catch (err) {
      console.log(err.response)
      console.log(JSON.stringify(err.response.data, null, 2))
      expect(err).not.toBeTruthy()
    }
  })

  test('Verify VP - Send request with incorrect did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyDid = `did:idin:${uuidv4()}`
      const jwtVp = await Gen.VP(jwtVc, state.cid, dummyDid, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.iss'].code).toBe(INVALID.CLAIMS_ISS.CODE)
      expect(err.response.data.fields['Claims.iss'].message).toBe(INVALID.CLAIMS_ISS.MESSAGE)
    }
  })

  test('Verify VP - Send request with incorrect cid', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyCid = uuidv4()
      const jwtVp = await Gen.VP(jwtVc, dummyCid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.jti'].code).toBe(INVALID.CLAIMS_JTI.CODE)
      expect(err.response.data.fields['Claims.jti'].message).toBe(INVALID.CLAIMS_JTI.MESSAGE)
    }
  })

  test('Verify VP - Send request with incorrect VP type', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyVCType = schemaType + 'unknown_type'

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, dummyVCType, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.vp.type'].code).toBe(INVALID.CLAIMS_VP_TYPE.CODE)
      expect(err.response.data.fields['Claims.vp.type'].message).toBe(INVALID.CLAIMS_VP_TYPE.MESSAGE)
    }
  })

  test('Verify VP - Send request with incorrect issuer_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyDid = `did:idin:${uuidv4()}`

      const jwtVp = await Gen.VP(jwtVc, state.cid, dummyDid, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.iss'].code).toBe(INVALID.CLAIMS_ISS.CODE)
      expect(err.response.data.fields['Claims.iss'].message).toBe(INVALID.CLAIMS_ISS.MESSAGE)
    }
  })

  test('Verify VP - Send request with incorrect audience_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyDid = `did:idin:${uuidv4()}`

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, dummyDid, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.aud'].code).toBe(INVALID.CLAIMS_AUD.CODE)
      expect(err.response.data.fields['Claims.aud'].message).toBe(INVALID.CLAIMS_AUD.MESSAGE)
    }
  })

  test('Verify VP - send request with incorrect issuer\'s key_id in JWT header', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const dummyKeyId = uuidv4()

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        dummyKeyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Header.kid'].code).toBe(INVALID.HEADER_KID.CODE)
      expect(err.response.data.fields['Header.kid'].message).toBe(INVALID.HEADER_KID.MESSAGE)
    }
  })

  test('Verify VP - Send request without did_address', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, '', state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.iss'].code).toBe(ERR_REQUIRE.CLAIMS_ISS.CODE)
      expect(err.response.data.fields['Claims.iss'].message).toBe(ERR_REQUIRE.CLAIMS_ISS.MESSAGE)
    }
  })

  test('Verify VP - Send request without cid', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, '', state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.jti'].code).toBe(ERR_REQUIRE.CLAIMS_JTI.CODE)
      expect(err.response.data.fields['Claims.jti'].message).toBe(ERR_REQUIRE.CLAIMS_JTI.MESSAGE)
    }
  })

  test('Verify VP - Send request without VP type', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, '', state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.vp.type[0]'].code).toBe(ERR_REQUIRE.CLAIMS_VP_TYPE.CODE)
      expect(err.response.data.fields['Claims.vp.type[0]'].message).toBe(ERR_REQUIRE.CLAIMS_VP_TYPE.MESSAGE)
      expect(err.response.data.fields['Claims.vp.type'].code).toBe(INVALID.CLAIMS_VP_TYPE.CODE)
      expect(err.response.data.fields['Claims.vp.type'].message).toBe(INVALID.CLAIMS_VP_TYPE.MESSAGE)
    }
  })

  test('Verify VP - send request without issuer_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, '', state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.iss'].code).toBe(ERR_REQUIRE.CLAIMS_ISS.CODE)
      expect(err.response.data.fields['Claims.iss'].message).toBe(ERR_REQUIRE.CLAIMS_ISS.MESSAGE)
    }
  })

  test('Verify VP - send request without audience_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, '', state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Claims.aud'].code).toBe(ERR_REQUIRE.CLAIMS_AUD.CODE)
      expect(err.response.data.fields['Claims.aud'].message).toBe(ERR_REQUIRE.CLAIMS_AUD.MESSAGE)
    }
  })

  test('Verify VP - send request without issuer\'s key_id in JWT header', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        '', state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.PARAMS.CODE)
      expect(err.response.data.message).toBe(INVALID.PARAMS.MESSAGE)
      expect(err.response.data.fields['Header.kid'].code).toBe(ERR_REQUIRE.HEADER_KID.CODE)
      expect(err.response.data.fields['Header.kid'].message).toBe(ERR_REQUIRE.HEADER_KID.MESSAGE)
    }
  })

  test('Verify VP - send request with incorrect private_key', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1
      state.didKey2 = didRegister.didKey2

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey2,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(400)
    } catch (err) {
      console.log(err.response)
      expect(err).toBeTruthy()
      expect(err.response.status).toEqual(400)
      expect(err.response.data.code).toBe(INVALID.SIGNATURE.CODE)
      expect(err.response.data.message).toBe(INVALID.SIGNATURE.MESSAGE)
    }
  })

  test('Verify VP - send request by issuer_did', async () => {
    try {
      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const didDocHistory1 = await DIDDoc.GetHistory(state.data.did)
      console.log('DID Doc History1: ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const vcRegister = await VC.Register(state.data.did, state.didKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `'sDocument` + '_Type'
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = 'object'
      const schemaBodyProperties = {
        'example_string': {
          'type': 'string'
        }
      }
      const schemaRequired = ['example_string']
      const additional = false

      const schemaBody = SchemaBody.Message(schemaName, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id

      const nonce3 = await DIDNonce.getDIDNonce(state.data.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = { 'example_string': 'Tony' }
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.data.did, VC_STATUS.ACTIVE,
        state.didKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.data.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
