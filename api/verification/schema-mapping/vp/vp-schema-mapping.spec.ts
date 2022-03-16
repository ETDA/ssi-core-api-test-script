import { SCHEMA_BODY_PROPERTIES } from '../schema-body-data'
import { DID } from '../../../did/register/did-register'
import { KEY_TYPE, VC_STATUS } from '../../../consts'
import { DIDNonce } from '../../../did/register/nonce'
import { VC } from '../../../vc/register/vc'
import { DIDDoc } from '../../../did/docs/doc'
import { VCStatus } from '../../../vc/status/status'
import { SUBJECT } from '../schema-subject-data'
import { Gen } from '../../vc-vp-verify/gen-vc-vp'
import { Verify } from '../../vc-vp-verify/verify'
import { SchemaBody } from '../../schema-body'
import { Schema } from '../../schema'
import { EXAMPLE_VP } from '../../vc-vp-verify/example-vc-vp'

const faker = require('faker')

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  issuerKey1: [],
  schemaId: '',
  issuanceDate: '',
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

describe('VC Schema Mapping', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() => {
    state.didKey1 = []
  })

  test('VP verify - Send request with compatible data with created schema', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_001.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_001.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_001.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with incompatible with created schema', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_001.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_001.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_001.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001_WRONG_TYPE
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with additional field when additionalProperties = true', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_001.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_001.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_001.REQUIRED
      const additional = true

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001_ADDITIONAL
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with additional field when additionalProperties = false', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_001.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_001.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_001.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001_ADDITIONAL
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with additional field in object field when additionalProperties = true', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional = true

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_002_ADDITIONAL
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with additional field in object field when additionalProperties = false', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_003.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_003.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_003.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_002_ADDITIONAL
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request with required field in object field', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_002
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request without required field', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_002_WITHOUT_REQUIRED
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('VP verify - Send request without required field in object field', async () => {
    try {
      const issRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Issuer Register: ', JSON.stringify(issRegister.request.data, null, 2))
      expect(issRegister.request.status).toEqual(201)
      state.issuer.did = issRegister.request.data.id
      state.issuerKey1 = issRegister.didKey1

      const didRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('DID Register: ', JSON.stringify(didRegister.request.data, null, 2))
      expect(didRegister.request.status).toEqual(201)
      state.data.did = didRegister.request.data.id
      state.didKey1 = didRegister.didKey1

      const audRegister = await DID.Register(KEY_TYPE.EcdsaSecp256r1VerificationKey2019)
      console.log('Audience Register: ', JSON.stringify(audRegister.request.data, null, 2))
      expect(audRegister.request.status).toEqual(201)
      state.audience.did = audRegister.request.data.id

      const nonce1 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 1: ', JSON.stringify(nonce1.data, null, 2))
      expect(nonce1.status).toEqual(200)
      state.data.nonce = nonce1.data.nonce

      const vcRegister = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register: ', JSON.stringify(vcRegister.data, null, 2))
      expect(vcRegister.status).toEqual(201)
      state.cid = vcRegister.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const schemaName = faker.name.title()
      const schemaType = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc = faker.name.jobTitle()
      const schemaBodyType = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional = false

      const schemaBody = SchemaBody.Message(schemaType, schemabodyDesc, schemaBodyType, schemaBodyProperties, schemaRequired, additional)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema = await Schema.Create(schemaName, schemaType, schemaBody)
      console.log('Create Schema: ', JSON.stringify(createSchema.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId = createSchema.data.id
      state.schemaName = createSchema.data.schema_name

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data, null, 2))
      expect(vcGetStatus.status).toEqual(200)
      state.issuanceDate = vcGetStatus.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_002_WITHOUT_REQUIRED_IN_OBJ
      const jwtVc = await Gen.VC(state.cid, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId, state.schemaName, schemaType, state.issuanceDate, vcSubject)

      const vcAddStatus = await VCStatus.Add(state.cid, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc)
      console.log('Add VC Status: ', JSON.stringify(vcAddStatus.data, null, 2))
      expect(vcAddStatus.status).toEqual(200)

      const jwtVp = await Gen.VP(jwtVc, state.cid, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, EXAMPLE_VP.TYPE, state.issuanceDate)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
