import { DID } from '../../did/register/did-register'
import { KEY_TYPE, VC_STATUS } from '../../consts'
import { DIDNonce } from '../../did/register/nonce'
import { VC } from '../../vc/register/vc'
import { SCHEMA_BODY_PROPERTIES } from '../schema-mapping/schema-body-data'
import { DIDDoc } from '../../did/docs/doc'
import { VCStatus } from '../../vc/status/status'
import { Gen } from '../vc-vp-verify/gen-vc-vp'
import { Verify } from '../vc-vp-verify/verify'
import { SUBJECT } from '../schema-mapping/schema-subject-data'
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
  cid1: '',
  cid2: '',
  schemaId1: '',
  schemaId2: '',
  issuanceDate1: '',
  issuanceDate2: ''
})

describe('VP Verify with more than 1 VC', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() => {
    state.didKey1 = []
  })

  test('Send request by correct 2 VCs data with the same schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate2, vcSubject)
      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, schemaType, state.issuanceDate1)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
      expect(vpVerify.data.vc[1].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Send request by incorrect 2 VCs data type with the same schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject = SUBJECT.SUBJECT_FOR_SCHEMA_001_WRONG_TYPE

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate2, vcSubject)

      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId, schemaType, state.issuanceDate1)
      console.log('vp_jwt: ', jwtVp)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
      expect(vpVerify.data.vc[1].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Send request by correct 2 VCs data with difference schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const schemaName2 = faker.name.title()
      const schemaType2 = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc2 = faker.name.jobTitle()
      const schemaBodyType2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional2 = false

      const schemaBody2 = SchemaBody.Message(schemaType2, schemabodyDesc2, schemaBodyType2, schemaBodyProperties2, schemaRequired2, additional2)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema2 = await Schema.Create(schemaName2, schemaType2, schemaBody2)
      console.log('Create Schema2: ', JSON.stringify(createSchema2.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId2 = createSchema2.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject1 = SUBJECT.SUBJECT_FOR_SCHEMA_001
      const vcSubject2 = SUBJECT.SUBJECT_FOR_SCHEMA_002

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject1)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId2, schemaName2, schemaType2, state.issuanceDate2, vcSubject2)

      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce6 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 6: ', JSON.stringify(nonce6.data, null, 2))
      expect(nonce6.status).toEqual(200)
      state.data.nonce = nonce6.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId1, schemaType, state.issuanceDate1)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
      expect(vpVerify.data.vc[1].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Send request by incorrect 2 VCs data with difference schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const schemaName2 = faker.name.title()
      const schemaType2 = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc2 = faker.name.jobTitle()
      const schemaBodyType2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional2 = false

      const schemaBody2 = SchemaBody.Message(schemaType2, schemabodyDesc2, schemaBodyType2, schemaBodyProperties2, schemaRequired2, additional2)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema2 = await Schema.Create(schemaName2, schemaType2, schemaBody2)
      console.log('Create Schema : ', JSON.stringify(createSchema2.data, null, 2))
      // expect(createSchema2.status).toEqual(201)
      state.schemaId2 = createSchema2.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject1 = SUBJECT.SUBJECT_FOR_SCHEMA_001_WRONG_TYPE
      const vcSubject2 = SUBJECT.SUBJECT_FOR_SCHEMA_002_WRONG_TYPE

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject1)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId2, schemaName2, schemaType2, state.issuanceDate2, vcSubject2)

      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce6 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 6: ', JSON.stringify(nonce6.data, null, 2))
      expect(nonce6.status).toEqual(200)
      state.data.nonce = nonce6.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId1, schemaType, state.issuanceDate1)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
      expect(vpVerify.data.vc[1].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Send request by correct VC data and incorrect VC data with the same schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject1 = SUBJECT.SUBJECT_FOR_SCHEMA_001
      const vcSubject2 = SUBJECT.SUBJECT_FOR_SCHEMA_001_WRONG_TYPE

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject1)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate2, vcSubject2)

      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId1, schemaType, state.issuanceDate1)
      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(true)
      expect(vpVerify.data.vc[1].verification_result).toBe(false)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })

  test('Send request by correct VC data and incorrect VC data with difference schema', async () => {
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

      const vcRegister1 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register1: ', JSON.stringify(vcRegister1.data, null, 2))
      expect(vcRegister1.status).toEqual(201)
      state.cid1 = vcRegister1.data.cid

      const nonce2 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 2: ', JSON.stringify(nonce2.data, null, 2))
      expect(nonce2.status).toEqual(200)
      state.data.nonce = nonce2.data.nonce

      const vcRegister2 = await VC.Register(state.issuer.did, state.issuerKey1, state.data.nonce)
      console.log('VC Register2: ', JSON.stringify(vcRegister2.data, null, 2))
      expect(vcRegister2.status).toEqual(201)
      state.cid2 = vcRegister2.data.cid

      const nonce3 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 3: ', JSON.stringify(nonce3.data, null, 2))
      expect(nonce3.status).toEqual(200)
      state.data.nonce = nonce3.data.nonce

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
      state.schemaId1 = createSchema.data.id

      const nonce4 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 4: ', JSON.stringify(nonce4.data, null, 2))
      expect(nonce4.status).toEqual(200)
      state.data.nonce = nonce4.data.nonce

      const schemaName2 = faker.name.title()
      const schemaType2 = faker.name.firstName() + `Doc's_Type`
      const schemabodyDesc2 = faker.name.jobTitle()
      const schemaBodyType2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.TYPE
      const schemaBodyProperties2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.BODY
      const schemaRequired2 = SCHEMA_BODY_PROPERTIES.SCHEMA_002.REQUIRED
      const additional2 = false

      const schemaBody2 = SchemaBody.Message(schemaType2, schemabodyDesc2, schemaBodyType2, schemaBodyProperties2, schemaRequired2, additional2)
      console.log('SchemaBody: ', JSON.stringify(schemaBody, null, 2))

      const createSchema2 = await Schema.Create(schemaName2, schemaType2, schemaBody2)
      console.log('Create Schema2: ', JSON.stringify(createSchema2.data, null, 2))
      // expect(createSchema.status).toEqual(201)
      state.schemaId2 = createSchema2.data.id

      const didDocHistory1 = await DIDDoc.GetHistory(state.issuer.did)
      console.log('DID Doc History1 : ', JSON.stringify(didDocHistory1.data, null, 2))
      expect(didDocHistory1.status).toEqual(200)
      state.keyId = didDocHistory1.data.did_document[0].verificationMethod[0].id

      const nonce5 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 5: ', JSON.stringify(nonce5.data, null, 2))
      expect(nonce5.status).toEqual(200)
      state.data.nonce = nonce5.data.nonce

      const vcGetStatus1 = await VCStatus.Get(state.cid1)
      console.log('Get VC Status:1 ', JSON.stringify(vcGetStatus1.data, null, 2))
      expect(vcGetStatus1.status).toEqual(200)
      state.issuanceDate1 = vcGetStatus1.data.created_at

      const vcGetStatus2 = await VCStatus.Get(state.cid2)
      console.log('Get VC Status2: ', JSON.stringify(vcGetStatus2.data, null, 2))
      expect(vcGetStatus2.status).toEqual(200)
      state.issuanceDate2 = vcGetStatus2.data.created_at

      const vcSubject1 = SUBJECT.SUBJECT_FOR_SCHEMA_001_WRONG_TYPE
      const vcSubject2 = SUBJECT.SUBJECT_FOR_SCHEMA_002

      const jwtVc1 = await Gen.VC(state.cid1, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId1, schemaName, schemaType, state.issuanceDate1, vcSubject1)

      const jwtVc2 = await Gen.VC(state.cid2, state.data.did, state.issuer.did, state.issuerKey1,
        state.keyId, state.schemaId2, schemaName2, schemaType2, state.issuanceDate2, vcSubject2)

      const jwtVcs = [jwtVc1, jwtVc2]

      const vcAddStatus1 = await VCStatus.Add(state.cid1, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc1)
      console.log('Add VC Status1: ', JSON.stringify(vcAddStatus1.data, null, 2))
      expect(vcAddStatus1.status).toEqual(200)

      const nonce6 = await DIDNonce.getDIDNonce(state.issuer.did)
      console.log('Nonce 6: ', JSON.stringify(nonce6.data, null, 2))
      expect(nonce6.status).toEqual(200)
      state.data.nonce = nonce6.data.nonce

      const vcAddStatus2 = await VCStatus.Add(state.cid2, state.issuer.did, VC_STATUS.ACTIVE,
        state.issuerKey1, state.data.nonce, jwtVc2)
      console.log('Add VC Status2: ', JSON.stringify(vcAddStatus2.data, null, 2))
      expect(vcAddStatus2.status).toEqual(200)

      const jwtVp = await Gen.VPwithMultipleVC(jwtVcs, state.cid1, state.data.did, state.audience.did, state.didKey1,
        state.keyId, state.schemaId1, schemaType, state.issuanceDate1)

      const vpVerify = await Verify.VP(jwtVp)
      console.log('VP Verify: ', JSON.stringify(vpVerify.data, null, 2))
      expect(vpVerify.status).toEqual(200)
      expect(vpVerify.data.verification_result).toBe(true)
      expect(vpVerify.data.vc[0].verification_result).toBe(false)
      expect(vpVerify.data.vc[1].verification_result).toBe(true)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
