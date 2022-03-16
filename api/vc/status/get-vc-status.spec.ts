import { DID } from '../../did/register/did-register'
import { KEY_TYPE } from '../../consts'
import { DIDNonce } from '../../did/register/nonce'
import { VC } from '../register/vc'
import { VCStatus } from './status'

let getInitState: any = () => ({
  keyId: '',
  didKey1: [],
  didKey2: [],
  didKey3: [],
  didKey4: [],
  data: {
    did: '',
    nonce: ''
  },
  issuer:{
    did: ''
  },
  didId: '',
  vc: {
    version: '',
    version2: ''
  }
})
describe('Get VC Status', () => {

  const state = getInitState()
  jest.setTimeout(20000)

  beforeEach(() =>{
    state.didKey1 = []
    state.issuerKey1 = []
  })

  test('Get VC Status', async () => {
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

      const vcGetStatus = await VCStatus.Get(state.cid)
      console.log('Get VC Status: ', JSON.stringify(vcGetStatus.data,null, 2))
      expect(vcGetStatus.status).toEqual(200)
      expect(vcGetStatus.data.cid).toBe(state.cid)
      expect(vcGetStatus.data.status).toBe(null)
      expect(vcGetStatus.data.activated_at).toBe(null)
      expect(vcGetStatus.data.revoked_at).toBe(null)
    } catch (err) {
      console.log(err.response)
      expect(err).not.toBeTruthy()
    }
  })
})
