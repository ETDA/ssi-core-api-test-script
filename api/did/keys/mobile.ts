import { CONFIG } from '../../consts'
import { CryptoHelper } from '../../utils/ecdsa-CryptoHelper'
import axios from 'axios'

const genMobileRegisterMessage = (obj: {
  id_card_no: string, first_name: string, last_name: string,
  date_of_birth: string, laser_id: string, email: string, uuid: string
}) => {
  return {
    id_card_no: obj.id_card_no,
    first_name: obj.first_name,
    last_name: obj.last_name,
    date_of_birth: obj.date_of_birth,
    laser_id: obj.laser_id,
    email: obj.email,
    device: {
      name: 'test',
      os: 'iOS',
      os_version: '14.0',
      model: '12',
      uuid: obj.uuid
    }
  }
}

const genRequestData = (private_key: string, message: any) => {
  const messageData = CryptoHelper.encodeBase64(JSON.stringify(message))
  return {
    data: {
      message: message
    },
    headers: {
      'x-signature': CryptoHelper.sign(private_key, messageData)
    }
  }
}

export class Mobile {

  static async Register (didKey: any, idCardNo: string, firstName: string,
    lastName: string, dateOfBirth: string, laserId: string,email: string,uuid: string) {

    const message = genMobileRegisterMessage({
      id_card_no: idCardNo,
      first_name: firstName,
      last_name: lastName,
      date_of_birth: dateOfBirth,
      laser_id: laserId,
      email: email,
      uuid: uuid,
    })
    const res = genRequestData(didKey[0].private_key, message)
    console.log('request: Mobile register ', JSON.stringify(message, null, 2))
    console.log('headers: Mobile register ', JSON.stringify(res.headers, null, 2))
    return await axios.post(`${CONFIG.MOBILE_URL}/mobile/users`,
      message)
  }

  static async GetRecovererDid () {
    return await axios.get(`${CONFIG.MOBILE_URL}/mobile/did_address`)
  }
}
