export const SUBJECT = {
  SUBJECT_FOR_SCHEMA_001: {
    example_array: ['ABC', 'DEF'],
    example_object: {
      'text1': 1,
      'text2': 'abc'
    },
    example_string: 'test'
  },
  SUBJECT_FOR_SCHEMA_001_WRONG_TYPE: {
    example_array: 'ABC',
    example_object: 'text1',
    example_string: 1
  },
  SUBJECT_FOR_SCHEMA_001_ADDITIONAL: {
    example_array: ['ABC', 'DEF'],
    example_object: {
      'text1': 1,
      'text2': 'abc'
    },
    example_string: 'test',
    name: 'Tester'
  },
  SUBJECT_FOR_SCHEMA_002: {
    pet_name: ['Nicky', 'Cookie', 'Fin'],
    pet_count: 3,
    keeper: {
      name: {
        prefix: 'Mr.',
        first_name: 'Michael',
        last_name: 'Bay'
      }
    },
    pet_avg_age: 4.5,
    keeper_id: 'abc-p1101'
  },
  SUBJECT_FOR_SCHEMA_002_WRONG_TYPE: {
    pet_name: 'Nicky',
    pet_count: '3',
    keeper: {
      name: {
        prefix: 'Mr.',
        first_name: 'Michael',
        last_name: 'Bay'
      }
    },
    pet_avg_age: '4.5',
    keeper_id: 123
  },
  SUBJECT_FOR_SCHEMA_002_ADDITIONAL: {
    pet_name: ['Nicky', 'Cookie', 'Fin'],
    pet_count: 3,
    keeper: {
      name: {
        prefix: 'Mr.',
        first_name: 'Michael',
        last_name: 'Bay',
        age: 24
      }
    },
    pet_avg_age: 4.5,
    keeper_id: 'abc-p1101'
  },
  SUBJECT_FOR_SCHEMA_002_WITHOUT_REQUIRED: {
    pet_name: ['Nicky', 'Cookie', 'Fin'],
    pet_count: 3,
    pet_avg_age: 4.5,
    keeper_id: ''
  },
  SUBJECT_FOR_SCHEMA_002_WITHOUT_REQUIRED_IN_OBJ: {
    pet_name: ['Nicky', 'Cookie', 'Fin'],
    pet_count: 3,
    keeper: {
      name: {
        prefix: 'Mr.',
        first_name: '',
      }
    },
    pet_avg_age: 4.5,
    keeper_id: 'abc-p1101'
  }
}
