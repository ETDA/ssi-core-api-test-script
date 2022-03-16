export const SCHEMA_BODY_PROPERTIES = {
  SCHEMA_001: {
    NAME: 'SCHEMA_001',
    TYPE: 'object',
    BODY: {
      'example_array': {
        'description': 'This is an example array',
        'type': 'array',
        'minItems': 1,
        'items': {
          'type': 'string'
        }
      },
      'example_object': {
        'type': 'object',
        'properties': {
          'text1': {
            'type': 'number'
          },
          'text2': {
            'type': 'string'
          }
        }
      },
      'example_string': {
        'type': 'string'
      }
    },
    REQUIRED: ['example_array']
  },
  SCHEMA_002: {
    NAME: 'SCHEMA_002',
    TYPE: 'object',
    BODY: {
      'pet_name': {
        'description': 'Your pet name',
        'type': 'array',
        'minItems': 1,
        'items': {
          'type': 'string'
        }
      },
      'pet_count': {
        'type': 'number'
      },
      'keeper': {
        'type': 'object',
        'properties': {
          'name': {
            'type': 'object',
            'properties': {
              'prefix': {
                'type': 'string'
              },
              'first_name': {
                'type': 'string'
              },
              'last_name': {
                'type': 'string'
              }
            },
            'required': [
              'first_name',
              'last_name'
            ],
            'additionalProperties': true
          }
        }
      },
      'pet_avg_age': {
        'type': 'number'
      },
      'keeper_id': {
        'type': 'string'
      }
    },
    REQUIRED: ['keeper', 'keeper_id'],
  },
  SCHEMA_003: {
    NAME: 'SCHEMA_003',
    TYPE: 'object',
    BODY: {
      'pet_name': {
        'description': 'Your pet name',
        'type': 'array',
        'minItems': 1,
        'items': {
          'type': 'string'
        }
      },
      'pet_count': {
        'type': 'number'
      },
      'keeper': {
        'type': 'object',
        'properties': {
          'name': {
            'type': 'object',
            'properties': {
              'prefix': {
                'type': 'string'
              },
              'first_name': {
                'type': 'string'
              },
              'last_name': {
                'type': 'string'
              }
            },
            'required': [
              'first_name',
              'last_name'
            ],
            'additionalProperties': false
          }
        }
      },
      'pet_avg_age': {
        'type': 'number'
      },
      'keeper_id': {
        'type': 'string'
      }
    },
    REQUIRED: ['keeper', 'keeper_id'],
    REQUIRED_IN_OBJ: ['keeper.properties.name.first_name', 'keeper.properties.name.last_name, keeper_id']
  }
}
