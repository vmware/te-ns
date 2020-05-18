from jsonschema import Draft4Validator, validate, ValidationError

te_controller_json_schema = {
	'title': 'te_list',
	'type':'object',
	'properties':{
		'host': {"format": "ipv4"},
		'hostport' : {"format": 'number'},
		'te_infra': {
			'apipath':'/api/',
			'apiversion':'v1.0',
		}
	},
	'required':['host', 'hostport']
}

te_dp_dict_json_schema = {
    'title': 'te_dp_property',
	'type':'object',
    'patternProperties': {
        "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" : {
            'type' : 'object',
        	'properties': {
                'tag': {'type':'string'},
                'user': {'type':'string'},
                'passwd': {'type':'string'},
                'ssh_key': {'type':'string'},
                'instance_profile': {
                    'type': 'object',
                    'additionalProperties': {'type': 'number'},                    
                }
            },
            'dependencies': {
                'user': ['passwd'],
                'passwd': ['user'],
                'ssh_key':['user']
            },
            'minProperties':1
        }
    },
    'minProperties':1
}

instanceProfileConfig ={
}

resource_config_json_schema = {
	'title': 'resource_config',
	'type':'object',
        'properties':	{
                'vip-list': {
                    'type':'array',
                    'items': {
                        'format': 'string'
                    },
                    'minItems':1,
                },
                'url-list': {
                    'type':'array',
                    'items': {
                        'type':'object',
                        'properties': {
                            'url':{'format':'string'},
                            'size':{'format':'number'},
                        },
                        'required': ['url','size']
                    },
                    'minItems':1,
                },
                'log-path': {'format':'string'},
        },
        'required':['vip-list','url-list', 'log-path' ],
        "additionalProperties": False,
}

session_config_json_schema = {
	'title': 'resource_config',
	'type':'array',
        'items': {
            'properties':	{
                            "session-type": {'format':'string'},
                            "num-sessions": {'format':'number'},
                            "connection-range": {
                                  "type": "array",
                                  'items': {
                                        'format':'number',
                                        'format':'number',
                                  },
                                  'minItems':2,
                            },
                            "requests-range": {
                                  "type": "array",
                                  'items': {
                                        'format':'number',
                                        'format':'number',
                                  },
                                  'minItems':2,
                            },
                            "persistence": {'format': 'boolean'},
                            "ssl-tickets": {'format': 'boolean'},
                            "num-cycles": {'format':'number'},
                            "type": {'format':'string'},
                            "cycle-delay": {'format':'number'},
                            "session-ramp-delay": {'format':'number'},
                            "session-ramp-step": {'format':'number'},
                    },
            'minProperties':11,

        },
        'minItems':1,
}
