#**********************************************************************************************
# Traffic Emulator for Network Services
# Copyright 2020 VMware, Inc
# The BSD-2 license (the "License") set forth below applies to all parts of
# the Traffic Emulator for Network Services project. You may not use this file
# except in compliance with the License.
#
# BSD-2 License
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE
#**********************************************************************************************


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
