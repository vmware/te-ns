from collections import defaultdict

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class TE(object):
    __metaclass__ = Singleton

    def __init__(self, daemon_ip, flask_port, redis_port, nginx_port, \
        postgres_port, zmq_port, loglevel):
        self.__daemon_ip               = daemon_ip
        self.__flask_port              = flask_port
        self.__nginx_port              = nginx_port
        self.__redis_port              = redis_port
        self.__postgres_port           = postgres_port
        self.__zmq_port                = zmq_port
        self.__loglevel                = loglevel
        self.__te_dp_dict              = {}
        self.__resource_config         = None
        self.__session_config          = None
        self.__instance_profile_config = None
        self.__client_cert_bundle      = None

        #Stats Collection Purpose
        self.ses_time_stamps = defaultdict(list)

    def add_ses_time_stamp(self, ses_tag, timestamp):
        self.ses_time_stamps[ses_tag].append(timestamp)

    def clear_ses_time_stamp(self):
        self.ses_time_stamps.clear()

    def get_daemon_ip(self):
        return self.__daemon_ip
    def get_flask_port(self):
        return self.__flask_port
    def get_nginx_port(self):
        return self.__nginx_port
    def get_redis_port(self):
        return self.__redis_port
    def get_postgres_port(self):
        return self.__postgres_port
    def get_zmq_port(self):
        return self.__zmq_port
    def get_loglevel(self):
        return self.__loglevel

    def set_te_dp(self, te_dp_dict):
        self.__te_dp_dict = te_dp_dict
    def unset_te_dp(self):
        self.__te_dp_dict = {}
    def get_te_dp(self):
        return self.__te_dp_dict

    def set_resource_config(self, resource_config):
        self.__resource_config = resource_config
    def unset_resource_config(self):
        self.__resource_config = None
    def get_resource_config(self):
        return self.__resource_config

    def set_session_config(self, session_config):
        self.__session_config = session_config
    def unset_session_config(self):
        self.__session_config = None
    def get_session_config(self):
        return self.__session_config

    def set_instance_profile_config(self, instance_profile_config):
        self.__instance_profile_config = instance_profile_config
    def unset_instance_profile_config(self):
        self.__instance_profile_config = None
    def get_instance_profile_config(self):
        return self.__instance_profile_config

    def set_client_cert_bundle(self, client_cert_bundle):
        self.__client_cert_bundle = client_cert_bundle
    def unset_client_cert_bundle(self):
        self.__client_cert_bundle = None
    def get_client_cert_bundle(self):
        return self.__client_cert_bundle
