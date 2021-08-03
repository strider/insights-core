"""
Rules for data collection
"""
from __future__ import absolute_import
import hashlib
import json
import logging
import six
import shlex
import os
import requests
import yaml
import stat
from six.moves import configparser as ConfigParser

from subprocess import Popen, PIPE, STDOUT
from tempfile import NamedTemporaryFile
from .constants import InsightsConstants as constants
from .map_components import map_rm_conf_to_components

APP_NAME = constants.app_name
logger = logging.getLogger(__name__)
NETWORK = constants.custom_network_log_level


def correct_format(parsed_data, expected_keys, filename):
    '''
    Ensure the parsed file matches the needed format
    Returns True, <message> on error
    Returns False, None on success
    '''
    # validate keys are what we expect
    def is_list_of_strings(data):
        '''
        Helper function for correct_format()
        '''
        if data is None:
            # nonetype, no data to parse. treat as empty list
            return True
        if not isinstance(data, list):
            return False
        for l in data:
            if not isinstance(l, six.string_types):
                return False
        return True

    keys = parsed_data.keys()
    invalid_keys = set(keys).difference(expected_keys)
    if invalid_keys:
        return True, ('Unknown section(s) in %s: ' % filename + ', '.join(invalid_keys) +
                      '\nValid sections are ' + ', '.join(expected_keys) + '.')

    # validate format (lists of strings)
    for k in expected_keys:
        if k in parsed_data:
            if k == 'patterns' and isinstance(parsed_data['patterns'], dict):
                if 'regex' not in parsed_data['patterns']:
                    return True, 'Patterns section contains an object but the "regex" key was not specified.'
                if 'regex' in parsed_data['patterns'] and len(parsed_data['patterns']) > 1:
                    return True, 'Unknown keys in the patterns section. Only "regex" is valid.'
                if not is_list_of_strings(parsed_data['patterns']['regex']):
                    return True, 'regex section under patterns must be a list of strings.'
                continue
            if not is_list_of_strings(parsed_data[k]):
                return True, '%s section must be a list of strings.' % k
    return False, None


def load_yaml(filename):
    try:
        with open(filename) as f:
            loaded_yaml = yaml.safe_load(f)
        if loaded_yaml is None:
            logger.debug('%s is empty.', filename)
            return {}
    except (yaml.YAMLError, yaml.parser.ParserError) as e:
        # can't parse yaml from conf
        raise RuntimeError('ERROR: Cannot parse %s.\n'
                           'If using any YAML tokens such as [] in an expression, '
                           'be sure to wrap the expression in quotation marks.\n\nError details:\n%s\n' % (filename, e))
    if not isinstance(loaded_yaml, dict):
        # loaded data should be a dict with at least one key
        raise RuntimeError('ERROR: Invalid YAML loaded.')
    return loaded_yaml


def verify_permissions(f):
    '''
    Verify 600 permissions on a file
    '''
    mode = stat.S_IMODE(os.stat(f).st_mode)
    if not mode == 0o600:
        raise RuntimeError("Invalid permissions on %s. "
                           "Expected 0600 got %s" % (f, oct(mode)))
    logger.debug("Correct file permissions on %s", f)


class InsightsUploadConf(object):
    """
    Insights spec configuration from uploader.json
    """

    def __init__(self, config, conn=None):
        """
        Load config from parent
        """
        # InsightsConfig
        self.config = config

        # .fallback.json
        self.fallback_file = constants.collection_fallback_file

        # denylist config
        self.remove_file = config.remove_file
        self.redaction_file = config.redaction_file
        self.content_redaction_file = config.content_redaction_file

        # tags
        self.tags_file = config.tags_file

        # .cache.json
        self.collection_rules_file = constants.collection_rules_file

        # location of new uploader.json
        self.collection_rules_url = self.config.collection_rules_url

        # initialize an attribute to store the content of uploader.json
        #   once it is loaded and verified
        self.uploader_json = None

        # set rm_conf as a class attribute so we can observe it
        #   in create_report
        self.rm_conf = None

        # attribute to set when using file-redaction.yaml instead of
        #   remove.conf, for reporting purposes. True by default
        #   since new format is favored.
        self.using_new_format = True

        if conn:
            if self.collection_rules_url is None:
                if config.legacy_upload:
                    self.collection_rules_url = conn.base_url + '/v1/static/uploader.v2.json'
                else:
                    self.collection_rules_url = conn.base_url.split('/platform')[0] + '/v1/static/uploader.v2.json'
            self.conn = conn

    def update(self):
        """
        Download new uploader.json from prod.

        Returns
            True  - success
            False - failure
        """
        # download new files
        downloaded_json = self._fetch_json()
        if not downloaded_json:
            return False
        if self.config.gpg:
            downloaded_gpg = self._fetch_gpg()
            if not downloaded_gpg:
                return False
            # write downloaded data to file to verify with gpg
            with NamedTemporaryFile(suffix=".json") as json_path, NamedTemporaryFile(suffix=".asc") as gpg_path:
                json_path.write(downloaded_json.encode("utf-8"))
                json_path.file.flush()
                gpg_path.write(downloaded_gpg.encode("utf-8"))
                gpg_path.file.flush()
                # verify the downloaded data
                verified = self.verify(json_path.name, gpg_path.name)
        else:
            downloaded_gpg = None
            verified = True
        if verified:
            # if OK, save to disk and cache as an attribute
            self.save(downloaded_json, downloaded_gpg)
            self.uploader_json = json.loads(downloaded_json)
            return True
        else:
            return False

    def _fetch_json(self):
        """
        Download the new uploader.json from prod

        Returns:
            (dict) on success
            None on failure
        """
        logger.debug("Attemping to download collection rules from %s",
                     self.collection_rules_url)
        logger.log(NETWORK, "GET %s", self.collection_rules_url)
        try:
            req = self.conn.session.get(
                self.collection_rules_url, headers=({'accept': 'application/json'}))
            if req.status_code == 200:
                logger.debug("Successfully downloaded collection rules")
                return req.text
            else:
                logger.error("ERROR: Could not download dynamic configuration")
                logger.error("Debug Info: \nConf status: %s", req.status_code)
                logger.error("Debug Info: \nConf message: %s", req.text)
                return None
        except requests.ConnectionError as e:
            logger.error(
                "ERROR: Could not download dynamic configuration: %s", e)
            return None

    def _fetch_gpg(self):
        '''
        Download gpg signature for uploader.json

        Returns
            GPG signature string on success
            None on failure
        '''
        logger.debug("Attemping to download collection "
                     "rules GPG signature from %s",
                     self.collection_rules_url + ".asc")

        headers = ({'accept': 'text/plain'})
        logger.log(NETWORK, "GET %s", self.collection_rules_url + '.asc')
        try:
            config_sig = self.conn.session.get(self.collection_rules_url + '.asc',
                                            headers=headers)
            if config_sig.status_code == 200:
                logger.debug("Successfully downloaded GPG signature")
                return config_sig.text
            else:
                logger.error("ERROR: Download of GPG Signature failed!")
                logger.error("Sig status: %s", config_sig.status_code)
                return None
        except requests.ConnectionError as e:
            logger.error(
                "ERROR: Could not download GPG signature: %s", e)
            return None

    def verify(self, json_path, gpg_path):
        """
        Validate the uploader.json

        Returns:
            True on success
            False on failure
        """
        logger.debug("Verifying GPG signature of Insights configuration")
        command = ("/usr/bin/gpg --no-default-keyring "
                   "--keyring " + constants.pub_gpg_path +
                   " --verify " + gpg_path + " " + json_path)
        if not six.PY3:
            command = command.encode('utf-8', 'ignore')
        args = shlex.split(command)
        logger.debug("Executing: %s", args)
        proc = Popen(
            args, shell=False, stdout=PIPE, stderr=STDOUT, close_fds=True)
        stdout, stderr = proc.communicate()
        logger.debug("STDOUT: %s", stdout)
        logger.debug("STDERR: %s", stderr)
        logger.debug("Status: %s", proc.returncode)
        if proc.returncode:
            logger.error("ERROR: Unable to validate GPG signature: %s", json_path)
            return False
        else:
            logger.debug("GPG signature verified")
            return True

    def save(self, downloaded_json, downloaded_gpg):
        """
        Write collections rules to disk
        """
        if downloaded_json:
            with open(self.collection_rules_file, "wb") as json_path:
                json_path.write(downloaded_json.encode("utf-8"))
        if downloaded_gpg:
            with open(self.collection_rules_file + ".asc", "wb") as gpg_path:
                gpg_path.write(downloaded_gpg.encode("utf-8"))

    def load(self):
        """
        Get config from local config file, first try cache, then fallback.

        Returns:
            dict on success

        Raises:
            RuntimeError on failure
        """
        if self.uploader_json:
            # already loaded, return cached
            return self.uploader_json

        for conf_file in [self.collection_rules_file, self.fallback_file]:
            logger.debug("trying to read conf from: " + conf_file)
            if not self.config.gpg or self.verify(conf_file, conf_file + ".asc"):
                with open(conf_file, "r") as f:
                    try:
                        conf = json.load(f)
                    except ValueError:
                        logger.error("ERROR: Invalid JSON in %s", path)
                        conf = None
            if conf:
                logger.debug("Success reading config")
                logger.debug(json.dumps(conf))
                self.uploader_json = conf
                return conf
        raise RuntimeError("ERROR: Unable to download conf or read it from disk!")

    def get_rm_conf_old(self):
        """
        Get excluded files config from remove_file.
        """
        # Convert config object into dict
        self.using_new_format = False
        parsedconfig = ConfigParser.RawConfigParser()
        if not self.remove_file:
            # no filename defined, return nothing
            logger.debug('remove_file is undefined')
            return None
        if not os.path.isfile(self.remove_file):
            logger.debug('%s not found. No data files, commands,'
                         ' or patterns will be ignored, and no keyword obfuscation will occur.', self.remove_file)
            return None
        try:
            verify_permissions(self.remove_file)
        except RuntimeError as e:
            if self.config.validate:
                # exit if permissions invalid and using --validate
                raise RuntimeError('ERROR: %s' % e)
            logger.warning('WARNING: %s', e)
        try:
            parsedconfig.read(self.remove_file)
            sections = parsedconfig.sections()

            if not sections:
                # file has no sections, skip it
                logger.debug('Remove.conf exists but no parameters have been defined.')
                return None

            if sections != ['remove']:
                raise RuntimeError('ERROR: invalid section(s) in remove.conf. Only "remove" is valid.')

            expected_keys = ('commands', 'files', 'patterns', 'keywords')
            rm_conf = {}
            for item, value in parsedconfig.items('remove'):
                if item not in expected_keys:
                    raise RuntimeError('ERROR: Unknown key in remove.conf: ' + item +
                                       '\nValid keys are ' + ', '.join(expected_keys) + '.')
                if six.PY3:
                    rm_conf[item] = [v.strip() for v in value.strip().encode('utf-8').decode('unicode-escape').split(',')]
                else:
                    rm_conf[item] = [v.strip() for v in value.strip().decode('string-escape').split(',')]
            self.rm_conf = rm_conf
        except ConfigParser.Error as e:
            # can't parse config file at all
            logger.debug(e)
            logger.debug('To configure using YAML, please use file-redaction.yaml and file-content-redaction.yaml.')
            raise RuntimeError('ERROR: Cannot parse the remove.conf file.\n'
                               'See %s for more information.' % self.config.logging_file)
        logger.warning('WARNING: remove.conf is deprecated. Please use file-redaction.yaml and file-content-redaction.yaml. See https://access.redhat.com/articles/4511681 for details.')
        return self.rm_conf

    def load_redaction_file(self, fname):
        '''
        Load the YAML-style file-redaction.yaml
            or file-content-redaction.yaml files
        '''
        if fname not in (self.redaction_file, self.content_redaction_file):
            # invalid function use, should never get here in a production situation
            return None
        if not fname:
            # no filename defined, return nothing
            logger.debug('redaction_file or content_redaction_file is undefined')
            return None
        if not fname or not os.path.isfile(fname):
            if fname == self.redaction_file:
                logger.debug('%s not found. No files or commands will be skipped.', self.redaction_file)
            elif fname == self.content_redaction_file:
                logger.debug('%s not found. '
                             'No patterns will be skipped and no keyword obfuscation will occur.', self.content_redaction_file)
            return None
        try:
            verify_permissions(fname)
        except RuntimeError as e:
            if self.config.validate:
                # exit if permissions invalid and using --validate
                raise RuntimeError('ERROR: %s' % e)
            logger.warning('WARNING: %s', e)
        loaded = load_yaml(fname)
        if fname == self.redaction_file:
            err, msg = correct_format(loaded, ('commands', 'files', 'components'), fname)
        elif fname == self.content_redaction_file:
            err, msg = correct_format(loaded, ('patterns', 'keywords'), fname)
        if err:
            # YAML is correct but doesn't match the format we need
            raise RuntimeError('ERROR: ' + msg)
        return loaded

    def get_rm_conf(self):
        '''
        Try to load the the "new" version of
        remove.conf (file-redaction.yaml and file-redaction.yaml)
        '''
        rm_conf = {}
        redact_conf = self.load_redaction_file(self.redaction_file)
        content_redact_conf = self.load_redaction_file(self.content_redaction_file)

        if redact_conf:
            rm_conf.update(redact_conf)
        if content_redact_conf:
            rm_conf.update(content_redact_conf)

        if not redact_conf and not content_redact_conf:
            # no file-redaction.yaml or file-content-redaction.yaml defined,
            #   try to use remove.conf
            self.rm_conf = self.get_rm_conf_old()
            if self.config.core_collect:
                self.rm_conf = map_rm_conf_to_components(self.rm_conf, self.load())
            return self.rm_conf

        # remove Nones, empty strings, and empty lists
        filtered_rm_conf = dict((k, v) for k, v in rm_conf.items() if v)
        self.rm_conf = filtered_rm_conf
        if self.config.core_collect:
            self.rm_conf = map_rm_conf_to_components(self.rm_conf, self.load())
        return self.rm_conf

    def get_tags_conf(self):
        '''
        Try to load the tags.conf file
        '''
        if not os.path.isfile(self.tags_file):
            logger.info("%s does not exist", self.tags_file)
            return None
        else:
            try:
                load_yaml(self.tags_file)
                logger.info("%s loaded successfully", self.tags_file)
            except RuntimeError:
                logger.warning("Invalid YAML. Unable to load %s", self.tags_file)
                return None

    def validate(self):
        '''
        Validate remove.conf and tags.conf
        '''
        self.get_tags_conf()
        success = self.get_rm_conf()
        if not success:
            logger.info('No contents in the blacklist configuration to validate.')
            return None
        # Using print here as this could contain sensitive information
        print('Blacklist configuration parsed contents:')
        print(json.dumps(success, indent=4))
        logger.info('Parsed successfully.')
        return True

    def create_report(self):
        def length(lst):
            '''
            Because of how the INI remove.conf is parsed,
            an empty value in the conf will produce
            the value [''] when parsed. Do not include
            these in the report
            '''
            if len(lst) == 1 and lst[0] == '':
                return 0
            return len(lst)

        num_commands = 0
        num_files = 0
        num_components = 0
        num_patterns = 0
        num_keywords = 0
        using_regex = False

        if self.rm_conf:
            for key in self.rm_conf:
                if key == 'commands':
                    num_commands = length(self.rm_conf['commands'])
                if key == 'files':
                    num_files = length(self.rm_conf['files'])
                if key == 'components':
                    num_components = length(self.rm_conf['components'])
                if key == 'patterns':
                    if isinstance(self.rm_conf['patterns'], dict):
                        num_patterns = length(self.rm_conf['patterns']['regex'])
                        using_regex = True
                    else:
                        num_patterns = length(self.rm_conf['patterns'])
                if key == 'keywords':
                    num_keywords = length(self.rm_conf['keywords'])

        return {
            'obfuscate': self.config.obfuscate,
            'obfuscate_hostname': self.config.obfuscate_hostname,
            'commands': num_commands,
            'files': num_files,
            'components': num_components,
            'patterns': num_patterns,
            'keywords': num_keywords,
            'using_new_format': self.using_new_format,
            'using_patterns_regex': using_regex
        }


if __name__ == '__main__':
    from .config import InsightsConfig
    from .connection import InsightsConnection
    config = InsightsConfig(verbose=True)
    conn = InsightsConnection(config)
    uploadconf = InsightsUploadConf(config, conn)
    # print(uploadconf.update())
    print(uploadconf.load())
    # print(uploadconf.uploader_json)
    # report = uploadconf.create_report()

    # print(report)
