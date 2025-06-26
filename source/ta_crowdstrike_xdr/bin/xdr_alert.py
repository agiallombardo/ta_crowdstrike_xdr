import import_declare_test

import sys

from splunklib import modularinput as smi
from xdr_alert_helper import stream_events, validate_input


class XDR_ALERT(smi.Script):
    def __init__(self):
        super(XDR_ALERT, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('xdr_alert')
        scheme.description = 'xdr_alert'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        scheme.add_argument(
            smi.Argument(
                'account',
                title='Account',
                description='CrowdStrike account to use',
                required_on_create=True,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition):
        return validate_input(definition)

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        return stream_events(inputs, ew)


if __name__ == '__main__':
    exit_code = XDR_ALERT().run(sys.argv)
    sys.exit(exit_code)