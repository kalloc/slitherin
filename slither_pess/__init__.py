from slither_pess.detectors.double_entry_token_possibility import DoubleEntryTokenPossiblity
from slither_pess.detectors.unprotected_setter import UnprotectedSetter
from slither_pess.detectors.transfer_from_arbitrary_Address import TransferFromWarning


def make_plugin():
    plugin_detectors = [DoubleEntryTokenPossiblity,UnprotectedSetter,TransferFromWarning]
    plugin_printers = []

    return plugin_detectors, plugin_printers
