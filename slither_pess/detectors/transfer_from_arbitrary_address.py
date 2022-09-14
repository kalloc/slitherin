# from slither.core.cfg.node import NodeType

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from slither.analyses.data_dependency.data_dependency import is_dependent, is_tainted

from slither.core.declarations import Contract



def strange_transfer_from(func: Function):

    if func.is_protected():
        return []

    ret: List[Node] = []

    # copypaste from arbitrary-send detector

    # for node in func.nodes:
    #     for ir in node.irs:
    #         if isinstance(ir, SolidityCall):
    #             if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)"):
    #                 return False
    #         if isinstance(ir, Index):
    #             if ir.variable_right == SolidityVariableComposed("msg.sender"):
    #                 return False
    #             if is_dependent(
    #                 ir.variable_right,
    #                 SolidityVariableComposed("msg.sender"),
    #                 func.contract,
    #             ):
    #                 return False
    #         if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
    #             if isinstance(ir, (HighLevelCall)):
    #                 if isinstance(ir.function, Function):
    #                     if ir.function.full_name == "transferFrom(address,address,uint256)":
    #                         return False
    #             if ir.call_value is None:
    #                 continue
    #             if ir.call_value == SolidityVariableComposed("msg.value"):
    #                 continue
    #             if is_dependent(
    #                 ir.call_value,
    #                 SolidityVariableComposed("msg.value"),
    #                 func.contract,
    #             ):
    #                 continue

    #             if is_tainted(ir.destination, func.contract):
    #                 ret.append(node)

    return ret



def detect_strange_transfer_from(contract: Contract):
    """
        Detect arbitrary from in transferFrom
    Args:
        contract (Contract)
    Returns:
        list((Function), (list (Node)))
    """
    ret = []
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes = strange_transfer_from(f)
        if nodes:
            ret.append((f, nodes))
    return ret



class TransferFromWarning(AbstractDetector):
    """
    Sees if contract contains a function wich is vulnurable to double-entry tokens attack
    """

    ARGUMENT = 'transfer-from-arbitrary-address' # slither will launch the detector with slither.py --detect mydetector
    HELP = 'The function might be possible to spend approved token of other users'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = 'https://twitter.com/0xblvck_/status/1559746627862237188'
    WIKI_TITLE = 'Transfer from an arnitrary address'
    WIKI_DESCRIPTION = ""
    WIKI_EXPLOIT_SCENARIO = '...'
    WIKI_RECOMMENDATION = 'Убедитесь, что контракт не даёт возможности переводить токены пользователей, давших контракту approve'


    def _detect(self):

        results = []

        for c in self.contracts:

            for (func, nodes) in detect_strange_transfer_from(c):

                info = [func, " sends tokens from an arbitrary addressss\n"]
                info += ["\tDangerous calls:\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)

                results.append(res)

        return results
