from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import EqlBackend
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.backends.secops import SecOpsBackend
from sigma.backends.loki import LogQLBackend

SIGMA_CONVERT_TARGETS = {
    'splunk':    {'label': 'Splunk (SPL)',            'extension': 'spl'},
    'elastic':   {'label': 'Elastic (EQL)',            'extension': 'eql'},
    'sentinel':  {'label': 'Microsoft Sentinel (KQL)', 'extension': 'kql'},
    'sumologic': {'label': 'Sumo Logic (CSE)',         'extension': 'json'},
    'secops':    {'label': 'Google SecOps (UDM)',      'extension': 'txt'},
    'loki':      {'label': 'Grafana Loki (LogQL)',     'extension': 'logql'},
}


def _backend_for(target: str):
    if target == 'splunk':
        return SplunkBackend()
    if target == 'elastic':
        return EqlBackend()
    if target == 'sentinel':
        return KustoBackend(processing_pipeline=sentinel_asim_pipeline())
    if target == 'sumologic':
        return SumoLogicCSERuleBackend()
    if target == 'secops':
        return SecOpsBackend()
    if target == 'loki':
        return LogQLBackend()
    raise ValueError(f"Unknown Sigma conversion target: {target}")


def convert_sigma_rule(rule, target: str) -> str:
    """Convert a Sigma rule's raw content into the given target query language via pySigma."""
    if target not in SIGMA_CONVERT_TARGETS:
        raise ValueError(f"Unknown Sigma conversion target: {target}")
    collection = SigmaCollection.from_yaml(rule.to_string)
    try:
        queries = _backend_for(target).convert(collection)
    except Exception as e:
        # pySigma-backend-kusto's ASIM pipeline can only pick a target table from a
        # fixed category/EventID -> table map (see its mappings.py); a rule whose
        # logsource isn't in that map raises this instead of guessing a table, and
        # we don't want to guess one either — a wrong table would look like a valid
        # query instead of clearly failing. Surface a short, honest message instead
        # of the library's multi-paragraph internal error (which talks about
        # "query_table" / "sigma-cli", irrelevant to a Rulezet visitor).
        if target == 'sentinel' and 'Unable to determine table name' in str(e):
            raise ValueError(
                "This rule's logsource isn't mapped to a Microsoft Sentinel ASIM table yet — "
                "conversion isn't available for this specific rule."
            ) from e
        raise
    return '\n\n'.join(queries)
