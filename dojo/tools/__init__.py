__author__ = 'jay7958'

from dojo.tools import SonarQubeHtmlParser
from dojo.tools.acunetix.parser import AcunetixScannerParser
from dojo.tools.anchore_engine.parser import AnchoreEngineScanParser
from dojo.tools.appspider.parser import AppSpiderXMLParser
from dojo.tools.aqua.parser import AquaJSONParser
from dojo.tools.arachni.parser import ArachniJSONParser
from dojo.tools.aws_prowler.parser import AWSProwlerParser
from dojo.tools.aws_scout2.parser import AWSScout2Parser
from dojo.tools.bandit.parser import BanditParser
from dojo.tools.blackduck.parser import BlackduckHubCSVParser
from dojo.tools.brakeman.parser import BrakemanScanParser
from dojo.tools.bundler_audit.parser import BundlerAuditParser
from dojo.tools.burp.parser import BurpXmlParser
from dojo.tools.checkmarx.parser import CheckmarxXMLParser, DetailedCheckmarxXMLParser
from dojo.tools.clair.parser import ClairParser
from dojo.tools.clair_klar.parser import ClairKlarParser
from dojo.tools.cobalt.parser import CobaltCSVParser
from dojo.tools.contrast.parser import ContrastCSVParser
from dojo.tools.crashtest_security.parser import CrashtestSecurityXmlParser
from dojo.tools.dawnscanner.parser import DawnScannerParser
from dojo.tools.dependency_check.parser import DependencyCheckParser
from dojo.tools.dependency_track.parser import DependencyTrackParser
from dojo.tools.fortify.parser import FortifyXMLParser
from dojo.tools.generic.parser import GenericFindingUploadCsvParser
from dojo.tools.gosec.parser import GosecScannerParser
from dojo.tools.hadolint.parser import HadolintParser
from dojo.tools.ibm_app.parser import IbmAppScanDASTXMLParser
from dojo.tools.immuniweb.parser import ImmuniwebXMLParser
from dojo.tools.jfrogxray.parser import XrayJSONParser
from dojo.tools.kiuwan.parser import KiuwanCSVParser
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectXMLParser
from dojo.tools.mobsf.parser import MobSFParser
from dojo.tools.mozilla_observatory.parser import MozillaObservatoryJSONParser
from dojo.tools.nessus.parser import nessus_parser_factory
from dojo.tools.netsparker.parser import NetsparkerParser
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.tools.nikto.parser import NiktoXMLParser
from dojo.tools.nmap.parser import NmapXMLParser
from dojo.tools.npm_audit.parser import NpmAuditParser
from dojo.tools.nsp.parser import NspParser
from dojo.tools.openscap.parser import OpenscapXMLParser
from dojo.tools.openvas_csv.parser import OpenVASUploadCsvParser
from dojo.tools.php_security_audit_v2.parser import PhpSecurityAuditV2
from dojo.tools.php_symfony_security_check.parser import PhpSymfonySecurityCheckParser
from dojo.tools.qualys.parser import QualysParser
from dojo.tools.qualys_webapp.parser import QualysWebAppParser
from dojo.tools.retirejs.parser import RetireJsParser
from dojo.tools.safety.parser import SafetyParser
from dojo.tools.skf.parser import SKFCsvParser
from dojo.tools.snyk.parser import SnykParser
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser
from dojo.tools.sonarqube_api.importer import SonarQubeApiImporter
from dojo.tools.sonatype.parser import SonatypeJSONParser
from dojo.tools.spotbugs.parser import SpotbugsXMLParser
from dojo.tools.ssl_labs.parser import SSLlabsParser
from dojo.tools.sslscan.parser import SslscanXMLParser
from dojo.tools.sslyze.parser import SslyzeXmlParser
from dojo.tools.testssl.parser import TestsslCSVParser
from dojo.tools.trivy.parser import TrivyParser
from dojo.tools.trufflehog.parser import TruffleHogJSONParser
from dojo.tools.trustwave.parser import TrustwaveUploadCsvParser
from dojo.tools.twistlock.parser import TwistlockParser
from dojo.tools.vcg.parser import VCGParser
from dojo.tools.veracode.parser import VeracodeXMLParser
from dojo.tools.wapiti.parser import WapitiXMLParser
from dojo.tools.whitesource.parser import WhitesourceJSONParser
from dojo.tools.wpscan.parser import WpscanJSONParser
from dojo.tools.xanitizer.parser import XanitizerXMLParser
from dojo.tools.zap.parser import ZapXmlParser

SCAN_GENERIC_FINDING = 'Generic Findings Import'
SCAN_SONARQUBE_API = 'SonarQube API Import'

SCANNERS = {
    "Burp Scan": BurpXmlParser,
    "Nessus Scan": nessus_parser_factory,
    "Clair Scan": ClairParser,
    "Nmap Scan": NmapXMLParser,
    "Nikto Scan": NiktoXMLParser,
    "Nexpose Scan": NexposeFullXmlParser,
    "Veracode Scan": VeracodeXMLParser,
    "Checkmarx Scan": CheckmarxXMLParser,
    "Checkmarx Scan detailed": DetailedCheckmarxXMLParser,
    "Contrast Scan": ContrastCSVParser,
    "Crashtest Security Scan": CrashtestSecurityXmlParser,
    "Bandit Scan": BanditParser,
    "ZAP Scan": ZapXmlParser,
    "AppSpider Scan": AppSpiderXMLParser,
    "Arachni Scan": ArachniJSONParser,
    "VCG Scan": VCGParser,
    "Dependency Check Scan": DependencyCheckParser,
    "Dependency Track Finding Packaging Format (FPF) Export": DependencyTrackParser,
    "Retire.js Scan": RetireJsParser,
    "Node Security Platform Scan": NspParser,
    "NPM Audit Scan": NpmAuditParser,
    "Symfony Security Check": PhpSymfonySecurityCheckParser,
    "Generic Findings Import": GenericFindingUploadCsvParser,
    "Qualys Scan": QualysParser,
    "Qualys Webapp Scan": QualysWebAppParser,
    "OpenVAS CSV": OpenVASUploadCsvParser,
    "Snyk Scan": SnykParser,
    "SKF Scan": SKFCsvParser,
    "SSL Labs Scan": SSLlabsParser,
    "Trufflehog Scan": TruffleHogJSONParser,
    "Clair Klar Scan": ClairKlarParser,
    "Gosec Scanner": GosecScannerParser,
    "Trustwave Scan (CSV)": TrustwaveUploadCsvParser,
    "Netsparker Scan": NetsparkerParser,
    "PHP Security Audit v2": PhpSecurityAuditV2,
    "Acunetix Scan": AcunetixScannerParser,
    "Fortify Scan": FortifyXMLParser,
    "SonarQube Scan": SonarQubeHtmlParser,
    "SonarQube Scan detailed": SonarQubeHtmlParser,
    SCAN_SONARQUBE_API: SonarQubeApiImporter,
    "MobSF Scan": MobSFParser,
    "AWS Scout2 Scan": AWSScout2Parser,
    "AWS Prowler Scan": AWSProwlerParser,
    "Brakeman Scan": BrakemanScanParser,
    "SpotBugs Scan": SpotbugsXMLParser,
    "Safety Scan": SafetyParser,
    "DawnScanner Scan": DawnScannerParser,
    "Anchore Engine Scan": AnchoreEngineScanParser,
    "Bundler-Audit Scan": BundlerAuditParser,
    "Twistlock Image Scan": TwistlockParser,
    "IBM AppScan DAST": IbmAppScanDASTXMLParser,
    "Kiuwan Scan": KiuwanCSVParser,
    "Blackduck Hub Scan": BlackduckHubCSVParser,
    "Sonatype Application Scan": SonatypeJSONParser,
    "Openscap Vulnerability Scan": OpenscapXMLParser,
    "Immuniweb Scan": ImmuniwebXMLParser,
    "Wapiti Scan": WapitiXMLParser,
    "Cobalt.io Scan": CobaltCSVParser,
    "Mozilla Observatory Scan": MozillaObservatoryJSONParser,
    "Whitesource Scan": WhitesourceJSONParser,
    "Microfocus Webinspect Scan": MicrofocusWebinspectXMLParser,
    "Wpscan": WpscanJSONParser,
    "Sslscan": SslscanXMLParser,
    "JFrog Xray Scan": XrayJSONParser,
    "Sslyze Scan": SslyzeXmlParser,
    "Testssl Scan": TestsslCSVParser,
    "Hadolint Dockerfile check": HadolintParser,
    "Aqua Scan": AquaJSONParser,
    "Xanitizer Scan": XanitizerXMLParser,
    "Trivy Scan": TrivyParser,
}


def requires_file(scan_type):
    return (
            scan_type and scan_type != SCAN_SONARQUBE_API
    )


def handles_active_verified_statuses(scan_type):
    return scan_type in [
        SCAN_GENERIC_FINDING, SCAN_SONARQUBE_API
    ]


def import_parser_factory(file, test, active, verified, scan_type=None):
    if scan_type is None:
        scan_type = test.test_type.name

    parser_class = SCANNERS.get(scan_type)

    if parser_class is None:
        raise ValueError('Unknown Test Type')

    call_args = []
    if requires_file(scan_type):
        call_args.append(file)
    call_args.append(test)
    if handles_active_verified_statuses(scan_type):
        call_args.append(active)
        call_args.append(verified)
    return parser_class(*call_args)
