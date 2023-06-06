# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import filename_from_path
from mobsf.StaticAnalyzer.views.common.shared_func import (
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.sast_engine import (
    niap_scan,
    scan,
)

logger = logging.getLogger(__name__)


def code_analysis(app_dir, typ, manifest_file):
    """Perform the code analysis."""
    try:
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        code_rules = root / 'android' / 'rules' / 'android_rules.yaml'
        code_rules_webview_remove_javascript_interface = root / 'android' / 'rules' / 'android_rules_webview_remove_javascript_interface.yaml'
        api_rules = root / 'android' / 'rules' / 'android_apis.yaml'
        niap_rules = root / 'android' / 'rules' / 'android_niap.yaml'
        code_findings = {}
        api_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        src = src.as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        logger.info('Code Analysis Started on - %s',
                    filename_from_path(src))
        # Code and API Analysis
        logger.warning('weiry:code_analysis:code_findings =========')
        code_findings = scan(
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)

        code_findings_webview_remove_javascript_interface = scan(
            code_rules_webview_remove_javascript_interface.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)

        logger.warning('weiry:code_analysis:code_findings_webview_remove_javascript_interface: %s', code_findings_webview_remove_javascript_interface)
        if code_findings_webview_remove_javascript_interface['android_webview_remove_javascript_interface']:
            if code_findings_webview_remove_javascript_interface['android_webview_accessibilitytraversal'] \
                    and code_findings_webview_remove_javascript_interface['android_webview_accessibility'] \
                    and code_findings_webview_remove_javascript_interface['android_webview_searchboxjavabridge']:
                pass
            else:
                code_findings['android_webview_remove_javascript_interface'] = code_findings_webview_remove_javascript_interface['android_webview_remove_javascript_interface']


        logger.warning('weiry:code_analysis:code_findings: %s', code_findings)
        logger.warning('weiry:code_analysis:api_findings =========')
        api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        # NIAP Scan
        logger.warning('weiry:code_analysis:niap_findings =========')
        niap_findings = niap_scan(
            niap_rules.as_posix(),
            {'.java', '.xml'},
            [src],
            manifest_file,
            None)
        logger.warning('weiry:code_analysis:niap_findings : %s', niap_findings)
        # Extract URLs and Emails
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                content = None
                try:
                    content = pfile.read_text('utf-8', 'ignore')
                    # Certain file path cannot be read in windows
                except Exception:
                    continue
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    content, relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
        logger.info('Finished Code Analysis, Email and URL Extraction')
        code_an_dic = {
            'api': api_findings,
            'findings': code_findings,
            'niap': niap_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
        }
        logger.warning('weiry:code_analysis:code_an_dic : %s', code_an_dic)
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')
