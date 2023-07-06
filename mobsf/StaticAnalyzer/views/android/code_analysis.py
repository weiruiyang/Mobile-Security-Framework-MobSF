# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""
import json
import logging
from pathlib import Path
import os

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
        # code_rules_text = root / 'android' / 'rules' / 'android_rules_text_test.yaml'
        code_rules_text = root / 'android' / 'rules' / 'android_rules.txt'
        api_rules = root / 'android' / 'rules' / 'android_apis.yaml'
        niap_rules = root / 'android' / 'rules' / 'android_niap.yaml'
        code_findings = {}
        api_findings = {}
        email_n_file = []
        phone_n_file = []
        is_confusing = False
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
            assets_src = app_dir / 'assets'
            assets_src = assets_src.as_posix() + '/'
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
        # logger.warning('weiry:code_analysis:code_findings =========')
        code_findings = scan(
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)

        codeRulesText(code_findings, code_rules_text)

        # logger.warning('weiry:code_analysis:code_findings: %s', code_findings)
        # logger.warning('weiry:code_analysis:api_findings =========')
        api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        # NIAP Scan
        # logger.warning('weiry:code_analysis:niap_findings =========')
        niap_findings = niap_scan(
            niap_rules.as_posix(),
            {'.java', '.xml'},
            [src],
            manifest_file,
            None)
        # logger.warning('weiry:code_analysis:niap_findings : %s', niap_findings)
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
                urls, urls_nf, emails_nf, phone_nf = url_n_email_extract(
                    content, relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
                phone_n_file.extend(phone_nf)

        if assets_src:
            for pfile in Path(assets_src).rglob('*'):
                if pfile.is_file():
                    content = None
                    try:
                        content = pfile.read_text('utf-8', 'ignore')
                        # Certain file path cannot be read in windows
                    except Exception:
                        continue
                    relative_java_path = 'assets'
                    urls, urls_nf, emails_nf, phone_nf = url_n_email_extract(
                        content, relative_java_path)
                    url_list.extend(urls)
                    url_n_file.extend(urls_nf)
                    email_n_file.extend(emails_nf)
                    phone_n_file.extend(phone_nf)

        if manifest_file:
            urls, urls_nf, emails_nf, phone_nf = url_n_email_extract(
                manifest_file, 'manifest')
            url_list.extend(urls)
            url_n_file.extend(urls_nf)
            email_n_file.extend(emails_nf)
            phone_n_file.extend(phone_nf)

        logger.info('Finished Code Analysis, Email and URL Extraction')

        sum = 0
        n = 0
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                try:
                    sum = sum + 1
                    if pfile.is_file():
                        filename_str = str(pfile.name)
                        filename_no_ext, file_extension = os.path.splitext(filename_str)
                        filename_str = filename_no_ext
                        # logger.warning('weiry:code_analysis:filename_str : %s', filename_str)
                        if '$' in filename_str:
                            filename_str = filename_str.split('$')[0]
                        if len(filename_str) < 3:
                            n = n + 1
                except Exception:
                    continue
        b = 0
        if sum != 0:
            b = n / sum * 100
            if b > 60:
                is_confusing = True
        logger.info('Finished Code Is it confusing:%s/%s=%s , %s', n, sum, b, is_confusing)

        code_an_dic = {
            'api': api_findings,
            'findings': code_findings,
            'niap': niap_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
            'phones': phone_n_file,
            'is_confusing': is_confusing,
        }
        # logger.warning('weiry:code_analysis:code_an_dic : %s', code_an_dic)
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')


def codeRulesText(code_findings, code_rules_text):
    # logger.warning('weiry:code_analysis:code_findings android_rules.txt =========')
    with open(code_rules_text.as_posix(), 'r') as file:
        content = file.read()
        # logger.warning('weiry:code_analysis:code_findings android_rules.text: %s', content)
        rules_json = json.loads(content)
        for ob_class in rules_json:
            # logger.info('weiry:code_findings ob_class: %s', ob_class)
            ob_class_id_ = ob_class["id"]
            # logger.info('weiry:code_findings ob_class_id_: %s', ob_class_id_)
            type_ = ob_class["type"]
            # logger.info('weiry:code_findings type_: %s', type_)
            if "all" == type_:
                is_all = True
                if code_findings.get(ob_class_id_):
                    # logger.info('weiry:code_findings code_findings[ob_class_id_]: %s', code_findings[ob_class_id_])
                    for id_s in ob_class["ids"]:
                        # logger.info('weiry:code_findings id_s: %s', id_s)
                        if code_findings.get(id_s):
                            # logger.info('weiry:code_findings code_findings[id_s]: %s', code_findings[id_s])
                            del code_findings[id_s]
                        else:
                            is_all = False

                # logger.info('weiry:code_findings is_all: %s', is_all)
                if not is_all:
                    del code_findings[ob_class_id_]
            elif ("not" == type_):
                if code_findings.get(ob_class_id_):
                    # logger.info('weiry:code_findings code_findings[ob_class_id_]: %s', code_findings[ob_class_id_])
                    for id_s in ob_class["ids"]:
                        # logger.info('weiry:code_findings id_s: %s', id_s)
                        if code_findings.get(id_s):
                            # logger.info('weiry:code_findings code_findings[id_s]: %s', code_findings[id_s])
                            files_ = code_findings[id_s]["files"]
                            for key, value in files_.items():
                                if code_findings[ob_class_id_]["files"].get(key):
                                    del code_findings[ob_class_id_]["files"][key]
                            del code_findings[id_s]
                    num_keys = len(code_findings[ob_class_id_]["files"])
                    if num_keys <= 0:
                        del code_findings[ob_class_id_]
