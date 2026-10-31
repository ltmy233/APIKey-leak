import csv
import json
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest

from keyaudit.models import parse_target
from keyaudit.providers import Provider, PROVIDERS
from keyaudit.rules import detect
from keyaudit.reports import export_report
from keyaudit.models import Finding


# Synthetic fixture, never sent to any provider.
SECRET = 'sk-proj-' + 'A9kLm7Qp2Zv5Rn8X' * 5


class TargetTests(unittest.TestCase):
    def test_repository_url_and_git_suffix_normalize(self):
        for text in (' owner/repo ', 'https://github.com/owner/repo.git', 'github.com/owner/repo/'):
            self.assertEqual(parse_target(text, 'repository'), 'owner/repo')

    def test_user_url_normalizes(self):
        self.assertEqual(parse_target('https://github.com/ltmy233/', 'user'), 'ltmy233')

    def test_rejects_external_hosts_and_query_injection(self):
        for text in ('https://evil.test/a/b', 'https://github.com.evil.test/a/b',
                     'https://user@github.com/a/b', 'a/b?x=1', 'a/../b',
                     'https://github.com/a/b/tree/main', '', 'user:other/repo'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_target(text, 'repository')

    def test_user_mode_rejects_repository(self):
        with self.assertRaises(ValueError):
            parse_target('owner/repo', 'user')

    def test_malformed_url_port_is_reported_as_validation_error(self):
        with self.assertRaises(ValueError):
            parse_target('https://[broken/owner/repo', 'repository')


class DetectionTests(unittest.TestCase):
    def test_each_json_assignment_uses_its_own_provider_context(self):
        openai = 'sk-' + 'N8pQ3rT6vW2xY9zA' * 2
        deepseek = 'sk-' + 'a7b8c9d0' * 4
        for pairs in ((('OPENAI_API_KEY', openai), ('DEEPSEEK_API_KEY', deepseek)),
                      (('DEEPSEEK_API_KEY', deepseek), ('OPENAI_API_KEY', openai))):
            with self.subTest(order=pairs[0][0]):
                items = detect(json.dumps(dict(pairs)), 'a/b', 'config.json', 'main',
                               [Provider.OPENAI, Provider.DEEPSEEK])
                self.assertEqual([f.provider for f in items],
                                 ['OpenAI' if name.startswith('OPENAI') else 'DeepSeek' for name, _ in pairs])

    def test_generic_json_assignments_do_not_inherit_previous_vendor(self):
        text = json.dumps({'MISTRAL_API_KEY': 'Q8rT4yUi9Op6As2Dz7Vx5Wn3',
                           'DEEPINFRA_API_KEY': 'L9mN8bV7cX6zA5sD4fG3hJ2k'})
        items = detect(text, 'a/b', 'config.json', 'main', [Provider.MISTRAL, Provider.DEEPINFRA])
        self.assertEqual([f.provider for f in items], ['Mistral', 'DeepInfra'])

    def test_unrelated_assignment_does_not_supply_generic_vendor_context(self):
        text = 'MISTRAL_MODEL="small"; build_id="Q8rT4yUi9Op6As2Dz7Vx5Wn3"'
        self.assertEqual(detect(text, 'a/b', 'config.py', 'main', [Provider.MISTRAL]), [])

    def test_shared_definitions_cover_existing_providers(self):
        self.assertEqual(len(PROVIDERS), 19)
        self.assertIn(Provider.OPENAI, PROVIDERS)

    def test_reports_line_mask_fingerprint_but_not_secret(self):
        findings = detect('title\nOPENAI_API_KEY="' + SECRET + '"\n',
                          'owner/repo', '.env', 'main', [Provider.OPENAI])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.provider, 'OpenAI')
        self.assertEqual(len(finding.fingerprint), 64)
        self.assertTrue(finding.url.endswith('/.env#L2'))
        self.assertNotIn(SECRET, json.dumps(asdict(finding)))
        self.assertIn('…', finding.masked)

    def test_repeated_occurrences_keep_locations_without_pattern_duplicates(self):
        findings = detect(SECRET + '\n' + SECRET, 'a/b', 'config.py', 'main', [Provider.OPENAI])
        self.assertEqual([f.line for f in findings], [1, 2])
        self.assertEqual(findings[0].fingerprint, findings[1].fingerprint)

    def test_generic_tokens_require_provider_assignment_context(self):
        token = 'q7Dz9Mp4Hv2Ks6Nb8Ra3Wc5Y'
        self.assertEqual(detect('build_id="' + token + '"', 'a/b', 'x', 'main', [Provider.MISTRAL]), [])
        items = detect('MISTRAL_API_KEY="' + token + '"', 'a/b', 'x', 'main', [Provider.MISTRAL])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].provider, 'Mistral')

    def test_selected_providers_do_not_capture_other_prefixed_keys(self):
        self.assertEqual(detect(SECRET, 'a/b', 'x', 'main', [Provider.DEEPSEEK]), [])

    def test_sk_vendor_not_guessed_without_context(self):
        token = 'sk-' + 'd7e8f90a' * 4
        items = detect(token, 'a/b', 'x', 'main', [Provider.OPENAI, Provider.DEEPSEEK])
        self.assertEqual(len(items), 1)
        self.assertIn('待确认', items[0].provider)

    def test_placeholders_are_ignored(self):
        self.assertEqual(detect('sk-proj-' + 'x' * 90, 'a/b', 'x', 'main', [Provider.OPENAI]), [])

    def test_special_paths_are_url_encoded(self):
        item = detect(SECRET, 'a/b', 'folder/my #config.py', 'release/v1', [Provider.OPENAI])[0]
        self.assertIn('release%2Fv1/folder/my%20%23config.py#L1', item.url)


class ReportTests(unittest.TestCase):
    def test_partial_export_records_coverage_and_cancelled_state(self):
        items = detect(SECRET, 'a/b', '.env', 'main', [Provider.OPENAI])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'partial.json'
            export_report(path, items, coverage={'state': 'cancelled', 'files_scanned': 2, 'files_total': 10})
            data = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(data['coverage']['state'], 'cancelled')
            self.assertEqual(data['coverage']['files_scanned'], 2)
            for suffix in ('.csv', '.txt'):
                path = Path(tmp) / ('partial' + suffix)
                export_report(path, items, coverage={'state': 'cancelled'})
                self.assertIn('cancelled', path.read_text(encoding='utf-8-sig'))

    def test_secret_in_path_repository_or_ref_is_not_retained_or_exported(self):
        findings = detect(SECRET, 'owner/' + SECRET, 'configs/' + SECRET + '.env', SECRET, [Provider.OPENAI])
        self.assertEqual(len(findings), 1)
        item = findings[0]
        self.assertNotIn(SECRET, repr(item))
        self.assertEqual(item.url, '')
        with tempfile.TemporaryDirectory() as tmp:
            for suffix in ('.json', '.csv', '.txt'):
                path = Path(tmp) / ('safe' + suffix)
                export_report(path, findings)
                self.assertNotIn(SECRET, path.read_text(encoding='utf-8-sig'))

    def test_record_boundary_masks_secret_in_alternate_blob_path(self):
        from dataclasses import replace
        item = detect(SECRET, 'owner/repo', 'config.py', 'main', [Provider.OPENAI])[0]
        item = replace(item, path=SECRET + '.env')
        self.assertNotIn(SECRET, repr(item))
        self.assertEqual(item.url, '')

    def test_all_formats_exclude_raw_secrets(self):
        findings = detect(SECRET, 'a/b', '.env', 'main', [Provider.OPENAI])
        with tempfile.TemporaryDirectory() as tmp:
            for suffix in ('.json', '.csv', '.txt'):
                path = Path(tmp) / ('report' + suffix)
                export_report(path, findings)
                content = path.read_text(encoding='utf-8-sig')
                self.assertNotIn(SECRET, content)
                self.assertIn(findings[0].fingerprint, content)
            payload = json.loads((Path(tmp) / 'report.json').read_text(encoding='utf-8-sig'))
            self.assertEqual(payload['findings'][0]['line'], 1)

    def test_csv_prevents_formula_injection_from_file_name(self):
        findings = detect(SECRET, 'a/b', '=HYPERLINK("bad")', 'main', [Provider.OPENAI])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.csv'
            export_report(path, findings)
            with path.open(encoding='utf-8-sig', newline='') as handle:
                rows = list(csv.reader(handle))
            self.assertIn('\'=HYPERLINK("bad")', rows[1])


if __name__ == '__main__':
    unittest.main()
