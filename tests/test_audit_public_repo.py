import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_public_repo.py"
SPEC = importlib.util.spec_from_file_location("audit_public_repo", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(audit)


class SecretAssignmentTests(unittest.TestCase):
    def assert_detected(self, prefix: bytes, value: bytes = b"a" * 24) -> None:
        self.assertTrue(audit.scan_blob("fixture", prefix + value))

    def test_detects_unquoted_yaml_secret(self) -> None:
        self.assert_detected(b"client_secret: ")

    def test_detects_yaml_secret_after_anchor(self) -> None:
        key = b"pass" + b"word: &shared "
        self.assert_detected(key)

    def test_detects_yaml_secret_after_standard_tags(self) -> None:
        key = b"pass" + b"word: "
        for tag in (b"!!str ", b"!<tag:yaml.org,2002:str> "):
            with self.subTest(tag=tag):
                self.assert_detected(key + tag)

    def test_detects_inline_yaml_passphrase(self) -> None:
        key = b"pass" + b"word: "
        self.assert_detected(key, b"correct horse battery staple 1234")

    def test_detects_unquoted_ini_passphrase(self) -> None:
        key = b"pass" + b"word = "
        self.assertTrue(
            audit.scan_blob("fixture", key + b"correct horse battery staple 1234")
        )

    def test_detects_continued_yaml_plain_secret(self) -> None:
        key = b"pass" + b"word: "
        fixture = key + b"correct horse\n  battery staple 1234\nnext: value"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_ignores_comments_in_yaml_plain_continuations(self) -> None:
        key = b"pass" + b"word: "
        fixture = key + b"disabled\n  value # this explanatory comment is intentionally very long"
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_unquoted_environment_secret(self) -> None:
        self.assert_detected(b"ADERESO_API_KEY=")

    def test_detects_shell_declaration_credentials(self) -> None:
        key = b"PASS" + b"WORD=hunter2"
        for prefix in (b"readonly ", b"local ", b"declare -x ", b"typeset -gx "):
            with self.subTest(prefix=prefix):
                self.assertTrue(audit.scan_blob("fixture", prefix + key))

    def test_detects_compose_environment_list_credential(self) -> None:
        key = b"environment:\n  - PASS" + b"WORD=hunter2"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_dockerfile_credentials(self) -> None:
        key = b"PASS" + b"WORD"
        fixtures = (
            b"ARG " + key + b"=hunter2",
            b"ENV " + key + b"=hunter2",
            b"ENV " + key + b" hunter2",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_later_dockerfile_env_pair(self) -> None:
        key = b"ENV FOO=bar PASS" + b"WORD=hunter2"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_credential_value_suffix(self) -> None:
        fixtures = (
            b"SECRET_VAL" + b"UE=hunter2",
            b"CLIENT_SECRET_VAL" + b"UE=hunter2",
            b"apiKeyVal" + b"ue=hunter2",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_password_aliases(self) -> None:
        for key in (b"PASSWD", b"DB_PASS", b"DB_PWD"):
            with self.subTest(key=key):
                self.assertTrue(audit.scan_blob("fixture", key + b"=hunter2"))
        self.assertFalse(audit.scan_blob("fixture", b"compass=enabled"))

    def test_detects_rails_secret_key_base(self) -> None:
        key = b"SECRET_KEY_BA" + b"SE=hunter2"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_secret_key_names(self) -> None:
        fixtures = (
            b"secretK" + b"ey: hunter2",
            b"secret_k" + b"ey: hunter2",
            b"apiSecretK" + b"ey: hunter2",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_quoted_credential(self) -> None:
        key = b"pass" + b'word = "hunter2"'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_backtick_authorization_headers(self) -> None:
        fixtures = (
            b"const headers = { Authorization: `Bea"
            + b"rer abcdefghijklmnop` };",
            b"const headers = { Authorization: `Bas" + b"ic dXNlcjpwYXNz` };",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_authorization_header_setter_values(self) -> None:
        bearer = b'headers.set("Authoriz' + b'ation", "Bea' + b'rer abcd")'
        basic = b"headers.append('Authoriz" + b"ation', 'Bas" + b"ic dXNlcjpwYXNz')"
        for fixture in (bearer, basic):
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_quoted_authorization_mapping_key(self) -> None:
        key = b'{"Authoriz' + b'ation": "Bea' + b'rer abcdefghijklmnop"}'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_concatenated_authorization_literals(self) -> None:
        key = b"Authoriz" + b'ation: "Bea' + b'rer " + "abcdefghijklmnop"'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_javascript_compound_assignments(self) -> None:
        key = b"pass" + b"word "
        fixtures = (
            key + b'||= "' + b"a" * 24 + b'"',
            key + b'??= "' + b"a" * 24 + b'"',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_dotted_api_key_property(self) -> None:
        self.assert_detected(b"adereso.api.key=")

    def test_detects_unquoted_secret_before_comment(self) -> None:
        self.assert_detected(b"pass" + b"word: ", b"a" * 24 + b" # never commit")

    def test_detects_unquoted_padded_base64_secret(self) -> None:
        self.assert_detected(b"CLIENT_SEC" + b"RET=", b"YWJjZGVmZ2hpamtsbW5vcA==")

    def test_detects_compound_aws_secret_name(self) -> None:
        self.assert_detected(b"aws_sec" + b"ret_access_key = ", b"a" * 40)

    def test_detects_secret_before_shell_separator(self) -> None:
        for separator in (b"; run-client", b" && run-client", b" | run-client"):
            with self.subTest(separator=separator):
                self.assert_detected(
                    b"export ADERESO_API_" + b"KEY=", b"a" * 24 + separator
                )

    def test_preserves_literal_hash_in_unquoted_secret(self) -> None:
        self.assert_detected(b"PASS" + b"WORD=", b"abcdefghijklmno#pqrstuvwxyz")

    def test_detects_quoted_secret(self) -> None:
        self.assert_detected(b'access_to' + b'ken: "', b"a" * 24 + b'"')

    def test_detects_toml_multiline_quoted_secrets(self) -> None:
        key = b"pass" + b"word = "
        for delimiter in (b'"""', b"'''"):
            with self.subTest(delimiter=delimiter):
                fixture = key + delimiter + b"a" * 24 + delimiter
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_toml_multiline_includes_quotes_before_closing_delimiter(self) -> None:
        key = b"pass" + b'word = """'
        fixture = key + b"abcdefghijklmn" + b'"""""'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_toml_multiline_credential(self) -> None:
        key = b"pass" + b'word = """\nhunter2\n"""'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_safe_reference_in_toml_multiline_string(self) -> None:
        key = b"pass" + b'word = """'
        fixture = key + b"${{ secrets.PASSWORD }}" + b'"""'
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_toml_multiline_stops_at_first_delimiter(self) -> None:
        fixture = (
            b'password = """disabled"""\n'
            b'description = """this unrelated description is intentionally long"""'
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_quoted_padded_base64_secret(self) -> None:
        self.assert_detected(b'api_' + b'key: "', b"YWJjZGVmZ2hpamtsbW5vcA==\"")

    def test_detects_standard_json_secret(self) -> None:
        self.assert_detected(b'{"client_sec' + b'ret":"', b"a" * 24 + b'"}')

    def test_detects_secret_in_non_yaml_source(self) -> None:
        key = b"pass" + b"word: "
        fixture = b"const config = { " + key + b"a" * 24 + b" };"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_colon_assignments(self) -> None:
        key = b"pass" + b"word: "
        fixtures = (
            b"const config = { " + key + b"process.env.PASSWORD };",
            b"const config = { " + key + b'os.getenv("PASSWORD") };',
            b"const config = { " + key + b"get_secret_from_vault() };",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_colon_getter_literal_fallback(self) -> None:
        key = b"pass" + b'word: os.getenv(PASSWORD_ENV, "hunter2")'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_multiline_template_literal_colon_assignment(self) -> None:
        key = b"pass" + b"word: `\nhunter2\n`"
        fixture = b"const config = { " + key + b" };"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_multiline_template_literal_colon_assignment(self) -> None:
        key = b"pass" + b"word: `\n${PASSWORD}\n`"
        fixture = b"const config = { " + key + b" };"
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_noncredential_sensitive_substrings(self) -> None:
        fixture = (
            b"token_url: https://example.com/oauth/token\n"
            b"tokenizer: standard\npasswordPolicy: strong"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_bracketed_property_assignment(self) -> None:
        key = b'config["pass' + b'word"] = "'
        fixture = key + b"a" * 24 + b'";'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_equals_assignments(self) -> None:
        key = b"pass" + b"word = "
        fixtures = (
            key + b'os.getenv("DATABASE_PASSWORD")',
            b"const " + key + b"process.env.PASSWORD;",
            key + b"get_secret_from_vault()",
            key + b'os.environ["PASSWORD"]',
            key + b'os.environ.get("PASSWORD")',
            key + b'config.get("password")',
            key + b'config["password"]',
            key + b"config.password",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_generic_getter_fallback(self) -> None:
        key = b"pass" + b'word = config.get("password", "hunter2")'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_parenthesized_multiline_literal_assignment(self) -> None:
        key = b"pass" + b"word = (\n    \""
        fixture = key + b"a" * 24 + b'"\n)'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_multiline_template_literal_assignment(self) -> None:
        key = b"const pass" + b"word = `\nhunter2\n`"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_parenthesized_multiline_environment_reference(self) -> None:
        key = b"pass" + b"word = (\n    "
        fixture = key + b"process.env.PASSWORD\n)"
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_multiline_environment_getter_call(self) -> None:
        key = b"pass" + b"word = os.getenv(\n    \"PASSWORD\"\n)"
        self.assertFalse(audit.scan_blob("fixture", key))

    def test_detects_multiline_environment_getter_fallback(self) -> None:
        key = b"pass" + b"word = os.environ.get(\n    \"PASSWORD\",\n    \"hunter2\"\n)"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_typescript_environment_reference(self) -> None:
        key = b"const pass" + b"word: string = "
        self.assertFalse(audit.scan_blob("fixture", key + b"process.env.PASSWORD;"))

    def test_detects_typescript_literal_assignment(self) -> None:
        key = b"const pass" + b'word: string = "hunter2";'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_python_annotated_literal_assignment(self) -> None:
        key = b"pass" + b'word: str = "hunter2"'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_type_only_sensitive_annotations(self) -> None:
        key = b"pass" + b"word"
        fixtures = (
            b"def login(" + key + b": str):\n    pass",
            b"def login(\n    " + key + b": str,\n):\n    pass",
            b"function login(" + key + b": string) {}",
            b"const login = (" + key + b": string) => true",
            b"interface Config { " + key + b": string; }",
            b"interface Config { " + key + b": () => string; }",
            key + b": str",
            b"class Config:\n    " + key + b": str",
            key + b": Optional[str]",
            key + b": str | None",
            key + b": SecretStr",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_literal_getenv_fallback(self) -> None:
        key = b"pass" + b'word = os.getenv("PASSWORD", "'
        fixture = key + b"a" * 24 + b'")'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_vault_getter_fallback(self) -> None:
        key = b"pass" + b'word = get_secret_from_vault("path", default="hunter2")'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_positional_vault_getter_fallback(self) -> None:
        key = b"pass" + b'word = get_secret_from_vault("path", "hunter2")'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_non_default_named_vault_option(self) -> None:
        key = b"pass" + b'word = get_secret_from_vault("path", version="latest")'
        self.assertFalse(audit.scan_blob("fixture", key))

    def test_detects_later_shell_environment_assignment(self) -> None:
        key = b"PASS" + b"WORD=hunter2"
        fixtures = (
            b"FOO=bar " + key + b" command",
            b"export FOO=bar " + key,
            b"declare -x FOO=bar " + key,
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_later_shell_environment_reference(self) -> None:
        key = b"PASS" + b"WORD=${PASSWORD}"
        self.assertFalse(
            audit.scan_blob("fixture", b"FOO=bar " + key + b" command")
        )

    def test_detects_getenv_fallback_after_nonliteral_key(self) -> None:
        key = b"pass" + b'word = os.getenv(PASSWORD_ENV, "hunter2")'
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_concatenated_string_secret(self) -> None:
        key = b"pass" + b'word: "'
        fixture = (
            b"const config = { "
            + key
            + b'abcdefgh" + "ijklmnop" + "qrstuvwx" };'
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_concatenated_equals_secret(self) -> None:
        key = b"pass" + b'word = "'
        fixture = key + b'abcdefgh" + "ijklmnop" + "qrstuvwx"'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_implicitly_concatenated_equals_secret(self) -> None:
        key = b"pass" + b'word = "'
        fixture = key + b'abcdefgh" "ijklmnop" "qrstuvwx"'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_concatenated_call_argument_secret(self) -> None:
        key = b"pass" + b'word: String("'
        fixture = (
            b"const config = { "
            + key
            + b'abcdefgh" + "ijklmnop" + "qrstuvwx") };'
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_concatenated_indirect_references(self) -> None:
        key = b"pass" + b'word: "'
        fixture = b"const config = { " + key + b'${PASS}" + "${WORD}" };'
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_secret_literal_inside_call_expression(self) -> None:
        key = b"pass" + b"word: "
        fixture = b"const config = { " + key + b'String("' + b"a" * 24 + b'") };'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_javascript_template_literal_assignment(self) -> None:
        key = b"pass" + b"word = `"
        fixture = b"const " + key + b"a" * 24 + b"`;"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_javascript_template_literal(self) -> None:
        key = b"pass" + b"word = `"
        fixture = b"const " + key + b"${PASSWORD}`;"
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_call_expression(self) -> None:
        key = b"pass" + b"word: "
        fixtures = (
            b"const config = { " + key + b"getPasswordFromEnvironment() };",
            b"const config = { " + key + b'String("${PASSWORD}") };',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_secret_inside_source_string(self) -> None:
        key = b"pass" + b"word: "
        fixture = b'const fixture = "' + key + b"a" * 24 + b'";'
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_non_secret_multiline_source_fixture(self) -> None:
        fixture = b'const fixture = "secret' + b'KeyRef:\\n  name: runtime";'
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_json_secret_with_escaped_quote(self) -> None:
        key = b'{"pass' + b'word":"'
        value = b'abc\\"' + b"defghijklmnopqrstuvwxyz" + b'"}'
        self.assertTrue(audit.scan_blob("fixture", key + value))

    def test_detects_yaml_block_scalar_secret(self) -> None:
        for marker in (b">-", b"|", b"|2-"):
            with self.subTest(marker=marker):
                fixture = b"client_sec" + b"ret: " + marker + b"\n  " + b"a" * 24
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_yaml_block_scalar_secret_after_node_properties(self) -> None:
        key = b"pass" + b"word: "
        for properties in (b"&shared ", b"!!str ", b"!<tag:example.test,2026:str> "):
            with self.subTest(properties=properties):
                fixture = key + properties + b">-\n  " + b"a" * 24
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_yaml_block_scalar_secret_in_sequence_mapping(self) -> None:
        key = b"pass" + b"word"
        fixture = b"items:\n  - " + key + b": >-\n      " + b"a" * 24
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_sequence_block_scalar_stops_at_sibling_mapping_key(self) -> None:
        key = b"pass" + b"word"
        fixture = (
            b"items:\n  - " + key + b": >-\n      disabled\n"
            b"    description: this unrelated description is intentionally long"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_multiline_yaml_block_passphrase(self) -> None:
        key = b"pass" + b"word: >-\n"
        fixture = key + b"  correct horse\n  battery staple 1234\nnext: value\n"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_yaml_block_password(self) -> None:
        key = b"pass" + b"word: |-\n  hunter2"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_detects_single_quoted_secret_with_special_characters(self) -> None:
        prefix = b"to" + b"ken='"
        value = b"a!b@c:d?e=f+g/h_i-j" + b"'"
        self.assert_detected(prefix, value)

    def test_detects_yaml_single_quoted_secret_with_doubled_quote(self) -> None:
        key = b"pass" + b"word: '"
        value = b"abc''defghijklmnopqrstuvwxyz'"
        self.assert_detected(key, value)

    def test_detects_multiline_yaml_quoted_secrets(self) -> None:
        key = b"pass" + b"word: "
        fixtures = (
            key + b'"abcdefghij\n  klmnopqrstuvwx"',
            key + b"'abcdefghij\n  klmnopqrstuvwx'",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_credentials_in_non_http_urls(self) -> None:
        fixtures = (
            b"postgresql://user:" + b"a" * 24 + b"@host/db",
            b"redis://user:" + b"a" * 24 + b"@host/0",
            b"redis://:" + b"a" * 24 + b"@host/0",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_indirect_password_in_connection_url(self) -> None:
        fixtures = (
            b"DATABASE_URL=postgresql://user:${DB_PASSWORD}@host/db",
            b"DATABASE_URL=postgresql://user:$DB_PASSWORD@host/db",
            b"DATABASE_URL=postgresql://user:${{ secrets.DB_PASSWORD }}@host/db",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_long_identifier_without_secret_keyword_is_safe(self) -> None:
        self.assertFalse(audit.scan_blob("fixture", b"a" * 100_000))

    def test_allows_documentation_placeholder(self) -> None:
        self.assertFalse(audit.scan_blob("fixture", b"ADERESO_API_KEY=your_api_key_here"))

    def test_allows_yaml_documentation_placeholders(self) -> None:
        key = b"pass" + b"word: "
        fixtures = (
            key + b"your_credential_here",
            key + b">-\n  your_credential_here",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_yaml_alias_assigned_secret(self) -> None:
        key = b"pass" + b"word: *shared"
        fixtures = (
            b"neutral: &shared correct horse battery staple 1234\n" + key,
            b"neutral: &shared >-\n  correct horse battery staple 1234\n" + key,
            b'neutral: &shared "correct horse\n  battery staple 1234"\n' + key,
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_prefixed_with_placeholder_word(self) -> None:
        key = b"pass" + b"word="
        for value in (
            b"example-REALCREDENTIAL1234567890",
            b"placeholder-REALCREDENTIAL1234567890",
            b"replace-me-but-actually-secret-1234",
            b"your_api_key_here_REALCREDENTIAL1234",
        ):
            with self.subTest(value=value):
                self.assertTrue(audit.scan_blob("fixture", key + value))

    def test_allows_environment_variable_references(self) -> None:
        key = b"api_" + b"key: "
        fixtures = (
            key + b"${ADERESO_API_KEY}",
            key + b"$ADERESO_API_KEY",
            key + b"$env:ADERESO_API_KEY",
            key + b"%ADERESO_API_KEY%",
            key + b'"{{ ADERESO_API_KEY }}"',
            key + b'"${{ secrets.ADERESO_API_KEY }}"',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_unquoted_github_and_template_references(self) -> None:
        key = b"pass" + b"word: "
        fixtures = (
            key + b"${{ secrets.PASSWORD }}",
            key + b"{{ PASSWORD }}",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_environment_reference_with_literal_fallback(self) -> None:
        key = b"api_" + b"key: "
        fixtures = (
            key + b"${ADERESO_API_KEY-" + b"a" * 24 + b"}",
            key + b"${ADERESO_API_KEY" + b":-" + b"a" * 24 + b"}",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_template_reference_with_literal_fallback(self) -> None:
        key = b"api_" + b'key: "'
        expression = b"${{ secrets.API_KEY || '" + b"a" * 24 + b"' }}\""
        self.assertTrue(audit.scan_blob("fixture", key + expression))

    def test_detects_basic_authorization_value(self) -> None:
        value = b"Authorization: Basic " + b"dXNlcjph" + b"a" * 24 + b"=="
        self.assertTrue(audit.scan_blob("fixture", value))

    def test_detects_short_authorization_values(self) -> None:
        fixtures = (
            b"Author" + b"ization: Basic " + b"dXNlcjpw",
            b"Author" + b"ization: Bearer " + b"abcd",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_pgp_private_key(self) -> None:
        fixture = b"-----BEGIN PGP PRIVATE " + b"KEY BLOCK-----\nsynthetic\n"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_environment_literals(self) -> None:
        name = b"PASS" + b"WORD"
        fixtures = (
            b"env:\n  - name: " + name + b"\n    value: " + b"a" * 24,
            b'env:\n  - "name": ' + name + b"\n    'value': " + b"a" * 24,
            b"env:\n  - {name: " + name + b", value: " + b"a" * 24 + b"}",
            b"env:\n  - &shared {name: " + name + b", value: " + b"a" * 24 + b"}",
            b"env:\n  - {name: " + name + b", value: 'abc''defghijklmnopqrstuvwxyz'}",
            b"env:\n  - {name: " + name + b", value: " + b"a" * 24 + b"} # production",
            b'env:\n  - {"name": "' + name + b'", "value": "' + b"a" * 24 + b'"}',
            b"env:\n  -\n    name: " + name + b"\n    value: " + b"a" * 24,
            b"env:\n  - value: '" + b"a" * 24 + b"'\n    name: " + name,
            b"env:\n  - name: " + name + b"\n    value: >-\n      " + b"a" * 24,
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_kubernetes_environment_literals(self) -> None:
        name = b"PASS" + b"WORD"
        fixtures = (
            b"env: [{name: " + name + b", value: hunter2}]",
            b"env:\n  - name: " + name + b"\n    value: short",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_environment_flow_sequence(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"env: [{name: " + name + b", value: " + b"a" * 24 + b"}]"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_nested_flow_environment_sequence(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"{kind: Pod, spec: {containers: [{name: app, env: [{name: "
            + name + b", value: " + b"a" * 24 + b"}]}]}}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_env_as_first_sequence_item_field(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"containers:\n  - env:\n      - name: " + name
            + b"\n        value: " + b"a" * 24
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_ignores_non_environment_name_value_sequence(self) -> None:
        fixture = (
            b"form_fields:\n  - name: password\n    value: " + b"a" * 24
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_kubernetes_environment_references(self) -> None:
        name = b"PASS" + b"WORD"
        fixtures = (
            b"env:\n  - name: " + name + b"\n    value: ${PASSWORD}",
            b"env:\n  - name: " + name + b"\n    valueFrom:\n      secretKeyRef:\n        name: runtime",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_kubernetes_environment_block_stops_at_sibling(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"env:\n  - name: " + name + b"\n    value: >-\n      ${PASSWORD}\n"
            b"    description: this unrelated description is intentionally long"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_environment_item_alias(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"shared: &shared\n  name: " + name + b"\n  value: " + b"a" * 24
            + b"\nenv:\n  - *shared"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_environment_merge_alias(self) -> None:
        name = b"PASS" + b"WORD"
        fixture = (
            b"shared: &shared\n  name: " + name + b"\n  value: " + b"a" * 24
            + b"\nenv:\n  - <<: *shared"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_secret_literals(self) -> None:
        kind = b"kind: " + b"Secret"
        encoded = b"dXNlcjphYmNkZWZnaGlqa2xtbm9wcQ=="
        fixtures = (
            kind + b"\ndata: { auth: " + encoded + b" }",
            kind + b"\ndata: { auth: " + encoded + b" } # production",
            kind + b"\ndata: {\n  auth: " + encoded + b"\n}",
            kind + b'\ndata: { "auth:primary": ' + encoded + b" }",
            kind + b"\ndata:\n  auth: " + encoded,
            kind + b'\n"data":\n  auth: ' + encoded,
            kind + b"\ndata: &shared\n  auth: " + encoded,
            b'"kind": Secret\ndata: { auth: ' + encoded + b" }",
            b"kind: !!str Secret\ndata: { auth: " + encoded + b" }",
            kind + b"\nstringData:\n  auth: 'correct horse battery staple'",
            kind + b"\nstringData:\n  auth: >-\n    correct horse battery staple",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_when_document_has_unknown_yaml_tag(self) -> None:
        fixture = (
            b"kind: Secret\ndata:\n  auth: c2VjcmV0\ncustom: !example value"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_traverses_secret_sibling_after_environment(self) -> None:
        fixture = (
            b"env: [{name: MODE, value: test}]\n"
            b"nested:\n  kind: Secret\n  data:\n    auth: c2VjcmV0\n"
            b"custom: !foo bar"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_retains_secret_before_malformed_yaml_document(self) -> None:
        fixture = b"kind: Secret\ndata:\n  auth: c2VjcmV0\n---\ninvalid: ["
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_inside_helm_control_block(self) -> None:
        opening = b"{{" + b"- if .Values.enabled }}"
        closing = b"{{" + b"- end }}"
        fixture = (
            opening
            + b"\nkind: Secret\ndata:\n  auth: c2VjcmV0\n"
            + closing
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_scans_yaml_document_after_malformed_document(self) -> None:
        fixture = (
            b"bad: [\n---\nkind: Secret\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_after_standalone_helm_action(self) -> None:
        action = b"{{" + b"- $x := .Values.x -}}"
        fixture = action + b"\nkind: Secret\ndata:\n  auth: c2VjcmV0"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_assigned_to_helm_variable(self) -> None:
        assignment = b"{{- $value := \"hunter2\" -}}"
        fixture = assignment + b"\nkind: Secret\nstringData:\n  password: {{ $value }}"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_scopes_reassigned_helm_variable_literals(self) -> None:
        fixture = (
            b"{{- $value := \"public-url\" -}}\nkind: ConfigMap\ndata: {}\n---\n"
            b"{{- $value := .Values.password -}}\nkind: Secret\nstringData:\n"
            b"  password: {{ $value }}"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_secret_with_inline_helm_expression(self) -> None:
        expression = b"{{" + b" .Values.name }}"
        fixture = (
            b"kind: Secret\nmetadata:\n  name: "
            + expression
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_helm_reference_as_secret_value(self) -> None:
        expressions = (
            b"{{" + b" PASSWORD }}",
            b"{{" + b" .Values.auth }}",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                fixture = b"kind: Secret\ndata:\n  auth: " + expression
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_literal_default_in_helm_secret_value(self) -> None:
        expression = b"{{" + b' .Values.auth | default "hunter2" }}'
        fixture = b"kind: Secret\nstringData:\n  auth: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_in_inline_helm_branch(self) -> None:
        opening = b"{{" + b" if .Values.enabled }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            opening
            + b"kind: Secret"
            + alternate
            + b"kind: ConfigMap"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_templated_secret_kind_value(self) -> None:
        opening = b"{{" + b" if .Values.secret }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind: "
            + opening
            + b"Secret"
            + alternate
            + b"ConfigMap"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_multiline_templated_secret_kind(self) -> None:
        opening = b"{{" + b" if .Values.secret }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind:\n"
            + opening
            + b"\n  Secret\n"
            + alternate
            + b"\n  ConfigMap\n"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_in_helm_with_branch(self) -> None:
        opening = b"{{" + b" with .Values.x }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind: "
            + opening
            + b"Secret"
            + alternate
            + b"ConfigMap"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_in_helm_else_if_branch(self) -> None:
        opening = b"{{" + b" if .Values.first }}"
        middle = b"{{" + b" else if .Values.secret }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind: "
            + opening
            + b"ConfigMap"
            + middle
            + b"Secret"
            + alternate
            + b"ConfigMap"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_removes_inline_helm_comment(self) -> None:
        comment = b"{{" + b"/* comment */}}"
        fixture = b"kind: " + comment + b"Secret\ndata:\n  auth: c2VjcmV0"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_nested_helm_secret_branch(self) -> None:
        outer = b"{{" + b" if .Values.enabled }}"
        inner = b"{{" + b" if .Values.secret }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind: "
            + outer
            + inner
            + b"Secret"
            + alternate
            + b"ConfigMap"
            + closing
            + alternate
            + b"ConfigMap"
            + closing
            + b"\ndata:\n  auth: c2VjcmV0"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_enumerates_independent_helm_branch_combinations(self) -> None:
        opening_kind = b"{{" + b" if .Values.useSecret }}"
        opening_auth = b"{{" + b" if .Values.external }}"
        alternate = b"{{" + b" else }}"
        closing = b"{{" + b" end }}"
        fixture = (
            b"kind: "
            + opening_kind
            + b"Secret"
            + alternate
            + b"ConfigMap"
            + closing
            + b"\nstringData:\n  auth: "
            + opening_auth
            + b"${PASSWORD}"
            + alternate
            + b"hunter2"
            + closing
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_caps_helm_branch_expansion_without_false_positive(self) -> None:
        branches = b"\n".join(
            b"{{ if .Values.flag%d }}enabled: true{{ else }}enabled: false{{ end }}"
            % index
            for index in range(9)
        )
        self.assertFalse(audit.scan_blob("fixture", branches))

    def test_preserves_sensitive_helm_branch_past_expansion_cap(self) -> None:
        kind = (
            b"kind: {{ if .Values.config }}ConfigMap{{ else }}Secret{{ end }}\n"
            b"data:\n  auth: c2VjcmV0\n"
        )
        branches = b"\n".join(
            b"{{ if .Values.flag%d }}enabled%d: true{{ else }}enabled%d: false{{ end }}"
            % (index, index, index)
            for index in range(8)
        )
        self.assertTrue(audit.scan_blob("fixture", kind + branches))

    def test_preserves_correlated_helm_branches_past_expansion_cap(self) -> None:
        kind = b"kind: {{ if .Values.config }}ConfigMap{{ else }}Secret{{ end }}\n"
        neutral = b"\n".join(
            b"{{ if .Values.flag%d }}enabled%d: true{{ else }}enabled%d: false{{ end }}"
            % (index, index, index)
            for index in range(7)
        )
        auth = (
            b"\ndata:\n  auth: {{ if .Values.external }}${PASSWORD}"
            b"{{ else }}c2VjcmV0{{ end }}"
        )
        self.assertTrue(audit.scan_blob("fixture", kind + neutral + auth))

    def test_preserves_three_correlated_helm_branches(self) -> None:
        kind = b"kind: {{ if .Values.config }}ConfigMap{{ else }}Secret{{ end }}\n"
        neutral = b"\n".join(
            b"{{ if .Values.flag%d }}enabled%d: true{{ else }}enabled%d: false{{ end }}"
            % (index, index, index)
            for index in range(7)
        )
        field = b"\n{{ if .Values.meta }}metadata:{{ else }}data:{{ end }}\n"
        auth = (
            b"  auth: {{ if .Values.external }}${PASSWORD}"
            b"{{ else }}c2VjcmV0{{ end }}"
        )
        self.assertTrue(audit.scan_blob("fixture", kind + neutral + field + auth))

    def test_preserves_four_correlated_helm_branches(self) -> None:
        kind = b"kind: {{ if .Values.config }}ConfigMap{{ else }}Secret{{ end }}\n"
        neutral = b"\n".join(
            b"{{ if .Values.flag%d }}enabled%d: true{{ else }}enabled%d: false{{ end }}"
            % (index, index, index)
            for index in range(5)
        )
        field = b"\n{{ if .Values.meta }}metadata:{{ else }}data:{{ end }}\n"
        key = b"  {{ if .Values.note }}note{{ else }}auth{{ end }}: "
        value = (
            b"{{ if .Values.external }}${PASSWORD}{{ else }}c2VjcmV0{{ end }}"
        )
        self.assertTrue(
            audit.scan_blob("fixture", kind + neutral + field + key + value)
        )

    def test_allows_safe_helm_pipeline_in_sensitive_field(self) -> None:
        expression = b"{{" + b" .Values.password | quote }}"
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_non_value_helm_string_arguments(self) -> None:
        expressions = (
            b"{{" + b' required "set PASSWORD" .Values.password }}',
            b"{{" + b' printf "%s" .Values.password }}',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                fixture = b"kind: Secret\nstringData:\n  password: " + expression
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_helm_transformation_control_arguments(self) -> None:
        expressions = (
            b"{{" + b' trimPrefix "Bearer " .Values.password }}',
            b"{{" + b' join "," .Values.passwordParts }}',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                fixture = b"kind: Secret\nstringData:\n  password: " + expression
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_literal_helm_output_argument(self) -> None:
        expression = b"{{" + b' printf "%s" "abcdefghijklmnopqrstuvwx" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_only_helm_printf_format(self) -> None:
        expression = b"{{" + b' printf "hunter2" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_helm_pipeline_input(self) -> None:
        expression = b"{{" + b' "abcdefghijklmnopqrstuvwx" | b64enc }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_prefix_helm_function_argument(self) -> None:
        expression = b"{{" + b' quote "hunter2" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_helm_argument_containing_pipe(self) -> None:
        expression = b"{{" + b' quote "hunter2|fallback" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_helm_dig_default(self) -> None:
        expression = b"{{" + b' dig "auth" "c2VjcmV0" (dict) }}'
        fixture = b"kind: Secret\ndata:\n  auth: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_numeric_helm_credentials(self) -> None:
        expressions = (
            b"{{ 123456 }}",
            b"{{ default 123456 .Values.password }}",
            b"{{ get (dict \"password\" 123456) \"password\" }}",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                fixture = b"kind: Secret\nstringData:\n  password: " + expression
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_helm_replace_output_literal(self) -> None:
        expression = b"{{" + b' replace "placeholder" "hunter2" "placeholder" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_literal_in_helm_lookup_container(self) -> None:
        expressions = (
            b"{{" + b' get (dict "password" "hunter2") "password" }}',
            b"{{" + b' index (list "hunter2") 0 }}',
            b"{{" + b' pluck "password" (dict "password" "hunter2") }}',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                fixture = b"kind: Secret\nstringData:\n  password: " + expression
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_helm_dict_key_in_pipeline_input(self) -> None:
        expression = b"{{" + b' dict "password" .Values.password | get "password" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_helm_dict_literal_value_in_pipeline_input(self) -> None:
        expression = b"{{" + b' dict "password" "hunter2" | get "password" }}'
        fixture = b"kind: Secret\nstringData:\n  password: " + expression
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_bracketed_javascript_environment_reference(self) -> None:
        key = b"const pass" + b"word = "
        fixture = key + b'process.env["PASSWORD"];'
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_quoted_null_like_secret_literals(self) -> None:
        for value in (b'"null"', b'"~"', b'"{}"', b'"[]"'):
            with self.subTest(value=value):
                fixture = b"kind: Secret\nstringData:\n  password: " + value
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_actual_null_and_empty_secret_collections(self) -> None:
        fixtures = (
            b"kind: Secret\nstringData:\n  password: null",
            b"kind: Secret\nstringData:\n  password: ~",
            b"kind: Secret\nstringData:\n  password: {}",
            b"kind: Secret\nstringData:\n  password: []",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_typed_yaml_scalars_under_policy_keys(self) -> None:
        fixture = (
            b"useSec" + b"ret: false\ngenerateTo" + b"ken: true\ntokenExpira"
            b"tion: 3600"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_boolean_under_bare_sensitive_key(self) -> None:
        key = (
            b"sec" + b"ret: false\nto" + b"ken: true\nkind: Secret\nstringData:\n"
            b"  pass" + b"word: false"
        )
        self.assertFalse(audit.scan_blob("fixture", key))

    def test_detects_numeric_yaml_credentials(self) -> None:
        key = b"pass" + b"word: 123456\napi" + b"Key: 1234567890123456"
        self.assertTrue(audit.scan_blob("fixture", key))

    def test_allows_kubernetes_secret_reference_names(self) -> None:
        fixture = (
            b"tls:\n  secretNa" + b"me: tls-certificate\nexistingSec" + b"ret: runtime"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_allows_schema_container_under_sensitive_key(self) -> None:
        key = b'{"properties":{"pass' + b'word":{"type":"string"}}}'
        self.assertFalse(audit.scan_blob("fixture", key))

    def test_detects_merged_secret_with_unknown_yaml_tag(self) -> None:
        fixture = (
            b"payload: &payload {auth: c2VjcmV0}\n"
            b"kind: Secret\ndata: {<<: *payload}\ncustom: !foo bar"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_registry_auth_fields(self) -> None:
        docker = b'{"auths":{"registry":{"auth":"dXNlcjpwYXNz"}}}'
        npm = b"_au" + b"th=dXNlcjpwYXNz"
        self.assertTrue(audit.scan_blob("fixture", docker))
        self.assertTrue(audit.scan_blob("fixture", npm))

    def test_rejects_netrc_filenames(self) -> None:
        self.assertTrue(audit.risky_name(".netrc"))
        self.assertTrue(audit.risky_name("_netrc"))

    def test_detects_merged_environment_with_unknown_yaml_tag(self) -> None:
        fixture = (
            b"shared: &shared {name: PASSWORD, value: abcdefghijklmnopqrstuvwxyz}\n"
            b"env:\n  - {<<: *shared}\ncustom: !foo bar"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_honors_yaml_merge_sequence_precedence_with_unknown_tag(self) -> None:
        fixture = (
            b"literal: &literal {name: PASSWORD, value: abcdefghijklmnopqrstuvwxyz}\n"
            b"safe: &safe {name: PASSWORD, value: '${PASSWORD}'}\n"
            b"env:\n  - {<<: [*literal, *safe]}\ncustom: !foo bar"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_explicit_secret_data_overrides_yaml_merge(self) -> None:
        fixture = (
            b"payload: &payload {auth: c2VjcmV0}\n"
            b'kind: Secret\ndata: {<<: *payload, auth: "${PASSWORD}"}'
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_literal_secret_data_overrides_safe_yaml_merge(self) -> None:
        fixture = (
            b"payload: &payload {auth: '${PASSWORD}'}\n"
            b"kind: Secret\ndata: {<<: *payload, auth: c2VjcmV0}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_explicit_environment_fields_override_yaml_merge(self) -> None:
        fixture = (
            b"literal: &literal {name: PASSWORD, value: abcdefghijklmnopqrstuvwxyz}\n"
            b"env:\n  - {value: '${PASSWORD}', <<: *literal}\ncustom: !foo bar"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_flow_style_kubernetes_secret(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"{apiVersion: v1, kind: " + b"Secret"
            + b", data: {auth: " + encoded + b"}}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_inside_flow_style_list(self) -> None:
        fixture = (
            b"{kind: List, items: [{kind: Secret, data: {auth: c2VjcmV0}}]}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_flow_secret_data_alias(self) -> None:
        fixture = (
            b"{kind: Secret, payload: &payload {auth: c2VjcmV0}, data: *payload}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_flow_secret_kind_alias(self) -> None:
        fixture = (
            b"{metadata: {labels: {type: &secretKind Secret}}, "
            b"kind: *secretKind, data: {auth: c2VjcmV0}}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_allows_safe_scalar_alias_in_flow_secret(self) -> None:
        fixture = (
            b"{kind: Secret, shared: &x ${PASSWORD}, data: {auth: *x}}"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_flow_secret_data_after_node_property(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"{kind: " + b"Secret" + b", data: &payload {auth: " + encoded + b"}}"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_secret_alias(self) -> None:
        kind = b"kind: " + b"Secret"
        fixture = (
            kind + b"\nmetadata:\n  labels:\n    checksum: &shared " + b"a" * 24
            + b"\ndata:\n  auth: *shared"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_secret_data_map_alias(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixtures = (
            b"payload: &payload {auth: " + encoded + b"}\nkind: Secret\ndata: *payload",
            b"payload: &payload\n  auth: " + encoded + b"\nkind: Secret\ndata: *payload",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_nested_in_kubernetes_list(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"kind: List\nitems:\n  - apiVersion: v1\n    kind: Secret\n"
            b"    data:\n      auth: " + encoded
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_when_kind_starts_list_item(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"kind: List\nitems:\n  - kind: Secret\n    data:\n      auth: " + encoded
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_scopes_list_data_to_its_resource_kind(self) -> None:
        fixture = (
            b"kind: List\nitems:\n  - kind: Secret\n    data: {}\n"
            b"  - kind: ConfigMap\n    data:\n      auth: ordinary public configuration text"
        )
        self.assertFalse(audit.scan_blob("fixture", fixture))

    def test_detects_secret_kind_alias(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"type: &secretKind Secret\nkind: *secretKind\ndata:\n  auth: " + encoded
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_kind_block_scalar(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = b"kind: |-\n  Secret\ndata:\n  auth: " + encoded
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_when_data_precedes_kind(self) -> None:
        fixture = b"data:\n  auth: c2VjcmV0\nkind: Secret"
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_kubernetes_secret_literals(self) -> None:
        fixtures = (
            b"kind: Secret\ndata:\n  auth: c2VjcmV0",
            b"kind: Secret\nstringData:\n  auth: short",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_secret_data_merge_alias(self) -> None:
        encoded = b"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
        fixture = (
            b"payload: &payload\n  auth: " + encoded
            + b"\nkind: Secret\ndata:\n  <<: *payload"
        )
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_kubernetes_json_secret(self) -> None:
        fixture = json.dumps(
            {
                "kind": "Secret",
                "data": {"auth": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"},
            }
        ).encode()
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_detects_short_kubernetes_json_secret(self) -> None:
        fixture = json.dumps(
            {"kind": "Secret", "data": {"auth": "c2VjcmV0"}}
        ).encode()
        self.assertTrue(audit.scan_blob("fixture", fixture))

    def test_ignores_configmap_data_and_secret_references(self) -> None:
        fixtures = (
            b"kind: ConfigMap\ndata:\n  auth: this is ordinary public configuration text",
            b"kind: Secret\nstringData:\n  auth: ${RUNTIME_SECRET}",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertFalse(audit.scan_blob("fixture", fixture))


class HistoryPathTests(unittest.TestCase):
    def test_reads_symlink_itself_instead_of_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside.txt").write_text("external content")
            (root / "link.txt").symlink_to("outside.txt")
            previous_root = audit.ROOT
            audit.ROOT = root
            try:
                self.assertEqual(audit.working_tree_blob("link.txt"), b"outside.txt")
            finally:
                audit.ROOT = previous_root

    def test_preserves_forbidden_name_after_blob_is_renamed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def run(*args: str) -> None:
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

            run("init", "-q")
            run("config", "user.name", "Audit Test")
            run("config", "user.email", "audit@example.invalid")
            (root / "secret.key").write_text("synthetic fixture\n")
            run("add", "secret.key")
            run("commit", "-qm", "add forbidden path")
            run("mv", "secret.key", "config.txt")
            run("commit", "-qm", "rename forbidden path")

            previous_root = audit.ROOT
            audit.ROOT = root
            try:
                paths = {path for _, path in audit.history_blobs()}
            finally:
                audit.ROOT = previous_root

            self.assertIn("secret.key", paths)
            self.assertIn("config.txt", paths)


if __name__ == "__main__":
    unittest.main()
