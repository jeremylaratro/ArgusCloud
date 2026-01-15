"""Tests for arguscloud.cli.main module."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from arguscloud.cli.main import (
    parse_args,
    main,
    cmd_normalize,
    cmd_analyze,
    cmd_export,
    cmd_keygen,
)


class TestParseArgs:
    """Tests for CLI argument parsing."""

    def test_help_output(self):
        """Test that --help exits gracefully."""
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--help"])
        assert exc_info.value.code == 0

    def test_version_output(self):
        """Test that --version shows version and exits."""
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_no_command(self):
        """Test parsing with no command."""
        args = parse_args([])
        assert args.command is None

    def test_collect_command_defaults(self):
        """Test collect command default values."""
        args = parse_args(["collect"])
        assert args.command == "collect"
        assert args.provider == "aws"
        assert args.output == "arguscloud-output"
        assert args.mode == "fast"
        assert args.services is None
        assert args.profile is None
        assert args.region is None

    def test_collect_command_with_options(self):
        """Test collect command with options."""
        args = parse_args([
            "collect",
            "--provider", "aws",
            "--profile", "myprofile",
            "--region", "us-east-1",
            "--output", "/tmp/output",
            "--services", "iam", "s3",
            "--mode", "full",
        ])
        assert args.provider == "aws"
        assert args.profile == "myprofile"
        assert args.region == "us-east-1"
        assert args.output == "/tmp/output"
        assert args.services == ["iam", "s3"]
        assert args.mode == "full"

    def test_normalize_command_defaults(self):
        """Test normalize command default values."""
        args = parse_args(["normalize"])
        assert args.command == "normalize"
        assert args.input == "arguscloud-output"
        assert args.output is None

    def test_normalize_command_with_options(self):
        """Test normalize command with options."""
        args = parse_args([
            "normalize",
            "--input", "/tmp/input",
            "--output", "/tmp/output",
        ])
        assert args.input == "/tmp/input"
        assert args.output == "/tmp/output"

    def test_analyze_command_defaults(self):
        """Test analyze command default values."""
        args = parse_args(["analyze"])
        assert args.command == "analyze"
        assert args.input == "arguscloud-output"
        assert args.rules is None
        assert args.severity is None

    def test_analyze_command_severity_filter(self):
        """Test analyze command with severity filter."""
        args = parse_args([
            "analyze",
            "--severity", "high",
        ])
        assert args.severity == "high"

    def test_analyze_command_invalid_severity(self):
        """Test analyze command with invalid severity."""
        with pytest.raises(SystemExit):
            parse_args(["analyze", "--severity", "invalid"])

    def test_export_command_defaults(self):
        """Test export command default values."""
        args = parse_args(["export"])
        assert args.command == "export"
        assert args.input == "arguscloud-output"
        assert args.format == "json"
        assert args.output is None

    def test_export_command_json_format(self):
        """Test export command with JSON format."""
        args = parse_args(["export", "--format", "json"])
        assert args.format == "json"

    def test_export_command_sarif_format(self):
        """Test export command with SARIF format."""
        args = parse_args(["export", "--format", "sarif"])
        assert args.format == "sarif"

    def test_export_command_html_format(self):
        """Test export command with HTML format."""
        args = parse_args(["export", "--format", "html"])
        assert args.format == "html"

    def test_export_command_invalid_format_error(self):
        """Test export command with invalid format."""
        with pytest.raises(SystemExit):
            parse_args(["export", "--format", "pdf"])

    def test_serve_command_defaults(self):
        """Test serve command default values."""
        args = parse_args(["serve"])
        assert args.command == "serve"
        assert args.host == "0.0.0.0"
        assert args.port == 5000
        assert args.neo4j_uri == "bolt://localhost:7687"
        assert args.neo4j_user == "neo4j"
        assert args.no_auth is False

    def test_serve_command_custom_port(self):
        """Test serve command with custom port."""
        args = parse_args(["serve", "--port", "8080"])
        assert args.port == 8080

    def test_serve_command_no_auth_flag(self):
        """Test serve command with no-auth flag."""
        args = parse_args(["serve", "--no-auth"])
        assert args.no_auth is True

    def test_import_command_defaults(self):
        """Test import command default values."""
        args = parse_args(["import"])
        assert args.command == "import"
        assert args.input == "arguscloud-output"
        assert args.neo4j_uri == "bolt://localhost:7687"
        assert args.clear is False

    def test_import_command_neo4j_uri_parsing(self):
        """Test import command with custom Neo4j URI."""
        args = parse_args([
            "import",
            "--neo4j-uri", "bolt://myserver:7687",
            "--neo4j-user", "admin",
            "--neo4j-password", "secret",
        ])
        assert args.neo4j_uri == "bolt://myserver:7687"
        assert args.neo4j_user == "admin"
        assert args.neo4j_password == "secret"

    def test_import_command_clear_flag(self):
        """Test import command with clear flag."""
        args = parse_args(["import", "--clear"])
        assert args.clear is True

    def test_keygen_command_defaults(self):
        """Test keygen command default values."""
        args = parse_args(["keygen"])
        assert args.command == "keygen"
        assert args.prefix == "ch"

    def test_keygen_command_with_prefix(self):
        """Test keygen command with custom prefix."""
        args = parse_args(["keygen", "--prefix", "test"])
        assert args.prefix == "test"


class TestMain:
    """Tests for main CLI entry point."""

    def test_main_no_command(self):
        """Test main with no command shows usage."""
        result = main([])
        assert result == 1

    def test_main_unknown_command(self):
        """Test main with unknown command exits with error."""
        with pytest.raises(SystemExit) as exc_info:
            main(["unknown"])
        assert exc_info.value.code == 2  # argparse exits with 2 for invalid commands


class TestCmdNormalize:
    """Tests for normalize command."""

    def test_normalize_missing_input_error(self):
        """Test normalize with missing input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["normalize", "--input", f"{tmpdir}/nonexistent"])
            result = cmd_normalize(args)
            assert result == 1

    def test_normalize_with_valid_input(self):
        """Test normalize with valid input data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()

            # Create mock service data
            iam_data = [
                {"Role": {"Arn": "arn:aws:iam::123456789012:role/TestRole", "RoleName": "TestRole"}}
            ]
            with open(input_dir / "iam-roles.jsonl", "w") as f:
                for item in iam_data:
                    f.write(json.dumps(item) + "\n")

            # Mock the normalize module at the awshound level
            with patch("awshound.normalize.normalize") as mock_normalize:
                mock_normalize.return_value = ([], [])

                args = parse_args(["normalize", "--input", str(input_dir)])
                result = cmd_normalize(args)
                assert result == 0


class TestCmdAnalyze:
    """Tests for analyze command."""

    def test_analyze_missing_input_error(self):
        """Test analyze with missing normalized data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["analyze", "--input", tmpdir])
            result = cmd_analyze(args)
            assert result == 1

    def test_analyze_with_valid_input(self):
        """Test analyze with valid normalized data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {"name": "TestRole"}}]
            edges = [{"src": "role1", "dst": "bucket1", "type": "CanAccess", "properties": {}}]

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            with open(input_dir / "edges.jsonl", "w") as f:
                for edge in edges:
                    f.write(json.dumps(edge) + "\n")

            # Mock both Node/Edge from awshound.normalize and rules
            mock_node = MagicMock()
            mock_edge = MagicMock()
            with patch("awshound.normalize.Node") as MockNode:
                with patch("awshound.normalize.Edge") as MockEdge:
                    MockNode.from_dict.return_value = mock_node
                    MockEdge.from_dict.return_value = mock_edge
                    with patch("awshound.rules.evaluate_rules") as mock_evaluate:
                        mock_evaluate.return_value = []

                        args = parse_args(["analyze", "--input", str(input_dir)])
                        result = cmd_analyze(args)
                        assert result == 0

    def test_analyze_severity_filter(self):
        """Test analyze with severity filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {}}]
            edges = []

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            with open(input_dir / "edges.jsonl", "w") as f:
                for edge in edges:
                    f.write(json.dumps(edge) + "\n")

            # Mock Node/Edge and rules
            mock_node = MagicMock()
            with patch("awshound.normalize.Node") as MockNode:
                with patch("awshound.normalize.Edge") as MockEdge:
                    MockNode.from_dict.return_value = mock_node
                    with patch("awshound.rules.evaluate_rules") as mock_evaluate:
                        # Create mock attack edges with properties
                        mock_edge_high = MagicMock()
                        mock_edge_high.properties = {"severity": "high", "rule": "test"}
                        mock_edge_high.to_dict.return_value = {"src": "a", "dst": "b", "type": "AttackPath", "properties": {"severity": "high"}}

                        mock_edge_low = MagicMock()
                        mock_edge_low.properties = {"severity": "low", "rule": "test"}
                        mock_edge_low.to_dict.return_value = {"src": "a", "dst": "b", "type": "AttackPath", "properties": {"severity": "low"}}

                        mock_evaluate.return_value = [mock_edge_high, mock_edge_low]

                        args = parse_args(["analyze", "--input", str(input_dir), "--severity", "high"])
                        result = cmd_analyze(args)
                        assert result == 0


class TestCmdExport:
    """Tests for export command."""

    def test_export_missing_input_error(self):
        """Test export with missing normalized data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["export", "--input", tmpdir])
            result = cmd_export(args)
            assert result == 1

    def test_export_json_format(self):
        """Test export with JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {}}]

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            args = parse_args(["export", "--input", str(input_dir), "--format", "json"])
            result = cmd_export(args)
            assert result == 0
            assert (input_dir / "report.json").exists()

    def test_export_sarif_format(self):
        """Test export with SARIF format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {}}]

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            args = parse_args(["export", "--input", str(input_dir), "--format", "sarif"])
            result = cmd_export(args)
            assert result == 0
            assert (input_dir / "report.sarif").exists()

    def test_export_html_format(self):
        """Test export with HTML format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {}}]

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            args = parse_args(["export", "--input", str(input_dir), "--format", "html"])
            result = cmd_export(args)
            assert result == 0
            assert (input_dir / "report.html").exists()

    def test_export_custom_output_path(self):
        """Test export with custom output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)
            output_file = input_dir / "custom-report.json"

            # Create mock normalized data
            nodes = [{"id": "role1", "type": "Role", "properties": {}}]

            with open(input_dir / "nodes.jsonl", "w") as f:
                for node in nodes:
                    f.write(json.dumps(node) + "\n")

            args = parse_args([
                "export",
                "--input", str(input_dir),
                "--format", "json",
                "--output", str(output_file),
            ])
            result = cmd_export(args)
            assert result == 0
            assert output_file.exists()


class TestCmdKeygen:
    """Tests for keygen command."""

    def test_keygen_output_format(self, capsys):
        """Test keygen outputs API key and hash."""
        args = parse_args(["keygen"])
        result = cmd_keygen(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "API Key" in captured.out
        assert "Hashed Key" in captured.out
        assert "ch_" in captured.out  # Default prefix

    def test_keygen_with_prefix(self, capsys):
        """Test keygen with custom prefix."""
        args = parse_args(["keygen", "--prefix", "test"])
        result = cmd_keygen(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "test_" in captured.out

    def test_keygen_shows_usage_examples(self, capsys):
        """Test keygen shows usage examples."""
        args = parse_args(["keygen"])
        result = cmd_keygen(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "ARGUSCLOUD_API_KEYS" in captured.out
        assert "curl" in captured.out
        assert "X-API-Key" in captured.out


class TestCommandIntegration:
    """Integration tests for CLI commands."""

    def test_normalize_analyze_export_pipeline(self):
        """Test the normalize -> analyze -> export pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir)

            # Step 1: Create mock service data (simulating collected data)
            iam_data = [
                {
                    "Role": {
                        "Arn": "arn:aws:iam::123456789012:role/TestRole",
                        "RoleName": "TestRole",
                        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                    },
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                }
            ]
            with open(input_dir / "iam-roles.jsonl", "w") as f:
                for item in iam_data:
                    f.write(json.dumps(item) + "\n")

            # Step 2: Normalize
            with patch("awshound.normalize.normalize") as mock_normalize:
                mock_node = MagicMock()
                mock_node.to_dict.return_value = {"id": "role1", "type": "Role", "properties": {"name": "TestRole"}}
                mock_normalize.return_value = ([mock_node], [])

                args = parse_args(["normalize", "--input", str(input_dir)])
                result = cmd_normalize(args)
                assert result == 0

            # Create nodes.jsonl manually for subsequent steps
            with open(input_dir / "nodes.jsonl", "w") as f:
                f.write(json.dumps({"id": "role1", "type": "Role", "properties": {"name": "TestRole"}}) + "\n")
            with open(input_dir / "edges.jsonl", "w") as f:
                pass  # Empty file

            # Step 3: Analyze (mock the Node/Edge classes used by cmd_analyze)
            mock_node = MagicMock()
            with patch("awshound.normalize.Node") as MockNode:
                with patch("awshound.normalize.Edge") as MockEdge:
                    MockNode.from_dict.return_value = mock_node
                    with patch("awshound.rules.evaluate_rules") as mock_evaluate:
                        mock_evaluate.return_value = []

                        args = parse_args(["analyze", "--input", str(input_dir)])
                        result = cmd_analyze(args)
                        assert result == 0

            # Step 4: Export
            args = parse_args(["export", "--input", str(input_dir), "--format", "json"])
            result = cmd_export(args)
            assert result == 0

            # Verify output exists
            assert (input_dir / "report.json").exists()
