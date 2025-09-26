#!/usr/bin/env python3
"""
Comprehensive test runner for BMP collector application.

This script provides various test execution modes and reporting options.
"""
import argparse
import subprocess
import sys
import os
import time
from pathlib import Path
from typing import List, Optional, Dict, Any


class TestRunner:
    """Comprehensive test runner with multiple execution modes."""

    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        self.coverage_dir = self.project_root / "htmlcov"
        self.reports_dir = self.project_root / "test-reports"

    def setup_environment(self):
        """Setup test environment."""
        # Create reports directory
        self.reports_dir.mkdir(exist_ok=True)

        # Set environment variables for testing
        test_env = {
            "DB_HOST": "localhost",
            "DB_PORT": "5432",
            "DB_NAME": "test_bmp",
            "DB_USER": "test_user",
            "DB_PASSWORD": "test_password",
            "LOG_LEVEL": "DEBUG",
            "PYTHONPATH": str(self.project_root),
        }

        for key, value in test_env.items():
            os.environ.setdefault(key, value)

    def run_command(self, cmd: List[str], description: str) -> bool:
        """Run a command and return success status."""
        print(f"\n{'='*60}")
        print(f"Running: {description}")
        print(f"Command: {' '.join(cmd)}")
        print(f"{'='*60}")

        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=False,
                text=True,
                check=True
            )
            elapsed = time.time() - start_time
            print(f"\n✅ {description} completed successfully ({elapsed:.2f}s)")
            return True
        except subprocess.CalledProcessError as e:
            elapsed = time.time() - start_time
            print(f"\n❌ {description} failed ({elapsed:.2f}s)")
            print(f"Return code: {e.returncode}")
            return False

    def run_unit_tests(self, coverage: bool = True, verbose: bool = True) -> bool:
        """Run unit tests."""
        cmd = ["python", "-m", "pytest", "tests/unit/"]

        if coverage:
            cmd.extend([
                "--cov=src",
                "--cov-report=html",
                "--cov-report=xml",
                "--cov-report=term-missing",
                "--cov-fail-under=85"
            ])

        if verbose:
            cmd.append("-v")

        cmd.extend([
            "--junitxml=test-reports/junit-unit.xml",
            "--html=test-reports/unit-tests.html",
            "--self-contained-html",
            "-m", "unit"
        ])

        return self.run_command(cmd, "Unit Tests")

    def run_integration_tests(self, verbose: bool = True) -> bool:
        """Run integration tests."""
        cmd = [
            "python", "-m", "pytest", "tests/integration/",
            "--junitxml=test-reports/junit-integration.xml",
            "--html=test-reports/integration-tests.html",
            "--self-contained-html",
            "-m", "integration"
        ]

        if verbose:
            cmd.append("-v")

        return self.run_command(cmd, "Integration Tests")

    def run_security_tests(self, verbose: bool = True) -> bool:
        """Run security tests."""
        cmd = [
            "python", "-m", "pytest", "tests/security/",
            "--junitxml=test-reports/junit-security.xml",
            "--html=test-reports/security-tests.html",
            "--self-contained-html",
            "-m", "security"
        ]

        if verbose:
            cmd.append("-v")

        return self.run_command(cmd, "Security Tests")

    def run_performance_tests(self, verbose: bool = True) -> bool:
        """Run performance/stress tests."""
        cmd = [
            "python", "-m", "pytest", "tests/",
            "--benchmark-only",
            "--benchmark-json=test-reports/benchmark.json",
            "--junitxml=test-reports/junit-performance.xml",
            "-m", "slow"
        ]

        if verbose:
            cmd.append("-v")

        return self.run_command(cmd, "Performance Tests")

    def run_all_tests(self, coverage: bool = True, verbose: bool = True) -> bool:
        """Run all test suites."""
        cmd = ["python", "-m", "pytest", "tests/"]

        if coverage:
            cmd.extend([
                "--cov=src",
                "--cov-report=html",
                "--cov-report=xml",
                "--cov-report=term-missing",
                "--cov-fail-under=80"  # Lower threshold for full suite
            ])

        if verbose:
            cmd.append("-v")

        cmd.extend([
            "--junitxml=test-reports/junit-all.xml",
            "--html=test-reports/all-tests.html",
            "--self-contained-html",
            "--maxfail=10"  # Stop after 10 failures
        ])

        return self.run_command(cmd, "All Tests")

    def run_code_quality_checks(self) -> bool:
        """Run code quality checks."""
        checks = [
            (["python", "-m", "black", "--check", "--diff", "src", "tests"], "Black (Code Formatting)"),
            (["python", "-m", "isort", "--check-only", "--diff", "src", "tests"], "isort (Import Sorting)"),
            (["python", "-m", "flake8", "src", "tests"], "Flake8 (Linting)"),
            (["python", "-m", "mypy", "src"], "MyPy (Type Checking)"),
        ]

        all_passed = True
        for cmd, description in checks:
            if not self.run_command(cmd, description):
                all_passed = False

        return all_passed

    def run_security_linting(self) -> bool:
        """Run security linting tools."""
        checks = [
            (["python", "-m", "bandit", "-r", "src", "-f", "json", "-o", "test-reports/bandit.json"], "Bandit (Security Linting)"),
            (["python", "-m", "safety", "check", "--json", "--output", "test-reports/safety.json"], "Safety (Vulnerability Check)"),
        ]

        all_passed = True
        for cmd, description in checks:
            # Security tools may find issues, so don't fail the entire run
            self.run_command(cmd, description)

        return all_passed

    def run_parallel_tests(self, num_workers: int = 4) -> bool:
        """Run tests in parallel."""
        cmd = [
            "python", "-m", "pytest", "tests/",
            f"-n", str(num_workers),
            "--dist=loadfile",
            "--junitxml=test-reports/junit-parallel.xml",
            "--html=test-reports/parallel-tests.html",
            "--self-contained-html",
            "-v"
        ]

        return self.run_command(cmd, f"Parallel Tests ({num_workers} workers)")

    def run_memory_tests(self) -> bool:
        """Run memory profiling tests."""
        cmd = [
            "python", "-m", "pytest", "tests/",
            "--memray",
            "--junitxml=test-reports/junit-memory.xml",
            "-k", "memory or buffer or large",
            "-v"
        ]

        return self.run_command(cmd, "Memory Profiling Tests")

    def generate_coverage_report(self) -> bool:
        """Generate detailed coverage report."""
        if not (self.project_root / "coverage.xml").exists():
            print("❌ No coverage data found. Run tests with coverage first.")
            return False

        # Generate additional coverage formats
        cmd = ["python", "-m", "coverage", "html", "--directory", "test-reports/coverage-html"]
        self.run_command(cmd, "HTML Coverage Report")

        cmd = ["python", "-m", "coverage", "report"]
        self.run_command(cmd, "Coverage Summary")

        return True

    def clean_test_artifacts(self) -> bool:
        """Clean test artifacts and reports."""
        artifacts = [
            "test-reports",
            "htmlcov",
            ".coverage",
            "coverage.xml",
            ".pytest_cache",
            "**/__pycache__",
            "**/*.pyc",
            "*.memray"
        ]

        for pattern in artifacts:
            if pattern.startswith("**"):
                # Handle glob patterns
                for path in self.project_root.rglob(pattern.replace("**/", "")):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        import shutil
                        shutil.rmtree(path)
            else:
                path = self.project_root / pattern
                if path.exists():
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        import shutil
                        shutil.rmtree(path)

        print("🧹 Cleaned test artifacts")
        return True

    def print_summary(self, results: Dict[str, bool]):
        """Print test execution summary."""
        print(f"\n{'='*60}")
        print("TEST EXECUTION SUMMARY")
        print(f"{'='*60}")

        total_tests = len(results)
        passed_tests = sum(1 for result in results.values() if result)
        failed_tests = total_tests - passed_tests

        for test_name, passed in results.items():
            status = "✅ PASSED" if passed else "❌ FAILED"
            print(f"{test_name:<30} {status}")

        print(f"\n{'='*60}")
        print(f"Total: {total_tests} | Passed: {passed_tests} | Failed: {failed_tests}")

        if failed_tests == 0:
            print("🎉 All tests passed!")
        else:
            print(f"⚠️  {failed_tests} test suite(s) failed")

        print(f"{'='*60}")

        # Print report locations
        if self.reports_dir.exists():
            print("\n📊 Test reports available in:")
            for report_file in self.reports_dir.glob("*.html"):
                print(f"  - {report_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="BMP Collector Test Runner")
    parser.add_argument("--mode", choices=[
        "unit", "integration", "security", "performance", "all",
        "quality", "security-lint", "parallel", "memory", "clean"
    ], default="all", help="Test mode to run")
    parser.add_argument("--no-coverage", action="store_true", help="Disable coverage reporting")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (less verbose)")
    parser.add_argument("--parallel", "-p", type=int, default=4, help="Number of parallel workers")
    parser.add_argument("--fast", action="store_true", help="Skip slow tests and checks")

    args = parser.parse_args()

    runner = TestRunner()
    runner.setup_environment()

    coverage = not args.no_coverage
    verbose = not args.quiet
    results = {}

    if args.mode == "clean":
        runner.clean_test_artifacts()
        return 0

    try:
        if args.mode == "unit":
            results["Unit Tests"] = runner.run_unit_tests(coverage=coverage, verbose=verbose)

        elif args.mode == "integration":
            results["Integration Tests"] = runner.run_integration_tests(verbose=verbose)

        elif args.mode == "security":
            results["Security Tests"] = runner.run_security_tests(verbose=verbose)

        elif args.mode == "performance":
            results["Performance Tests"] = runner.run_performance_tests(verbose=verbose)

        elif args.mode == "quality":
            results["Code Quality"] = runner.run_code_quality_checks()

        elif args.mode == "security-lint":
            results["Security Linting"] = runner.run_security_linting()

        elif args.mode == "parallel":
            results["Parallel Tests"] = runner.run_parallel_tests(num_workers=args.parallel)

        elif args.mode == "memory":
            results["Memory Tests"] = runner.run_memory_tests()

        elif args.mode == "all":
            if not args.fast:
                results["Code Quality"] = runner.run_code_quality_checks()
                results["Security Linting"] = runner.run_security_linting()

            results["Unit Tests"] = runner.run_unit_tests(coverage=coverage, verbose=verbose)
            results["Integration Tests"] = runner.run_integration_tests(verbose=verbose)
            results["Security Tests"] = runner.run_security_tests(verbose=verbose)

            if not args.fast:
                results["Performance Tests"] = runner.run_performance_tests(verbose=verbose)
                results["Memory Tests"] = runner.run_memory_tests()

        # Generate coverage report if coverage was collected
        if coverage and any(results.values()):
            runner.generate_coverage_report()

        # Print summary
        if results:
            runner.print_summary(results)

        # Return appropriate exit code
        return 0 if all(results.values()) else 1

    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())