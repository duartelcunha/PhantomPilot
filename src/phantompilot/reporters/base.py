"""Abstract base class for report generators."""

from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from phantompilot.models import MetricsReport, ScanResult


class ReporterError(Exception):
    """Base exception for reporter errors."""


class Reporter(ABC):
    @property
    @abstractmethod
    def format_name(self) -> str: ...

    @property
    @abstractmethod
    def file_extension(self) -> str: ...

    @abstractmethod
    def generate(self, scan_result: ScanResult, metrics: MetricsReport, output_dir: Path) -> Path: ...
