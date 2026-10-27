"""Abstract base classes for Collectors, Rules, and AlertSinks."""

from abc import ABC, abstractmethod
from ps011.models.observation import Finding, Observation


class Collector(ABC):
    """Abstract Base Class for probe collectors."""

    @abstractmethod
    async def collect(self, target: str) -> list[Observation]:
        """Collect observations for a target.

        Args:
            target: The target domain or host identifier.

        Returns:
            List of collected Observation dataclass instances.
        """
        pass


class Rule(ABC):
    """Abstract Base Class for analysis rules."""

    @abstractmethod
    async def evaluate(self, diff: dict, baseline: dict) -> list[Finding]:
        """Evaluate observations/diffs against baseline to produce findings.

        Args:
            diff: Calculated difference dictionary.
            baseline: Baseline state dictionary.

        Returns:
            List of generated Finding dataclass instances.
        """
        pass


class AlertSink(ABC):
    """Abstract Base Class for alert dispatch sinks."""

    @abstractmethod
    async def send(self, finding: Finding) -> None:
        """Send a finding to the alert channel.

        Args:
            finding: The Finding dataclass instance to dispatch.
        """
        pass
