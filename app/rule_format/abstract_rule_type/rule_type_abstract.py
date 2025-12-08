from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import importlib
import pkgutil
from typing import Any, Dict, List, Optional
import app.rule_format.available_format as available_formats


# ---------- Common contract ----------

#
#   To help the creation of many new formats , abstract class RuleType with 
#   many methods to implement.
#
#   /!\ validate() is very important for the syntaxe and execute section 
#   (if return false then you have to create a bad rule). 
#
#   get_rule_files() and extract_rules_from_file() are only for the import
#   section to help parsing all the rule in a file on a github project.
#


def load_all_rule_formats():
    """Import dynamically all available rule format classes except the default one."""
    for module_info in pkgutil.iter_modules(available_formats.__path__):
        module_name = module_info.name
        if module_name.lower() in ["default_format", "base_format", "__init__"]:
            continue

        full_name = f"{available_formats.__name__}.{module_name}"
        importlib.import_module(full_name)

@dataclass
class ValidationResult:
    """Class for keeping information if a rule is valid or not."""
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_content: Optional[str] = None


class RuleType(ABC):
    """
    Contract for all rule formats.
    Implementations should be lightweight and stateless.
    """

    @property
    @abstractmethod
    def format(self) -> str:
        """Short identifier of the format (e.g., 'yara', 'sigma')."""
        ...

    @abstractmethod
    def get_class(self) -> str:
        """Short identifier of the class."""
        ...

    @abstractmethod
    def validate(self, content: str, **kwargs) -> ValidationResult:
        """Validate the rule and return a ValidationResult."""
        ...

    @abstractmethod
    def parse_metadata(self, content: str, **kwargs) -> Dict[str, Any]:
        """Extract common metadata from the rule."""
        ...

    @abstractmethod
    def get_rule_files(self, file: str) -> bool:
        """Return all rule files from a given repository directory."""
        ...

    @abstractmethod
    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """Extract individual rules from a given file."""
        ...

    @abstractmethod
    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """Extract one rule with his id in a repo (to_update)."""
        ...
        
    # other method to do ....