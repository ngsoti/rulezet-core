# ------------------------------------------------------------------------------------------------------------------- #
#                                               Validation rule                                                       #
# ------------------------------------------------------------------------------------------------------------------- #
"""
Rule Input Validation Functions

Standalone functions for validating rule search parameters, pagination, and verifying rule syntax by format.
"""

from typing import Any, Tuple, Type

from app.rule_format.abstract_rule_type.rule_type_abstract import RuleType


# --------------------------
# Validation functions
# --------------------------

def validate_search_param(search: str) -> None:
    if search and not isinstance(search, str):
        raise ValueError("Search parameter must be a string.")
    if search and len(search) > 200:
        raise ValueError("Search parameter cannot exceed 200 characters.")


def validate_author_param(author: str) -> None:
    if author and not isinstance(author, str):
        raise ValueError("Author parameter must be a string.")
    if author and len(author) > 100:
        raise ValueError("Author parameter cannot exceed 100 characters.")


def validate_sort_by_param(sort_by: str, allowed_sort: set) -> None:
    if sort_by and sort_by not in allowed_sort:
        raise ValueError(f"Invalid sort_by. Allowed values: {sorted(allowed_sort)}")


def validate_page_param(page: Any) -> None:
    if page is not None:
        try:
            page_int = int(page)
            if page_int < 1:
                raise ValueError("Page number must be greater than 0.")
        except (ValueError, TypeError):
            raise ValueError("Page parameter must be an integer.")


def validate_per_page_param(per_page: Any) -> None:
    if per_page is not None:
        try:
            per_page_int = int(per_page)
            if per_page_int < 1 or per_page_int > 100:
                raise ValueError("Per_page must be between 1 and 100.")
        except (ValueError, TypeError):
            raise ValueError("Per_page parameter must be an integer.")

# --------------------------
# Rule format verification
# --------------------------

def verify_rule_format(rule_format: str) -> None:
    """
    Verify that the given rule format exists in RuleType subclasses.
    Raises ValueError if not found.
    """
    if rule_format:
       

        rule_format_lower = rule_format.strip().lower()
        for cls in RuleType.__subclasses__():
            try:
                instance = cls()
                # Access as a property, not a method
                cls_format = getattr(instance, "format", None)
                if cls_format and cls_format.lower() == rule_format_lower:
                    return  # valid format
            except Exception:
                continue

        raise ValueError(f"Format is not supported.")