from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, Integer, JSON
from sqlalchemy.orm import relationship
from uuid import uuid4
import datetime


# ============================
# UpdateResult Table
# ============================
class UpdateResult(Base):
    """
    Represents a single update process (for a set of rules, URLs, or repositories).
    Each run of the update process creates one UpdateResult entry.
    """
    __tablename__ = "update_results"

    uuid = Column(String, primary_key=True, default=lambda: str(uuid4()))
    
    # User and mode information
    current_user = Column(String, nullable=True)   # The username or user ID that triggered the update
    mode = Column(String, nullable=False)           # Mode used for the update (e.g., 'url', 'rule', 'repo')

    # Optional metadata
    info = Column(Text, nullable=True)              # Optional descriptive info (e.g., CLI args, context)
    repo_sources = Column(JSON, nullable=True)      # List or dict of repository URLs/sources used in this update

    # Stats tracking
    not_found = Column(Integer, default=0)          # Number of rules not found
    found = Column(Integer, default=0)              # Number of rules found
    updated = Column(Integer, default=0)            # Number of rules updated
    skipped = Column(Integer, default=0)            # Number of rules skipped

    # Technical parameters
    thread_count = Column(Integer, default=4)       # Number of threads used in the update process
    query_date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))  # When the update ran

    # Relationships
    rule_statuses = relationship("RuleStatus", back_populates="update_result", cascade="all, delete-orphan")
    new_rules = relationship("NewRule", back_populates="update_result", cascade="all, delete-orphan")

    def to_json(self):
        return {
            "uuid": self.uuid,
            "mode": self.mode,
            "current_user": self.current_user,
            "info": self.info,
            "repo_sources": self.repo_sources,
            "not_found": self.not_found,
            "found": self.found,
            "updated": self.updated,
            "skipped": self.skipped,
            "thread_count": self.thread_count,
            "query_date": self.query_date.isoformat() if self.query_date else None,
        }


# ============================
# RuleStatus Table
# ============================
class RuleStatus(Base):
    """
    Represents the result of checking or updating one specific rule.
    Each rule analyzed during an update has one corresponding RuleStatus record.
    """
    __tablename__ = "rule_statuses"

    uuid = Column(String, primary_key=True, default=lambda: str(uuid4()))
    update_result_uuid = Column(String, ForeignKey("update_results.uuid", ondelete="CASCADE"), nullable=False)
    
    date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))  # When the rule was processed
    name_rule = Column(String, nullable=False)           # Rule name or identifier
    rule_id = Column(String, nullable=True)              # Unique rule ID if available
    message = Column(Text, nullable=True)                # Log or status message for debugging
    
    found = Column(Boolean, default=False)               # Whether the rule was found in the repository
    update_available = Column(Boolean, default=False)    # Whether an update is available for the rule
    rule_syntax_valid = Column(Boolean, default=True)    # Whether the rule syntax is valid
    error = Column(Boolean, default=False)               # Whether an error occurred when processing this rule

    history_id = Column(String, nullable=True)           # Reference to RuleUpdateHistory if applicable

    update_result = relationship("UpdateResult", back_populates="rule_statuses")

    def to_json(self):
        return {
            "uuid": self.uuid,
            "update_result_uuid": self.update_result_uuid,
            "date": self.date.isoformat() if self.date else None,
            "name_rule": self.name_rule,
            "rule_id": self.rule_id,
            "message": self.message,
            "found": self.found,
            "update_available": self.update_available,
            "rule_syntax_valid": self.rule_syntax_valid,
            "error": self.error,
            "history_id": self.history_id,
        }


# ============================
# NewRule Table
# ============================
class NewRule(Base):
    """
    Represents a new rule that was discovered during an update process.
    For example, a rule that did not previously exist locally but was found in a remote source.
    """
    __tablename__ = "new_rules"

    uuid = Column(String, primary_key=True, default=lambda: str(uuid4()))
    update_result_uuid = Column(String, ForeignKey("update_results.uuid", ondelete="CASCADE"), nullable=False)

    date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))  # When the new rule was found
    name_rule = Column(String, nullable=False)             # The name of the new rule
    rule_content = Column(Text, nullable=False)            # Full rule content (e.g., the rule body)
    message = Column(Text, nullable=True)                  # Optional log or message
    
    rule_syntax_valid = Column(Boolean, default=True)      # Whether the new rule’s syntax is valid
    error = Column(Boolean, default=False)                 # Whether an error occurred during validation
    accept = Column(Boolean, default=False)                # Whether the new rule was accepted/imported

    update_result = relationship("UpdateResult", back_populates="new_rules")

    def to_json(self):
        return {
            "uuid": self.uuid,
            "update_result_uuid": self.update_result_uuid,
            "date": self.date.isoformat() if self.date else None,
            "name_rule": self.name_rule,
            "rule_content": self.rule_content,
            "message": self.message,
            "rule_syntax_valid": self.rule_syntax_valid,
            "error": self.error,
            "accept": self.accept,
        }
