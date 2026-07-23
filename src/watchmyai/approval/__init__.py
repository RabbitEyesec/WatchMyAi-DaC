"""Local approval token service: single-use, short-lived, tightly bound."""

from watchmyai.approval.service import Approval, ApprovalService, ConsumeResult

__all__ = ["Approval", "ApprovalService", "ConsumeResult"]
