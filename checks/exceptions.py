import logging
import sys

def setup_logger(name: str = "SecAudit") -> logging.Logger:
    """Configures enterprise-standard structured console logging."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levename)-8s | %(names)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

class SecurityAuditError(Exception):
    """Base exception for all security audit suite errors."""
    pass

class ConfigurationError(Exception):
    """Raised when required inputs, port lists, or paths are misconfigured."""
    pass

class TargetUnreachableError(SecurityAuditError):
    """Raised when a target host cannot be resolved or reached."""
    pass