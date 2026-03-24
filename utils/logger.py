import logging
import sys


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[94m",   # Blue
        "INFO":     "\033[92m",   # Green
        "WARNING":  "\033[93m",   # Yellow
        "ERROR":    "\033[91m",   # Red
        "CRITICAL": "\033[95m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    LEVEL_ICONS = {
        "DEBUG":    "[~]",
        "INFO":     "[+]",
        "WARNING":  "[!]",
        "ERROR":    "[-]",
        "CRITICAL": "[✖]",
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        icon = self.LEVEL_ICONS.get(record.levelname, "[*]")
        msg = super().format(record)
        return f"{color}{self.BOLD}{icon}{self.RESET} {msg}"


def get_logger(name="GhostGateway", level=logging.DEBUG):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger
