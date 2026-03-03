import logging
import os
from logging.handlers import RotatingFileHandler
import sys

def setup_logger(name: str, log_dir: str = "logs", level=logging.INFO):
    """
    Sets up a logger with console and file handlers.
    
    Args:
        name: Name of the logger (usually __name__).
        log_dir: Directory to save log files.
        level: Logging level.
        
    Returns:
        A configured Logger instance.
    """
    
    # Define log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Resolve absolute path for log directory
    # Assumes this file is in Implementation/utils/
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    abs_log_dir = os.path.join(base_dir, log_dir)
    
    if not os.path.exists(abs_log_dir):
        os.makedirs(abs_log_dir, exist_ok=True)
        
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to prevent duplicates
    if logger.handlers:
        logger.handlers.clear()
        
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File Handler (Rotating)
    log_file = os.path.join(abs_log_dir, "app.log")
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger
