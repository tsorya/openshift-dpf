"""
Utility functions for OpenShift DPF.

This module provides common utilities including logging, file operations,
retry mechanisms, and template processing.
"""

import functools
import hashlib
import ipaddress
import os
import random
import re
import shlex
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

import yaml
from jinja2 import Environment, FileSystemLoader, Template

# Type variable for generic functions
T = TypeVar("T")


# ============================================================================
# Logging Functions
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"  # No Color


def _log(level: str, color: str, message: str) -> None:
    """Internal logging function."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{color}[{timestamp}] [{level}] {message}{Colors.NC}", file=sys.stderr)


def log_info(message: str) -> None:
    """Log an info message."""
    _log("INFO", Colors.GREEN, message)


def log_warning(message: str) -> None:
    """Log a warning message."""
    _log("WARNING", Colors.YELLOW, message)


def log_error(message: str) -> None:
    """Log an error message."""
    _log("ERROR", Colors.RED, message)


def log_debug(message: str) -> None:
    """Log a debug message."""
    _log("DEBUG", Colors.CYAN, message)


def log_step(message: str) -> None:
    """Log a step/section message."""
    _log("STEP", Colors.PURPLE, f"=== {message} ===")


# ============================================================================
# Retry Mechanism
# ============================================================================

def retry(
    max_attempts: int = 3,
    delay: float = 5.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
) -> Callable:
    """
    Decorator for retrying a function on failure.
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
        exceptions: Tuple of exceptions to catch
    
    Returns:
        Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            current_delay = delay
            last_exception: Optional[Exception] = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        log_warning(
                            f"Attempt {attempt}/{max_attempts} failed: {e}. "
                            f"Retrying in {current_delay:.1f}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        log_error(f"All {max_attempts} attempts failed")
            
            if last_exception is not None:
                raise last_exception
            raise RuntimeError("Unexpected error in retry logic")
        
        return wrapper
    return decorator


def retry_on_failure(
    func: Callable[..., T],
    max_attempts: int = 3,
    delay: float = 5.0,
    *args: Any,
    **kwargs: Any,
) -> Optional[T]:
    """
    Retry a function on failure.
    
    Args:
        func: Function to retry
        max_attempts: Maximum number of attempts
        delay: Delay between retries in seconds
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
    
    Returns:
        Function result or None on failure
    """
    for attempt in range(1, max_attempts + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt < max_attempts:
                log_warning(f"Attempt {attempt}/{max_attempts} failed: {e}. Retrying...")
                time.sleep(delay)
            else:
                log_error(f"All {max_attempts} attempts failed: {e}")
                return None
    return None


# ============================================================================
# File Operations
# ============================================================================

def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure a directory exists, creating it if necessary."""
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def file_exists(path: Union[str, Path]) -> bool:
    """Check if a file exists."""
    return Path(path).exists()


def read_file(path: Union[str, Path]) -> str:
    """Read a file and return its contents."""
    with open(path, 'r') as f:
        return f.read()


def write_file(path: Union[str, Path], content: str, mode: int = 0o644) -> None:
    """Write content to a file."""
    file_path = Path(path)
    ensure_directory(file_path.parent)
    with open(file_path, 'w') as f:
        f.write(content)
    os.chmod(file_path, mode)


def copy_file(src: Union[str, Path], dst: Union[str, Path]) -> None:
    """Copy a file."""
    src_path = Path(src)
    dst_path = Path(dst)
    ensure_directory(dst_path.parent)
    shutil.copy2(src_path, dst_path)


def copy_directory(
    src: Union[str, Path],
    dst: Union[str, Path],
    exclude_patterns: Optional[List[str]] = None,
) -> None:
    """
    Copy a directory recursively, optionally excluding certain patterns.
    
    Args:
        src: Source directory
        dst: Destination directory
        exclude_patterns: List of glob patterns to exclude
    """
    src_path = Path(src)
    dst_path = Path(dst)
    exclude_patterns = exclude_patterns or []
    
    if not src_path.is_dir():
        log_error(f"Source directory does not exist: {src_path}")
        return
    
    ensure_directory(dst_path)
    
    for item in src_path.iterdir():
        # Check if item matches any exclude pattern
        excluded = False
        for pattern in exclude_patterns:
            if item.match(pattern):
                excluded = True
                break
        
        if excluded:
            continue
        
        dst_item = dst_path / item.name
        
        if item.is_dir():
            copy_directory(item, dst_item, exclude_patterns)
        else:
            copy_file(item, dst_item)


def delete_file(path: Union[str, Path]) -> bool:
    """Delete a file if it exists."""
    try:
        Path(path).unlink(missing_ok=True)
        return True
    except Exception as e:
        log_error(f"Failed to delete file {path}: {e}")
        return False


def delete_directory(path: Union[str, Path]) -> bool:
    """Delete a directory recursively."""
    try:
        shutil.rmtree(path, ignore_errors=True)
        return True
    except Exception as e:
        log_error(f"Failed to delete directory {path}: {e}")
        return False


# ============================================================================
# YAML Operations
# ============================================================================

def load_yaml(path: Union[str, Path]) -> Any:
    """Load a YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def load_yaml_all(path: Union[str, Path]) -> List[Any]:
    """Load a multi-document YAML file."""
    with open(path, 'r') as f:
        return list(yaml.safe_load_all(f))


def save_yaml(path: Union[str, Path], data: Any) -> None:
    """Save data to a YAML file."""
    ensure_directory(Path(path).parent)
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)


def save_yaml_all(path: Union[str, Path], documents: List[Any]) -> None:
    """Save multiple documents to a YAML file."""
    ensure_directory(Path(path).parent)
    with open(path, 'w') as f:
        yaml.dump_all(documents, f, default_flow_style=False)


# ============================================================================
# Template Processing
# ============================================================================

def process_template(
    template_path: Union[str, Path],
    output_path: Union[str, Path],
    variables: Dict[str, Any],
) -> bool:
    """
    Process a Jinja2 template file.
    
    Args:
        template_path: Path to the template file
        output_path: Path for the output file
        variables: Dictionary of template variables
    
    Returns:
        True if successful, False otherwise
    """
    try:
        template_file = Path(template_path)
        output_file = Path(output_path)
        
        # Create Jinja2 environment
        env = Environment(
            loader=FileSystemLoader(template_file.parent),
            keep_trailing_newline=True,
        )
        
        template = env.get_template(template_file.name)
        rendered = template.render(**variables)
        
        write_file(output_file, rendered)
        log_debug(f"Processed template {template_file} -> {output_file}")
        return True
        
    except Exception as e:
        log_error(f"Failed to process template {template_path}: {e}")
        return False


def process_template_string(
    template_string: str,
    variables: Dict[str, Any],
) -> str:
    """
    Process a Jinja2 template string.
    
    Args:
        template_string: Template string
        variables: Dictionary of template variables
    
    Returns:
        Rendered template string
    """
    template = Template(template_string)
    return template.render(**variables)


def substitute_env_vars(content: str) -> str:
    """
    Substitute environment variable placeholders in content.
    
    Supports both ${VAR} and $VAR syntax.
    """
    def replace_var(match: re.Match) -> str:
        var_name = match.group(1) or match.group(2)
        return os.environ.get(var_name, match.group(0))
    
    # Match ${VAR} or $VAR patterns
    pattern = r'\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)'
    return re.sub(pattern, replace_var, content)


# ============================================================================
# String Utilities
# ============================================================================

def escape_for_sed(value: str) -> str:
    """Escape special characters for use in sed replacement."""
    special_chars = r'\/&'
    result = value
    for char in special_chars:
        result = result.replace(char, f'\\{char}')
    return result


def generate_mac_address() -> str:
    """Generate a random MAC address."""
    # Use locally administered address (second hex digit is 2, 6, A, or E)
    mac = [
        0x52,  # Locally administered
        0x54,  # QEMU range
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    ]
    return ':'.join(f'{b:02x}' for b in mac)


def generate_random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def compute_md5(content: Union[str, bytes]) -> str:
    """Compute MD5 hash of content."""
    if isinstance(content, str):
        content = content.encode()
    return hashlib.md5(content).hexdigest()


# ============================================================================
# Command Execution (for tools that don't have Python libraries)
# ============================================================================

@dataclass
class CommandResult:
    """Result of a command execution."""
    
    returncode: int
    stdout: str
    stderr: str
    success: bool
    
    @property
    def output(self) -> str:
        """Combined stdout and stderr."""
        return self.stdout + self.stderr


def run_command(
    command: Union[str, List[str]],
    check: bool = False,
    capture: bool = True,
    shell: bool = False,
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Union[str, Path]] = None,
) -> CommandResult:
    """
    Run a command and return the result.
    
    Args:
        command: Command to run (string or list)
        check: Raise exception on non-zero exit code
        capture: Capture stdout/stderr
        shell: Run through shell
        timeout: Command timeout in seconds
        env: Environment variables
        cwd: Working directory
    
    Returns:
        CommandResult with returncode, stdout, stderr, and success flag
    """
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    
    # Merge environment
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    
    try:
        result = subprocess.run(
            command,
            capture_output=capture,
            shell=shell,
            timeout=timeout,
            env=run_env,
            cwd=cwd,
            text=True,
        )
        
        return CommandResult(
            returncode=result.returncode,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            success=result.returncode == 0,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=124,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            success=False,
        )
    except Exception as e:
        return CommandResult(
            returncode=1,
            stdout="",
            stderr=str(e),
            success=False,
        )


def run_command_with_output(
    command: Union[str, List[str]],
    shell: bool = False,
) -> Optional[str]:
    """
    Run a command and return stdout if successful.
    
    Args:
        command: Command to run
        shell: Run through shell
    
    Returns:
        stdout if successful, None otherwise
    """
    result = run_command(command, shell=shell)
    if result.success:
        return result.stdout.strip()
    return None


# ============================================================================
# Verification Functions
# ============================================================================

def verify_files(config: Any) -> bool:
    """
    Verify that required files exist.
    
    Args:
        config: Configuration object with file paths
    
    Returns:
        True if all required files exist
    """
    required_files = []
    
    # Check pull secret
    if hasattr(config, 'pull_secret_path') and config.pull_secret_path:
        required_files.append(config.pull_secret_path)
    
    # Check SSH key
    if hasattr(config, 'ssh_public_key_path') and config.ssh_public_key_path:
        required_files.append(config.ssh_public_key_path)
    
    all_exist = True
    for file_path in required_files:
        if not file_exists(file_path):
            log_error(f"Required file not found: {file_path}")
            all_exist = False
        else:
            log_debug(f"Found required file: {file_path}")
    
    return all_exist


def verify_command_exists(command: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(command) is not None


def verify_commands(*commands: str) -> bool:
    """Check if all required commands exist in PATH."""
    all_exist = True
    for cmd in commands:
        if not verify_command_exists(cmd):
            log_error(f"Required command not found: {cmd}")
            all_exist = False
    return all_exist


# ============================================================================
# IP Address Utilities
# ============================================================================

def is_valid_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address (v4 or v6)."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def get_ip_version(ip: str) -> Optional[int]:
    """Get the IP version (4 or 6) or None if invalid."""
    if is_valid_ipv4(ip):
        return 4
    if is_valid_ipv6(ip):
        return 6
    return None


# ============================================================================
# Wait Utilities (using Kubernetes client)
# ============================================================================

def wait_with_timeout(
    condition_func: Callable[[], bool],
    timeout: int = 300,
    interval: int = 10,
    message: str = "Waiting for condition",
) -> bool:
    """
    Wait for a condition to be true.
    
    Args:
        condition_func: Function that returns True when condition is met
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        message: Message to log while waiting
    
    Returns:
        True if condition was met, False if timeout occurred
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            if condition_func():
                return True
        except Exception as e:
            log_debug(f"Condition check failed: {e}")
        
        elapsed = int(time.time() - start_time)
        log_debug(f"{message} ({elapsed}s/{timeout}s)")
        time.sleep(interval)
    
    log_error(f"Timeout waiting for condition: {message}")
    return False
