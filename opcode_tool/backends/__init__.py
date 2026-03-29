"""Backend registry for OpCodeReverseTool."""

BACKEND_REGISTRY = {}


def get_backend(name: str):
    """Get a backend class by name.

    Args:
        name: Backend name (e.g., 'ghidra', 'radare2').

    Returns:
        Backend class.

    Raises:
        ValueError: If backend name is not registered.
    """
    if name not in BACKEND_REGISTRY:
        available = ', '.join(BACKEND_REGISTRY.keys())
        raise ValueError(f"Unknown backend '{name}'. Available: {available}")
    return BACKEND_REGISTRY[name]
