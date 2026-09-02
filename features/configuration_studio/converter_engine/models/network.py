from dataclasses import dataclass, field


@dataclass
class BaseConfig:
    """
    Base model untuk semua jenis network device.
    """

    hostname: str = ""

    # Source information
    source_vendor: str = ""
    source_device_type: str = ""
    source_model: str = ""

    # Target information
    target_vendor: str = ""
    target_device_type: str = ""
    target_model: str = ""

    # Original source filename
    source_file: str = ""

    # Commands yang tidak berhasil dikonversi otomatis
    review_commands: list[str] = field(
        default_factory=list
    )

    # Warning selama proses parsing / translation
    warnings: list[str] = field(
        default_factory=list
    )

    # Metadata tambahan
    metadata: dict = field(
        default_factory=dict
    )