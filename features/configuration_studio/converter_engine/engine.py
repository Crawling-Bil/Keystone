from importlib import import_module

from features.configuration_studio.converter_engine.detector import DeviceDetector
from features.configuration_studio.converter_engine.inventory import Inventory


class MigrationEngine:

    def __init__(
        self,
        inventory_file=(
            "mappings/migration_inventory.csv"
        )
    ):

        self.detector = DeviceDetector()

        self.inventory = Inventory(
            inventory_file
        )

        # ====================================================
        # PARSER REGISTRY
        # ====================================================

        self.parser_registry = {

            # SWITCH

            (
                "switch",
                "cisco"
            ): (
                "features.configuration_studio.converter_engine.parsers.switch.cisco",
                "CiscoSwitchParser"
            ),

            (
                "switch",
                "aruba"
            ): (
                "features.configuration_studio.converter_engine.parsers.switch.aruba",
                "ArubaSwitchParser"
            ),

            (
                "switch",
                "huawei"
            ): (
                "features.configuration_studio.converter_engine.parsers.switch.huawei",
                "HuaweiSwitchParser"
            ),

            # FIREWALL

            (
                "firewall",
                "mikrotik"
            ): (
                "features.configuration_studio.converter_engine.parsers.firewall.mikrotik",
                "MikrotikFirewallParser"
            ),

            (
                "firewall",
                "palo alto"
            ): (
                "features.configuration_studio.converter_engine.parsers.firewall.paloalto",
                "PaloAltoFirewallParser"
            ),
        }

        # ====================================================
        # TRANSLATOR REGISTRY
        # ====================================================

        self.translator_registry = {

            # SWITCH

            (
                "switch",
                "cisco"
            ): (
                "features.configuration_studio.converter_engine.translators.switch.cisco",
                "CiscoSwitchTranslator"
            ),

            (
                "switch",
                "aruba"
            ): (
                "features.configuration_studio.converter_engine.translators.switch.aruba",
                "ArubaSwitchTranslator"
            ),

            (
                "switch",
                "huawei"
            ): (
                "features.configuration_studio.converter_engine.translators.switch.huawei",
                "HuaweiSwitchTranslator"
            ),

            # FIREWALL

            (
                "firewall",
                "palo alto"
            ): (
                "features.configuration_studio.converter_engine.translators.firewall.paloalto",
                "PaloAltoFirewallTranslator"
            ),
        }

    # ========================================================
    # NORMALIZE
    # ========================================================

    @staticmethod
    def normalize(value):

        return (
            str(value)
            .strip()
            .lower()
        )

    @staticmethod
    def is_auto(value):

        return (
            str(value)
            .strip()
            .lower()
            in (
                "",
                "auto",
                "auto detect",
            )
        )

    # ========================================================
    # DETECT
    # ========================================================

    def detect(
        self,
        filename
    ):

        return (
            self.detector.detect_file(
                filename
            )
        )

    # ========================================================
    # DYNAMIC CLASS LOADER
    # ========================================================

    def load_class(
        self,
        module_path,
        class_name
    ):

        try:

            module = import_module(
                module_path
            )

        except ModuleNotFoundError as error:

            raise RuntimeError(
                "\nModule belum tersedia:\n"
                f"{module_path}\n\n"
                "Parser atau translator "
                "untuk platform ini "
                "belum dibuat."
            ) from error

        try:

            return getattr(
                module,
                class_name
            )

        except AttributeError as error:

            raise RuntimeError(
                "\nClass tidak ditemukan:\n"
                f"{class_name}\n\n"
                f"Module:\n"
                f"{module_path}"
            ) from error

    # ========================================================
    # GET PARSER
    # ========================================================

    def get_parser(
        self,
        vendor,
        device_type
    ):

        key = (
            self.normalize(
                device_type
            ),
            self.normalize(
                vendor
            )
        )

        parser_info = (
            self.parser_registry.get(
                key
            )
        )

        if not parser_info:

            raise ValueError(
                "Parser belum tersedia untuk "
                f"{vendor} {device_type}"
            )

        module_path = (
            parser_info[0]
        )

        class_name = (
            parser_info[1]
        )

        parser_class = (
            self.load_class(
                module_path,
                class_name
            )
        )

        return parser_class()

    # ========================================================
    # GET TRANSLATOR
    # ========================================================

    def get_translator(
        self,
        vendor,
        device_type
    ):

        key = (
            self.normalize(
                device_type
            ),
            self.normalize(
                vendor
            )
        )

        translator_info = (
            self.translator_registry.get(
                key
            )
        )

        if not translator_info:

            raise ValueError(
                "Translator belum tersedia "
                "untuk "
                f"{vendor} {device_type}"
            )

        module_path = (
            translator_info[0]
        )

        class_name = (
            translator_info[1]
        )

        translator_class = (
            self.load_class(
                module_path,
                class_name
            )
        )

        # Translator yang mendukung
        # inventory akan menerima object
        # inventory.
        #
        # Translator lain tetap bisa
        # berjalan tanpa inventory.

        try:

            return translator_class(
                inventory=self.inventory
            )

        except TypeError:

            return translator_class()

    # ========================================================
    # PARSE
    # ========================================================

    def parse(
        self,
        filename,
        source_vendor="Auto Detect",
        source_device_type="Auto Detect"
    ):

        detection = None

        if (
            self.is_auto(
                source_vendor
            )
            or
            self.is_auto(
                source_device_type
            )
        ):

            detection = self.detect(
                filename
            )

            if (
                detection.vendor
                == "Unknown"
                or
                detection.device_type
                == "Unknown"
            ):

                raise ValueError(
                    "Vendor atau device type "
                    "tidak dapat dideteksi."
                )

        if self.is_auto(
            source_vendor
        ):

            source_vendor = (
                detection.vendor
            )

        if self.is_auto(
            source_device_type
        ):

            source_device_type = (
                detection.device_type
            )

        parser = self.get_parser(
            vendor=source_vendor,
            device_type=(
                source_device_type
            )
        )

        config = parser.parse_file(
            filename
        )

        config.source_vendor = (
            source_vendor
        )

        config.source_device_type = (
            source_device_type
        )

        config.source_file = str(
            filename
        )

        # ====================================================
        # INVENTORY METADATA
        # ====================================================

        inventory_data = (
            self.inventory.get(
                config.hostname
            )
        )

        if inventory_data:

            # Kalau model source belum
            # didapat dari config,
            # gunakan inventory.

            if (
                hasattr(
                    config,
                    "model"
                )
                and
                not config.model
            ):

                config.model = (
                    self.inventory
                    .get_source_model(
                        config.hostname
                    )
                )

            # Simpan metadata kalau
            # model BaseConfig support.

            if hasattr(
                config,
                "metadata"
            ):

                config.metadata.update(
                    inventory_data
                )

        return config

    # ========================================================
    # TRANSLATE
    # ========================================================

    def translate(
        self,
        config,
        target_vendor,
        target_device_type=None,
        profile=None,
        target_model=None,
        mapping=None
    ):

        if not target_device_type:

            target_device_type = (
                config.source_device_type
            )

        source_type = (
            self.normalize(
                config.source_device_type
            )
        )

        target_type = (
            self.normalize(
                target_device_type
            )
        )

        # Jangan izinkan:
        #
        # Switch -> Firewall
        # Firewall -> WLC
        # WLC -> Switch

        if (
            source_type
            != target_type
        ):

            raise ValueError(
                "Cross-device-type migration "
                "belum diizinkan.\n\n"
                "Source : "
                f"{config.source_device_type}\n"
                "Target : "
                f"{target_device_type}"
            )

        translator = (
            self.get_translator(
                vendor=target_vendor,
                device_type=(
                    target_device_type
                )
            )
        )

        config.target_vendor = (
            target_vendor
        )

        config.target_device_type = (
            target_device_type
        )

        # Not every translator's translate() accepts a "profile" or
        # "target_model" kwarg yet (only HuaweiSwitchTranslator does,
        # as of the TAM standard-config profile layer / target-model
        # port-count check) — fall back to the plain call for any
        # translator that doesn't, rather than requiring every
        # translator to widen its signature just to stay callable.
        extra_kwargs = {}

        if profile is not None:
            extra_kwargs["profile"] = profile

        if target_model:
            extra_kwargs["target_model"] = target_model

        if mapping:
            extra_kwargs["mapping"] = mapping

        if extra_kwargs:

            try:

                return translator.translate(
                    config,
                    **extra_kwargs
                )

            except TypeError:
                pass

        return translator.translate(
            config
        )

    # ========================================================
    # FULL CONVERSION
    # ========================================================

    def convert(
        self,
        filename,
        target_vendor,
        source_vendor="Auto Detect",
        source_device_type="Auto Detect",
        target_device_type=None,
        profile=None,
        target_model=None,
        mapping=None
    ):

        config = self.parse(
            filename=filename,
            source_vendor=(
                source_vendor
            ),
            source_device_type=(
                source_device_type
            )
        )

        if not target_device_type:

            target_device_type = (
                config.source_device_type
            )

        output = self.translate(
            config=config,
            target_vendor=(
                target_vendor
            ),
            target_device_type=(
                target_device_type
            ),
            profile=profile,
            target_model=target_model,
            mapping=mapping
        )

        return (
            config,
            output
        )

    # ========================================================
    # SUPPORT CHECK
    # ========================================================

    def is_parser_supported(
        self,
        vendor,
        device_type
    ):

        key = (
            self.normalize(
                device_type
            ),
            self.normalize(
                vendor
            )
        )

        return (
            key
            in self.parser_registry
        )

    def is_translator_supported(
        self,
        vendor,
        device_type
    ):

        key = (
            self.normalize(
                device_type
            ),
            self.normalize(
                vendor
            )
        )

        return (
            key
            in self.translator_registry
        )

    # ========================================================
    # SUPPORTED PLATFORMS
    # ========================================================

    def get_supported_sources(
        self
    ):

        return [

            {
                "device_type": (
                    device_type
                ),
                "vendor": vendor,
            }

            for (
                device_type,
                vendor
            )
            in self.parser_registry
        ]

    def get_supported_targets(
        self
    ):

        return [

            {
                "device_type": (
                    device_type
                ),
                "vendor": vendor,
            }

            for (
                device_type,
                vendor
            )
            in self.translator_registry
        ]