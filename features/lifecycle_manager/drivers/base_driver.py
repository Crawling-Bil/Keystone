class ConfigPushError(RuntimeError):
    """Raised by push_config_lines() when the device rejects a line, or
    the transport itself fails partway through a draft.

    Carries `.results` -- the same list of {"line", "status", "output"}
    dicts the method would have returned on full success, but stopping
    at (and including) the line that triggered the abort. A caller
    must not let this collapse to just the RuntimeError message: the
    whole point of Config Push's "monitor what actually got pushed"
    requirement is that a partial/aborted push still tells the
    operator exactly which lines were applied before it stopped, not
    only that something went wrong.
    """

    def __init__(self, message, results=None):
        super().__init__(message)
        self.results = list(results) if results is not None else []


class BaseDriver:

    def __init__(self, connection, log_fn=None):
        self.connection = connection
        self._log_fn = log_fn or (lambda command: None)

    def _log(self, command):
        try:
            self._log_fn(command)
        except Exception:
            pass

    def connect(self):
        return self.connection

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()

    def get_device_info(self):
        raise NotImplementedError("get_device_info is not implemented for this driver")

    def get_storage_info(self):
        raise NotImplementedError("get_storage_info is not implemented for this driver")

    def check_free_space(self, required_size):
        return None

    def firmware_exists(self, filename):
        try:
            listing = self.get_storage_info() or ""
        except Exception:
            return False
        # Match the filename as its own token (the last column of a
        # directory-listing line), not just anywhere in the raw text —
        # a bare substring match can false-positive on partial/incidental
        # text and cause the real transfer step to be silently skipped.
        for line in listing.splitlines():
            tokens = line.strip().split()
            if tokens and tokens[-1] == filename:
                return True
        return False

    def backup_config(self):
        raise NotImplementedError("Configuration backup is not implemented for this driver")

    def push_config_lines(self, lines, on_result=None):
        """Apply a batch of raw CLI configuration lines to the device,
        one at a time, so each line's own success/failure is
        individually visible to the caller (Zero Touch config push's
        "monitor what actually got pushed" requirement).

        `on_result`, if given, is called with a single {"line",
        "status", "output"} dict the moment EACH line's result is
        known -- i.e. as the push happens, not only once the whole
        batch finishes. This is what lets a caller show the operator a
        live, per-command success/fail view (comment thread request:
        "kaya live ssh gitu") instead of a single lump of results
        revealed only at the end. It is additive: a driver must still
        return the full list of {"line", "status", "output"} dicts (or
        raise ConfigPushError carrying the partial list) exactly as
        before -- on_result is a progress notification, not a
        replacement for the return value/exception contract below.
        Implementations should tolerate on_result raising (the caller
        streaming a result into a UI is not a reason to abort a config
        push) the same way _log()/BaseDriver._log already swallows
        logging callback errors.

        Returns a list of {"line", "status", "output"} dicts in the
        order the lines were sent, on full success. Must raise
        ConfigPushError -- not a plain RuntimeError -- on the first
        line the device rejects rather than silently continuing: a
        partially-applied draft config is something the operator needs
        to find out about immediately, not later by diffing
        `display current-configuration` by hand, and ConfigPushError's
        `.results` attribute is how the caller recovers exactly what
        was already applied before the abort.
        """
        raise NotImplementedError("Config push is not implemented for this driver")

    def capture_config(self, commands, on_result=None):
        """Run a fixed list of read-only `display`-style commands
        against the device and return each one's raw output --
        Config Capture / Backup's "snapshot everything the device is
        currently running" primitive.

        Unlike push_config_lines(), this never mutates device state,
        so there is no reason to abort the whole batch just because
        one command errors (an unsupported command on a given
        platform/version, for instance) -- each command is
        independent, so a failure is recorded and the rest still run.

        `on_result`, if given, is called with a single {"line",
        "status", "output"} dict the moment EACH command's result is
        known, exactly like push_config_lines()'s on_result -- reusing
        the same shape (and the "line" key, here holding the command
        text rather than a config line) is deliberate: it lets the
        existing live-command UI render a capture job's progress with
        no changes at all.

        Returns a list of {"line", "status", "output"} dicts in the
        order the commands were run. Never raises for an individual
        command's failure; only a transport-level problem (e.g. the
        SSH session itself dying) should propagate up.
        """
        raise NotImplementedError("Config capture is not implemented for this driver")

    def copy_firmware(self, protocol, server, filename):
        raise NotImplementedError("Firmware transfer is not implemented for this driver")

    def verify_md5(self, filename, checksum):
        raise NotImplementedError("Checksum verification is not implemented for this driver")

    def save_config(self):
        raise NotImplementedError("Saving configuration is not implemented for this driver")

    def install_firmware(self, filename):
        raise NotImplementedError("Firmware installation is not implemented for this driver")

    def reload_device(self):
        raise NotImplementedError("Device reload is not implemented for this driver")

    def wait_until_online(self, timeout=600):
        raise NotImplementedError("Reconnect check is not implemented for this driver")

    def post_check(self):
        return self.get_device_info()
