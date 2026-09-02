import unittest

from features.ztp.core import config_template as tmpl


def _device(**overrides):
    device = {
        "hostname": "TTC-SWAC-TEST-01",
        "mgmt_ip": "10.50.1.11",
        "mgmt_mask": "255.255.255.0",
        "gateway": "10.50.1.1",
        "vrp_username": "keystone-ztp",
        "vrp_password": "Str0ngP@ssw0rd!",
    }
    device.update(overrides)
    return device


class ConfigTemplateTests(unittest.TestCase):
    def test_requires_hostname(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(hostname=""))

    def test_requires_mgmt_ip(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(mgmt_ip=""))

    def test_requires_username(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(vrp_username=""))

    def test_requires_password(self):
        # This is the field Huawei's doc calls out explicitly: without
        # a working remote-login credential in the deployment config,
        # "the configuration file cannot be successfully set."
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(vrp_password=""))

    def test_contains_sysname_and_mgmt_ip(self):
        text = tmpl.render_bootstrap_config(_device())
        self.assertIn("sysname TTC-SWAC-TEST-01", text)
        self.assertIn("ip address 10.50.1.11 255.255.255.0", text)

    def test_contains_ssh_enablement(self):
        text = tmpl.render_bootstrap_config(_device())
        self.assertIn("stelnet server enable", text)
        self.assertIn("ssh user keystone-ztp authentication-type password", text)

    def test_vty_allows_telnet_fallback_alongside_ssh(self):
        # Regression, confirmed against real hardware: VRP validates a
        # config file before accepting it as next-startup config and
        # refuses one that would strand you with no working login path
        # ("Set the next startup saved-configuration file failed...
        # The configuration file will cause the next startup login
        # failure."). `rsa local-key-pair create` is a runtime ACTION,
        # not a config directive -- pushing it through ZTP is CONFIRMED
        # (not just suspected) to make VRP reject the whole file this
        # way, every time, even when a key already exists on the
        # device. This module deliberately does not emit that line at
        # all (see config_template.py's module docstring) and relies
        # on telnet -- same local-user, no RSA key required -- as the
        # login path VRP will actually accept.
        text = tmpl.render_bootstrap_config(_device())
        self.assertIn("telnet server enable", text)
        self.assertIn("protocol inbound all", text)
        self.assertNotIn("protocol inbound ssh", text)
        # The VTY-level fallback is useless if the local-user itself
        # isn't permitted to use telnet -- VRP checks both.
        self.assertIn("local-user keystone-ztp service-type ssh telnet", text)

    def test_contains_local_user_with_password(self):
        text = tmpl.render_bootstrap_config(_device())
        self.assertIn("local-user keystone-ztp password irreversible-cipher Str0ngP@ssw0rd!", text)

    def test_disables_aaa_complexity_check_and_forced_password_change(self):
        # Regression: Huawei's default AAA local-user complexity check
        # rejects short usernames on real hardware (confirmed against
        # a real switch) -- without these two lines, a device
        # pre-registered with a short vrp_username (e.g. "mlpt")
        # deploys "successfully" but the local-user command itself is
        # silently rejected by the switch, leaving it unreachable.
        text = tmpl.render_bootstrap_config(_device())
        self.assertIn("local-aaa-user user-name complexity-check disable", text)
        self.assertIn("local-user keystone-ztp password-force-change disable", text)
        self.assertIn("local-user keystone-ztp privilege level 3", text)

    def test_short_username_like_mlpt_is_accepted(self):
        text = tmpl.render_bootstrap_config(_device(vrp_username="mlpt"))
        self.assertIn("local-user mlpt password irreversible-cipher Str0ngP@ssw0rd!", text)
        self.assertIn("local-user mlpt privilege level 3", text)
        self.assertIn("local-user mlpt service-type ssh", text)

    def test_aaa_block_is_closed_with_quit(self):
        text = tmpl.render_bootstrap_config(_device())
        aaa_index = text.index("\naaa\n")
        quit_index = text.index("\n quit\n", aaa_index)
        self.assertGreater(quit_index, aaa_index)

    def test_gateway_route_only_added_when_present(self):
        with_gateway = tmpl.render_bootstrap_config(_device(gateway="10.50.1.1"))
        self.assertIn("ip route-static 0.0.0.0 0.0.0.0 10.50.1.1", with_gateway)

        without_gateway = tmpl.render_bootstrap_config(_device(gateway=""))
        self.assertNotIn("ip route-static", without_gateway)

    def test_ends_with_return(self):
        text = tmpl.render_bootstrap_config(_device())
        self.assertTrue(text.rstrip().endswith("return"))

    def test_sysname_sanitizes_invalid_characters(self):
        text = tmpl.render_bootstrap_config(_device(hostname="TTC SWAC Test #1!"))
        self.assertIn("sysname TTC-SWAC-Test-1", text)

    # ------------------------------------------------------------------
    # Regression (production-debugger pass): every field here gets
    # interpolated RAW into an f-string config line -- mgmt_ip,
    # mgmt_mask, gateway, vrp_username, vrp_password had NO validation
    # at all before this. A value containing a newline would inject an
    # extra, arbitrary line into the generated VRP config (VRP configs
    # are strictly line-oriented); an mgmt_ip/mgmt_mask/gateway that
    # isn't a real IPv4 address would silently produce a config VRP
    # rejects at apply time for a reason that has nothing to do with
    # what the operator actually got wrong.
    # ------------------------------------------------------------------

    def test_rejects_newline_in_password(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(
                _device(vrp_password="Str0ngP@ss!\ntelnet server enable")
            )

    def test_rejects_newline_in_username(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(vrp_username="admin\nsysname pwned"))

    def test_rejects_carriage_return_in_password(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(vrp_password="Str0ngP@ss!\rinjected"))

    def test_rejects_non_ipv4_mgmt_ip(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(mgmt_ip="not-an-ip"))

    def test_rejects_non_ipv4_mgmt_mask(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(mgmt_mask="not-a-mask"))

    def test_rejects_non_ipv4_gateway(self):
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(gateway="not-a-gateway"))

    def test_rejects_newline_in_mgmt_ip(self):
        # A newline can't be a valid IPv4 address either way, but
        # pin this down explicitly since it's the actual injection
        # vector, not just a format mismatch.
        with self.assertRaises(tmpl.ConfigTemplateError):
            tmpl.render_bootstrap_config(_device(mgmt_ip="10.50.1.11\ntelnet server enable"))

    def test_valid_ipv4_fields_are_still_accepted(self):
        # Make sure the new validation doesn't reject legitimate input.
        text = tmpl.render_bootstrap_config(_device(
            mgmt_ip="192.168.99.10", mgmt_mask="255.255.255.0", gateway="192.168.99.1",
        ))
        self.assertIn("ip address 192.168.99.10 255.255.255.0", text)
        self.assertIn("ip route-static 0.0.0.0 0.0.0.0 192.168.99.1", text)


if __name__ == "__main__":
    unittest.main()
