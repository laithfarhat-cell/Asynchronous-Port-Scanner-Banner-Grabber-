"""Target/port parsing: the part where a typo becomes a 65k-port accident."""

from __future__ import annotations

import ipaddress

import pytest

from core.parser import (
    PortParseError,
    TargetParseError,
    build_targets,
    load_top_ports,
    parse_ports,
    shuffle_ports,
)


class TestPorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_list_is_sorted_and_deduplicated(self):
        assert parse_ports("443,80,22,80") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]

    def test_reversed_range_is_normalised(self):
        assert parse_ports("25-20") == [20, 21, 22, 23, 24, 25]

    def test_mixed_spec(self):
        assert parse_ports("1-3,10,12-13") == [1, 2, 3, 10, 12, 13]

    def test_whitespace_is_tolerated(self):
        assert parse_ports(" 22 , 80 ") == [22, 80]

    def test_all(self):
        assert len(parse_ports("all")) == 65535

    @pytest.mark.parametrize("spec", ["0", "65536", "70000", "-1"])
    def test_out_of_range(self, spec):
        with pytest.raises(PortParseError):
            parse_ports(spec)

    @pytest.mark.parametrize("spec", ["http", "80-", "abc", "1-2-3"])
    def test_invalid(self, spec):
        with pytest.raises(PortParseError):
            parse_ports(spec)

    def test_requires_a_selector(self):
        with pytest.raises(PortParseError):
            parse_ports()

    def test_max_ports_guard(self):
        with pytest.raises(PortParseError):
            parse_ports("all", max_ports=1000)

    def test_top_ports_100(self):
        ports = parse_ports(top_ports=100)
        assert len(ports) == 100
        assert 22 in ports and 80 in ports and 443 in ports
        assert ports == sorted(ports)

    def test_top_ports_1000(self):
        assert len(load_top_ports(1000)) == 1000

    def test_top_ports_combined_with_spec(self):
        ports = parse_ports("31337", top_ports=100)
        assert 31337 in ports and len(ports) == 101

    def test_unsupported_preset(self):
        with pytest.raises(PortParseError):
            load_top_ports(42)

    def test_shuffle_is_a_permutation(self):
        ports = list(range(1, 51))
        shuffled = shuffle_ports(ports, seed=7)
        assert sorted(shuffled) == ports and shuffled != ports


class TestTargets:
    async def test_single_ipv4(self):
        report = await build_targets(["192.168.1.10"])
        assert [t.ip for t in report.targets] == ["192.168.1.10"]
        assert not report.targets[0].is_ipv6

    async def test_multiple_targets_comma_separated(self):
        report = await build_targets(["10.0.0.1,10.0.0.2"])
        assert [t.ip for t in report.targets] == ["10.0.0.1", "10.0.0.2"]

    async def test_ipv6(self):
        report = await build_targets(["::1"])
        assert report.targets[0].ip == "::1"
        assert report.targets[0].is_ipv6

    async def test_cidr_24(self):
        report = await build_targets(["192.168.1.0/24"])
        assert len(report.targets) == 254
        assert report.targets[0].ip == "192.168.1.1"
        assert report.targets[-1].ip == "192.168.1.254"

    async def test_cidr_31_keeps_both_addresses(self):
        report = await build_targets(["10.0.0.0/31"])
        assert [t.ip for t in report.targets] == ["10.0.0.0", "10.0.0.1"]

    async def test_host_cidr_is_normalised(self):
        report = await build_targets(["192.168.5.7/24"])
        assert len(report.targets) == 254
        assert "192.168.5.7" in {t.ip for t in report.targets}

    async def test_cidr_truncation_warns(self):
        report = await build_targets(["10.0.0.0/16"], max_hosts=10)
        assert len(report.targets) == 10
        assert report.truncated is True
        assert any("truncated" in warning for warning in report.warnings)

    async def test_invalid_cidr(self):
        with pytest.raises(TargetParseError):
            await build_targets(["10.0.0.0/33"])

    async def test_duplicates_are_dropped(self):
        report = await build_targets(["10.0.0.1", "10.0.0.1", "10.0.0.1/32"])
        assert len(report.targets) == 1
        assert report.duplicates_skipped >= 1

    async def test_no_targets(self):
        with pytest.raises(TargetParseError):
            await build_targets([])

    async def test_target_file(self, tmp_path):
        path = tmp_path / "targets.txt"
        path.write_text(
            "# comment line\n10.1.1.1\n\n10.1.1.2  # inline comment\n127.0.0.1\n",
            encoding="utf-8",
        )
        report = await build_targets([], [str(path)])
        assert [t.ip for t in report.targets] == ["10.1.1.1", "10.1.1.2", "127.0.0.1"]

    async def test_missing_target_file(self):
        with pytest.raises(TargetParseError):
            await build_targets([], ["/nonexistent/targets.txt"])

    async def test_hostname_resolution(self):
        report = await build_targets(["localhost"])
        assert report.targets
        assert all(t.hostname == "localhost" for t in report.targets)
        for target in report.targets:
            ipaddress.ip_address(target.ip)  # must be a real address

    async def test_hostname_without_resolution(self):
        report = await build_targets(["example.invalid"], resolve_dns=False)
        assert report.targets[0].ip == "example.invalid"

    async def test_unresolvable_hostname_aborts_with_reason(self):
        with pytest.raises(TargetParseError) as excinfo:
            await build_targets(["does-not-exist.invalid"], dns_timeout=2.0)
        assert "does-not-exist.invalid" in str(excinfo.value)

    async def test_partially_unresolvable_scope_keeps_good_hosts(self):
        report = await build_targets(["127.0.0.1", "does-not-exist.invalid"], dns_timeout=2.0)
        assert [t.ip for t in report.targets] == ["127.0.0.1"]
        assert report.unresolved

    async def test_inline_port_is_ignored_with_warning(self):
        report = await build_targets(["10.0.0.5:8080"])
        assert report.targets[0].ip == "10.0.0.5"
        assert any("inline port" in w for w in report.warnings)

    async def test_max_hosts_enforced_for_hostnames(self):
        with pytest.raises(TargetParseError):
            await build_targets(["localhost", "example.com"], max_hosts=1)
