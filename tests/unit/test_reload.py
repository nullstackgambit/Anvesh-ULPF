"""Hot-reload safety (finding P6-4): which configuration changes `ulpf spec
compile` may apply by Vector's hot reload, and which need a drained restart.

The configurations are the real generated live configs for the approved specs.
"""
import copy

import pytest

from ulpf import build, pipeline, settings
from ulpf.compile import compile_specs
from ulpf.spec import discover


@pytest.fixture(scope="module")
def configs():
    specs = discover()
    s = settings.load()
    full = pipeline.live_config(s, compile_specs(specs)[0])
    fewer = pipeline.live_config(s, compile_specs(specs[:-1])[0])
    none = pipeline.live_config(s, compile_specs([])[0])
    return full, fewer, none


def test_spec_promotion_and_retirement_are_hot_reloadable(configs):
    full, fewer, none = configs
    assert build.reload_hazards(fewer, full) == []      # a spec added
    assert build.reload_hazards(full, fewer) == []      # a spec retired
    assert build.reload_hazards(none, full) == []       # first spec(s): route/failed appear
    assert build.reload_hazards(full, copy.deepcopy(full)) == []


def test_sink_codec_change_needs_a_restart(configs):
    full = configs[0]
    new = copy.deepcopy(full)
    new["sinks"]["out_archive"]["encoding"] = {"codec": "json"}
    assert build.reload_hazards(full, new) == ["sink out_archive changed (encoding)"]


def test_archive_branch_and_sources_are_structural(configs):
    full = configs[0]
    new = copy.deepcopy(full)
    new["transforms"]["ulpf_archive_record"]["source"] += "\n# changed\n"
    new["transforms"]["ulpf_archive_batch"]["max_events"] = 10
    new["sources"]["in_syslog_udp"]["address"] = "127.0.0.1:5515"
    new["sinks"]["out_extra"] = {"type": "blackhole", "inputs": ["ulpf_finalize"]}
    assert build.reload_hazards(full, new) == [
        "source in_syslog_udp changed (address)",
        "transform ulpf_archive_batch changed (max_events)",
        "transform ulpf_archive_record changed (source)",
        "sink out_extra added",
    ]


def test_fan_in_program_change_is_structural_but_input_lists_are_not(configs):
    full = configs[0]
    new = copy.deepcopy(full)
    new["transforms"]["ulpf_finalize"]["inputs"] = new["transforms"]["ulpf_finalize"]["inputs"][:-1]
    assert build.reload_hazards(full, new) == []
    new["transforms"]["ulpf_finalize"]["source"] += "\n# changed\n"
    assert build.reload_hazards(full, new) == ["transform ulpf_finalize changed (source)"]


def test_global_option_change_is_structural(configs):
    full = configs[0]
    new = copy.deepcopy(full)
    new["data_dir"] = "/elsewhere"
    assert build.reload_hazards(full, new) == ["global option 'data_dir' changed"]
