"""bench/window.py: the attacker's window, worked out from real heads and a scripted link."""

from __future__ import annotations

import threading

import pytest

from tests.test_bench_measure import REPO, _load
from veriseal.signing import generate_key, public_pem
from veriseal.witness import Delivery, Witness, http_sender, serve

window = _load("window", REPO / "bench" / "window.py")

SECOND = window.SECOND
LATENCY = 50_000_000


def _run(task=120, epoch=1, every=1, outages=(), latency=LATENCY, start_delay=0, retry=SECOND):
    key = generate_key()
    witness = Witness(key)

    def link(path: str, body: dict) -> dict:
        if path == "/start":
            keys = [bytes.fromhex(value) for value in body["public_keys"]]
            return witness.register(body["record"], keys)
        return witness.submit(body)

    return window.record(
        task * SECOND,
        epoch * SECOND,
        every,
        link,
        public_pem(key),
        window.SimulatedClock(),
        [(first * SECOND, length * SECOND) for first, length in outages],
        latency,
        retry,
        start_delay * SECOND,
    )


def test_sawtooth_worst_and_average():
    worst, mean = window._sawtooth(0, 10, [(5, 5), (10, 10)])
    assert worst == 5
    assert mean == pytest.approx(2.5)


def test_sawtooth_without_any_reset_is_the_whole_task():
    assert window._sawtooth(0, 10, []) == (10, 5.0)


def test_sawtooth_ignores_a_reset_that_covers_nothing_new():
    assert window._sawtooth(0, 10, [(5, 5), (7, 3)])[0] == 5


def test_windows_only_count_what_has_left():
    result = window.windows(
        0, 10 * SECOND, 0, [5 * SECOND, 10 * SECOND], [Delivery(0, 5 * SECOND, 8 * SECOND)]
    )
    assert result["can_alter_throwaway_worst_s"] == 5
    assert result["can_delete_worst_s"] == 8


def test_scripted_outage_gives_the_outage_plus_one_epoch_plus_latency():
    """The check set for this task: a 60 s outage on 1 s epochs, starting as a head closes."""
    result = _run(outages=[(30, 60)])
    assert result["can_delete_worst_s"] == pytest.approx(60 + 1 + 0.05)
    assert result["can_alter_one_key_worst_s"] == pytest.approx(60 + 1 + 0.05)


def test_throw_away_keys_hold_through_an_outage():
    assert _run(outages=[(30, 60)])["can_alter_throwaway_worst_s"] == pytest.approx(1)


@pytest.mark.parametrize("every", [1, 5, 10, 30])
def test_with_a_steady_link_the_window_follows_the_export_interval(every):
    result = _run(every=every)
    assert result["can_delete_worst_s"] == pytest.approx(every + 0.05)
    assert result["can_alter_throwaway_worst_s"] == pytest.approx(1)


def test_never_exporting_leaves_the_whole_task_open():
    result = _run(every=1000, outages=[(0, 10_000)])
    assert result["can_delete_worst_s"] == result["sign_locally_only_s"]


def test_slower_retries_widen_the_window():
    result = _run(outages=[(30, 60)], retry=7 * SECOND)
    assert 61 < result["can_delete_worst_s"] < 61 + 7 + 1


def test_start_record_delay_sets_a_floor_under_every_window():
    result = _run(start_delay=12)
    assert result["can_alter_throwaway_worst_s"] == pytest.approx(12)
    assert result["can_delete_worst_s"] == pytest.approx(12)


def test_export_cost_falls_with_the_interval():
    every_second, every_ten = _run(every=1), _run(every=10)
    assert every_second["sends_per_hour"] == pytest.approx(3600, rel=0.01)
    assert every_ten["sends_per_hour"] == pytest.approx(360, rel=0.01)
    assert every_ten["bytes_per_hour"] == pytest.approx(
        every_second["bytes_per_hour"] / 10, rel=0.1
    )


def test_measure_latency_times_real_requests():
    witness = Witness(generate_key())
    server = serve(witness)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        send = http_sender(f"http://127.0.0.1:{server.server_address[1]}")
        times = window.measure_latency(send, 5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert len(times) == 5
    assert times == sorted(times)
    assert times[0] > 0


def test_real_time_run_over_http_with_an_outage():
    """The same recording on a real clock and a real socket, scaled down to about a second."""
    key = generate_key()
    server = serve(Witness(key))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    epoch = SECOND // 10
    try:
        result = window.record(
            SECOND,
            epoch,
            1,
            http_sender(f"http://127.0.0.1:{server.server_address[1]}"),
            public_pem(key),
            window.RealClock(),
            [(3 * epoch, 3 * epoch)],
            retry_ns=epoch,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert 0.35 <= result["can_delete_worst_s"] < 0.8
    assert result["can_alter_throwaway_worst_s"] < 0.3


def test_a_head_signed_late_widens_every_window_by_that_delay():
    closes = [1 * SECOND, 2 * SECOND, 3 * SECOND]
    deliveries = [Delivery(i, moment, moment + LATENCY) for i, moment in enumerate(closes)]
    prompt = window.windows(0, 3 * SECOND, 0, closes, deliveries)
    delayed = window.windows(0, 3 * SECOND, 0, closes, deliveries, head_delay_ns=3 * SECOND // 2)
    assert prompt["can_alter_throwaway_worst_s"] == 1.0
    assert delayed["can_alter_throwaway_worst_s"] == 2.5
    assert delayed["can_delete_worst_s"] == pytest.approx(prompt["can_delete_worst_s"] + 1.5)


# bench/plot_window.py: the chart.

plot = _load("plot_window", REPO / "bench" / "plot_window.py")


def _rows(scale=1.0):
    return [
        {"export_s": s, "can_alter_throwaway_worst_s": 1.0, "can_delete_worst_s": s * scale + 1}
        for s in (1, 10, 60)
    ]


def test_ticks_follow_1_2_5():
    assert plot._ticks(1, 60) == [1, 2, 5, 10, 20, 50]
    assert plot._bounds([1.05, 61]) == (1, 100)
    assert plot._bounds([3, 3]) == (2, 5)


def test_chart_draws_two_lines_per_file_and_names_each_file(tmp_path):
    svg = plot.chart([("wifi", _rows()), ("lte", _rows(2))], "Windows")
    assert svg.count("<polyline") == 4 and svg.count("<circle") == 12
    assert ">wifi<" in svg and ">lte<" in svg and ">50 s<" in svg
    import xml.etree.ElementTree as ET

    ET.fromstring(svg)


def test_chart_refuses_a_zero_window():
    rows = _rows()
    rows[0]["can_alter_throwaway_worst_s"] = 0
    with pytest.raises(ValueError, match="above zero"):
        plot.chart([("a", rows)], "t")


def test_plot_from_the_command_line(tmp_path):
    import json

    report = tmp_path / "window-wifi.json"
    report.write_text(json.dumps({"rows": _rows()}))
    plot.main([str(report), "--out", str(tmp_path / "w.svg")])
    assert (tmp_path / "w.svg").read_text(encoding="utf-8").startswith("<svg")
