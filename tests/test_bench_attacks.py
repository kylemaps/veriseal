"""bench/attacks.py: the matrix, and the strategies a hacker has to work with."""

from __future__ import annotations

import pytest

from tests.test_bench_measure import REPO, _load

attacks = _load("attacks", REPO / "bench" / "attacks.py")


@pytest.fixture(scope="module")
def scenario():
    return attacks.Scenario.of(attacks.synthetic_log())


@pytest.fixture(scope="module")
def matrix(scenario):
    return attacks.run_matrix(scenario)


def _run(scenario, erased=True, exported=True):
    return attacks.record_until_hack(scenario, erased, exported, scenario.index_at(attacks.HACK_AT))


def test_every_attack_has_an_expectation_and_a_cell_per_design(matrix):
    assert set(matrix) == set(attacks.EXPECTED)
    assert all(len(cells) == len(attacks.CONFIGS) for cells in matrix.values())


def test_matrix_matches_what_we_expect(matrix):
    assert attacks.findings(matrix) == []


def test_findings_reports_a_differing_cell(matrix):
    changed = {name: list(cells) for name, cells in matrix.items()}
    cell = changed["no attack"][1]
    changed["no attack"][1] = {**cell, "outcome": attacks.CAUGHT}
    (finding,) = attacks.findings(changed)
    assert finding.startswith("no attack / throw-away keys: expected PASSES, got CAUGHT")


def test_the_scenario_puts_each_position_where_the_rows_say(scenario):
    run = _run(scenario)
    left = run.witnessed[-1]["tree_size"]
    signed = run.heads[-1]["tree_size"]
    assert scenario.index_at(attacks.EXPORTED_AT) < left
    assert left <= scenario.index_at(attacks.SIGNED_AT) < signed
    assert signed <= scenario.index_at(attacks.UNSIGNED_AT) < run.hack_index


def test_throw_away_keys_cannot_re_sign_a_closed_epoch(scenario):
    target = attacks._altered(scenario.messages, scenario.index_at(attacks.SIGNED_AT))
    assert attacks.resign(_run(scenario, erased=True), target) is None
    assert attacks.resign(_run(scenario, erased=False), target) is not None


def test_one_key_differs_from_throw_away_keys_only_where_nothing_has_left(matrix):
    one_key, throw_away = 2, 3
    differs = {
        name
        for name, cells in matrix.items()
        if cells[one_key]["outcome"] != cells[throw_away]["outcome"]
    }
    assert differs == {
        "alter a signed message that had not left",
        "cut the end, back past the last head",
    }


def test_a_fake_power_cut_is_how_throw_away_keys_alone_are_beaten(matrix):
    cell = matrix["re-seal the whole task from scratch"][1]
    assert (cell["outcome"], cell["strategy"]) == (attacks.FLAGGED, "fake_power_cut")


def test_a_witness_stops_the_fake_power_cut(scenario):
    target = attacks._altered(scenario.messages, scenario.index_at(attacks.EXPORTED_AT))
    run = _run(scenario)
    outcome, result = attacks.judge(run, *attacks.fake_power_cut(run, target))
    assert outcome == attacks.CAUGHT
    assert result.reason == "a head the witness holds is missing"


def test_timed_restarts_force_a_long_gap_instead_of_catching(matrix):
    """Re-stamping beats the rule, but the gap must then reach back to the hack."""
    plain, timed = 1, 4
    row = matrix["alter a signed message that had not left"]
    assert row[plain]["outcome"] == row[timed]["outcome"] == attacks.FLAGGED
    epoch_s = attacks.Scenario.of(attacks.synthetic_log()).epoch_ns / 1e9
    assert row[plain]["seam_s"] < 0.5
    assert row[timed]["seam_s"] >= (attacks.HACK_AT - attacks.SIGNED_AT) * epoch_s
    assert row[timed]["strategy"] == "restamp_after_cut"


def test_a_backdated_insert_is_caught_by_the_time_check(matrix):
    for cell in matrix["insert a backdated message after the hack"][1:]:
        assert cell["outcome"] == attacks.CAUGHT
    assert matrix["insert a backdated message after the hack"][3]["reason"] == (
        "a message was sealed too long after its time"
    )


def test_timed_restart_rejection_names_the_rule(scenario):
    target = attacks._fabricated(scenario)
    run = attacks.record_until_hack(
        scenario, True, False, scenario.index_at(attacks.HACK_AT), timed=True
    )
    outcome, result = attacks.judge(run, *attacks.fake_power_cut(run, target))
    assert (outcome, result.reason) == (attacks.CAUGHT, "a message is older than its start record")


def test_the_changed_message_is_named(scenario, matrix):
    index = scenario.index_at(attacks.EXPORTED_AT)
    assert matrix["alter a message that left"][3]["message"] == index


def test_the_v1_column_runs_the_real_verifier(scenario, tmp_path):
    assert attacks.v1_outcome(scenario.messages, tmp_path)["outcome"] == attacks.PASSES
