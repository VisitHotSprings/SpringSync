from datetime import datetime, time, timedelta, timezone

from odnas import db as D
from odnas.scheduler import (ThrottleGovernor, assign_offsets, in_window, next_backoff, next_slot, period_minutes,
                             weekly_check_due)

T0 = datetime(2026, 10, 20, 15, 7, tzinfo=timezone.utc)


def test_offsets_spread_evenly():
    ids = [f"u{i}" for i in range(5)]
    off = assign_offsets(ids, 30)
    assert sorted(off.values()) == [0, 6, 12, 18, 24]
    assert assign_offsets([], 30) == {}
    big = assign_offsets([f"u{i}" for i in range(77)], 30)
    assert max(big.values()) < 30 and len(set(big.values())) == 30  # every minute slot used


def test_next_slot_grid_and_stagger():
    a = next_slot(T0, 30, 0)
    b = next_slot(T0, 30, 6)
    assert a > T0 and b > T0 and (a - T0) <= timedelta(minutes=30)
    assert (b.minute - a.minute) % 30 in (6, 24)  # 6 min apart on the grid
    assert next_slot(a, 30, 0) - a == timedelta(minutes=30)


def test_backoff_doubles_and_caps():
    assert next_backoff(1, True) == 2 and next_backoff(2, True) == 4 and next_backoff(4, False) == 1
    assert period_minutes(30, 16) == 240  # 4 h cap
    s1 = next_slot(T0, 30, 0, 1)
    s2 = next_slot(T0, 30, 0, 2)
    assert s2 >= s1


def test_active_window_including_overnight():
    noon_ct = datetime(2026, 10, 20, 17, 0, tzinfo=timezone.utc)   # 12:00 CDT
    night_ct = datetime(2026, 10, 21, 4, 0, tzinfo=timezone.utc)   # 23:00 CDT
    assert in_window(noon_ct, None)
    assert in_window(noon_ct, (time(6), time(22))) and not in_window(night_ct, (time(6), time(22)))
    assert in_window(night_ct, (time(18), time(7))) and not in_window(noon_ct, (time(18), time(7)))


def test_weekly_check():
    sunday_4am_ct = datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc)
    assert weekly_check_due(sunday_4am_ct, None, 6, "03:00")
    assert not weekly_check_due(sunday_4am_ct, sunday_4am_ct - timedelta(hours=1), 6, "03:00")
    assert not weekly_check_due(sunday_4am_ct - timedelta(days=1), None, 6, "03:00")


def test_throttle_governor_halves_concurrency():
    g = ThrottleGovernor()
    assert g.max_concurrent(T0, 2) == 2
    g.record(T0)
    assert g.max_concurrent(T0, 2) == 2
    g.record(T0 + timedelta(minutes=3))
    assert g.max_concurrent(T0 + timedelta(minutes=4), 2) == 1
    assert g.max_concurrent(T0 + timedelta(minutes=30), 2) == 2


def _worker(cfg, db, kr, entra, proc):
    from odnas.worker import Worker
    from tests.conftest import FakeHelperRunner
    from odnas.nas import MountHelperClient
    helper = MountHelperClient(cfg, FakeHelperRunner(mnt_root=cfg.p_mnt))
    return Worker(cfg, db, kr, entra, proc=proc, helper=helper)


def test_tick_caps_concurrency_and_skips_paused_states(cfg, db, kr, entra):
    from tests.conftest import FakeProc, seed_user
    users = [seed_user(db, kr, upn=f"u{i}@hotsprings.org") for i in range(4)]
    seed_user(db, kr, upn="bad@hotsprings.org", state=D.NAS_AUTH_FAILED)
    seed_user(db, kr, upn="re@hotsprings.org", state=D.NEEDS_REAUTH)
    w = _worker(cfg, db, kr, entra, FakeProc())
    started = w.tick(T0, wait=True)
    assert len(started) == 2  # max_concurrent default 2
    assert {u for u, _ in started} <= set(users)
    assert all(k == "bisync" for _, k in started)
    # offsets were assigned round-robin
    offs = sorted(r["slot_offset_min"] for r in db.users())
    assert offs == [0, 5, 10, 15, 20, 25]


def test_one_resync_at_a_time(cfg, db, kr, entra):
    from tests.conftest import FakeProc, seed_user
    for i in range(3):
        seed_user(db, kr, upn=f"r{i}@hotsprings.org", state=D.CRITICAL, needs_resync=1, resync_approved_by="mark")
    w = _worker(cfg, db, kr, entra, FakeProc())
    night = datetime(2026, 10, 21, 4, 0, tzinfo=timezone.utc)  # 23:00 CT, inside default 18:00-07:00
    assert [k for _, k in w.tick(night, wait=True)] == ["resync"]
    later = [k for _, k in w.tick(T0 + timedelta(days=1, minutes=1))]  # 10:08 CT next day: outside resync window
    assert "resync" not in later


def test_unapproved_critical_never_runs(cfg, db, kr, entra):
    from tests.conftest import FakeProc, seed_user
    seed_user(db, kr, state=D.CRITICAL, needs_resync=1)
    w = _worker(cfg, db, kr, entra, FakeProc())
    assert w.tick(datetime(2026, 10, 21, 4, 0, tzinfo=timezone.utc)) == []


def test_drain_blocks_new_jobs(cfg, db, kr, entra):
    from tests.conftest import FakeProc, seed_user
    seed_user(db, kr)
    w = _worker(cfg, db, kr, entra, FakeProc())
    w.drain_flag.parent.mkdir(parents=True, exist_ok=True)
    w.drain_flag.touch()
    assert w.tick(T0) == []
