import pytest

from tapm.eval.report import pct
from tapm.eval.stats import format_rate_with_ci, wilson_interval


def test_wilson_interval_known_values():
    # n=2, k=2 (E4 held-out precision / recall)
    ci = wilson_interval(2, 2, 0.95)
    assert ci is not None
    assert abs(ci[0] - 0.3424) < 1e-3
    assert abs(ci[1] - 1.0) < 1e-3

    # n=2, k=0 (false path rate when FP=0, TP=2)
    ci_zero = wilson_interval(0, 2, 0.95)
    assert ci_zero is not None
    assert abs(ci_zero[0] - 0.0) < 1e-3
    assert abs(ci_zero[1] - 0.6576) < 1e-3


def test_wilson_interval_edge_cases():
    # Zero denominator must return None
    assert wilson_interval(0, 0) is None
    assert wilson_interval(5, 0) is None
    assert wilson_interval(0, -1) is None

    # Invalid k
    with pytest.raises(ValueError):
        wilson_interval(-1, 10)
    with pytest.raises(ValueError):
        wilson_interval(11, 10)


def test_format_rate_with_ci():
    # Zero-denominator and None inputs must render n/a
    assert format_rate_with_ci(0, 0) == "n/a"
    assert format_rate_with_ci(None, None) == "n/a"
    assert format_rate_with_ci(5, 0) == "n/a"
    assert format_rate_with_ci(None, 5) == "n/a"

    # Small n (< 30) includes numerator/denominator and 95% Wilson interval
    res_2_2 = format_rate_with_ci(2, 2)
    assert res_2_2 == "100.0% (2/2, 95% CI [34.2%, 100.0%])"

    res_0_2 = format_rate_with_ci(0, 2)
    assert res_0_2 == "0.0% (0/2, 95% CI [0.0%, 65.8%])"

    # Large n (>= 30) shows numerator/denominator without CI
    res_large = format_rate_with_ci(30, 30)
    assert res_large == "100.0% (30/30)"


def test_pct_helper():
    assert pct(None) == "n/a"
    assert pct(0.0) == "0.0%"
    assert pct(0.5) == "50.0%"
    assert pct(1.0) == "100.0%"
