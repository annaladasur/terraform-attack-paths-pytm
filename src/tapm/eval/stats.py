"""Statistical calculations for evaluation reports (Wilson intervals, rates)."""

from __future__ import annotations

import math


def wilson_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float] | None:
    """Compute the Wilson score confidence interval for a binomial proportion.

    Returns (lower, upper) as floats in [0.0, 1.0], or None if n <= 0.
    """
    if n <= 0:
        return None
    if k < 0 or k > n:
        raise ValueError(f"k must be in [0, n], got k={k}, n={n}")

    # Standard normal quantile: 1.95996 for 95% confidence
    if abs(confidence - 0.95) < 1e-4:
        z = 1.959963984540054
    else:
        # Simple approximation for arbitrary confidence levels
        p = (1.0 + confidence) / 2.0
        z = math.sqrt(2.0) * _erfinv(2.0 * p - 1.0)

    z2 = z * z
    p_hat = k / n
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    spread = (z * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n)))) / denom

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


def _erfinv(y: float) -> float:
    # Winitzki approximation for inverse error function
    a = 0.147
    if y == 0:
        return 0.0
    sgn = 1.0 if y > 0 else -1.0
    l = math.log(max(1e-15, 1.0 - y * y))
    part1 = 2.0 / (math.pi * a) + l / 2.0
    val = part1 * part1 - l / a
    return sgn * math.sqrt(max(0.0, math.sqrt(max(0.0, val)) - part1))


def format_rate_with_ci(k: int | None, n: int | None, ci_threshold: int = 30) -> str:
    """Format a rate with numerator/denominator and 95% Wilson interval if n < ci_threshold.

    Returns 'n/a' if n is 0 or None.
    If n >= ci_threshold: 'X.X% (k/n)'
    If n < ci_threshold:  'X.X% (k/n, 95% CI [L.L%, U.U%])'
    """
    if k is None or n is None or n == 0:
        return "n/a"
    pct_val = 100.0 * k / n
    if n < ci_threshold:
        ci = wilson_interval(k, n, 0.95)
        if ci:
            return f"{pct_val:.1f}% ({k}/{n}, 95% CI [{100 * ci[0]:.1f}%, {100 * ci[1]:.1f}%])"
    return f"{pct_val:.1f}% ({k}/{n})"
