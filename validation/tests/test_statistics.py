"""Known-answer tests for the empirical percentiles used by validation reports."""

import unittest

from kinetum_validation.statistics import format_number, nearest_rank_percentile, validate_percentile_population


class TestReportStatistics(unittest.TestCase):
    """Percentiles select actual samples without interpolation or rank drift."""

    def test_integer_ranks_cover_even_odd_and_hundred_sample_boundaries(self) -> None:
        """p50 and p99 retain their exact order statistic at rounding boundaries."""
        for count, p50, p99 in (
            (1, 1, 1), (2, 1, 2), (3, 2, 3), (4, 2, 4),
            (99, 50, 99), (100, 50, 99), (101, 51, 100), (200, 100, 198),
        ):
            with self.subTest(count=count):
                values = list(range(count, 0, -1))
                original = list(values)
                self.assertEqual(nearest_rank_percentile(values, 50), p50)
                self.assertEqual(nearest_rank_percentile(values, 99), p99)
                self.assertEqual(values, original)

    def test_ties_extremes_and_exact_integer_arithmetic(self) -> None:
        """Repeated observations retain their weight and percentile zero selects the minimum."""
        values = [9, 1, 1, 1]
        for percentile, expected in ((0, 1), (25, 1), (50, 1), (75, 1), (100, 9)):
            with self.subTest(percentile=percentile):
                self.assertEqual(nearest_rank_percentile(values, percentile), expected)
        self.assertEqual(nearest_rank_percentile(list(range(1, 101)), 7), 7)

    def test_absent_samples_and_invalid_percentiles_reject(self) -> None:
        """Missing evidence cannot become a zero-valued sample or a clipped percentile."""
        with self.assertRaises(ValueError):
            nearest_rank_percentile([], 50)
        for percentile in (-1, 101, True, 50.5):
            with self.subTest(percentile=percentile), self.assertRaises(ValueError):
                nearest_rank_percentile([1], percentile)

    def test_display_keeps_small_nonzero_measurements_and_exact_integer_counters(self) -> None:
        """Display precision cannot turn packet loss into zero or narrow a uint64 counter."""
        self.assertEqual(format_number(0.000001, 2), "1e-06")
        self.assertEqual(format_number(0.0, 2), "0.00")
        self.assertEqual(format_number(10.0, 2), "10.00")
        self.assertEqual(format_number(18446744073709551615), "18446744073709551615")
        self.assertEqual(format_number(None, 2), "n/a")

    def test_percentiles_sharing_one_rank_must_name_the_same_observation(self) -> None:
        """Small populations cannot claim a p99 different from their maximum."""
        validate_percentile_population(30, {0: 1, 50: 2, 95: 3, 99: 4, 100: 4})
        for count, values in (
            (1, {0: 1, 50: 2, 100: 2}), (2, {0: 1, 50: 2, 100: 2}),
            (30, {0: 1, 50: 2, 95: 3, 99: 4, 100: 5}), (0, {0: 0}),
        ):
            with self.subTest(count=count), self.assertRaises(ValueError):
                validate_percentile_population(count, values)
