from app.version_compare import compare_versions, version_in_range


def test_compare_versions_orders_numeric_components():
    assert compare_versions("1.2.3", "1.10.0") < 0
    assert compare_versions("2.0", "1.9") > 0
    assert compare_versions("1.2.3", "1.2.3") == 0


def test_compare_versions_handles_mixed_alnum_suffix():
    assert compare_versions("8.9p1", "8.9p2") < 0
    assert compare_versions("2.4.52", "2.4.52") == 0


def test_version_in_range_no_constraints_matches_any_version():
    assert version_in_range("9.9.9") is True


def test_version_in_range_start_including():
    assert version_in_range("1.0", start_including="1.0") is True
    assert version_in_range("0.9", start_including="1.0") is False


def test_version_in_range_end_excluding():
    assert version_in_range("1.9.9", end_excluding="2.0") is True
    assert version_in_range("2.0", end_excluding="2.0") is False
    assert version_in_range("2.0.1", end_excluding="2.0") is False


def test_version_in_range_start_excluding_boundary_not_matched():
    assert version_in_range("1.0", start_excluding="1.0") is False
    assert version_in_range("1.0.1", start_excluding="1.0") is True


def test_version_in_range_end_including_boundary_matched():
    assert version_in_range("2.0", end_including="2.0") is True
    assert version_in_range("2.0.1", end_including="2.0") is False


def test_version_in_range_combined_window():
    assert version_in_range("1.5", start_including="1.0", end_excluding="2.0") is True
    assert version_in_range("2.0", start_including="1.0", end_excluding="2.0") is False
    assert version_in_range("0.5", start_including="1.0", end_excluding="2.0") is False


def test_version_in_range_exact_versions_list():
    assert version_in_range("2.3.4", exact_versions=["2.3.4", "2.3.5"]) is True
    assert version_in_range("2.3.6", exact_versions=["2.3.4", "2.3.5"]) is False
