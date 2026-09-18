import random

from app.detection.ml import AnomalyDetector


def normal_feature(rng: random.Random) -> dict:
    return {
        "duration": rng.uniform(0, 5),
        "src_bytes": rng.uniform(50, 500),
        "dst_bytes": rng.uniform(50, 500),
        "count": rng.uniform(1, 5),
        "srv_count": rng.uniform(1, 5),
        "same_srv_rate": 1.0,
        "serror_rate": 0.0,
    }


def outlier_feature() -> dict:
    return {
        "duration": 9999,
        "src_bytes": 50_000_000,
        "dst_bytes": 1,
        "count": 500,
        "srv_count": 500,
        "same_srv_rate": 0.01,
        "serror_rate": 1.0,
    }


def test_requires_fit_before_score():
    detector = AnomalyDetector()
    try:
        detector.score(normal_feature(random.Random(1)))
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


def test_fits_and_scores_without_error():
    rng = random.Random(42)
    training_data = [normal_feature(rng) for _ in range(200)]
    detector = AnomalyDetector(contamination=0.1).fit(training_data)

    is_anomaly, confidence = detector.score(normal_feature(rng))
    assert isinstance(is_anomaly, (bool, bool.__class__)) or is_anomaly in (True, False)
    assert 0.0 <= confidence <= 1.0


def test_flags_extreme_outlier_but_not_the_center_of_the_normal_distribution():
    rng = random.Random(7)
    training_data = [normal_feature(rng) for _ in range(300)]
    detector = AnomalyDetector(contamination=0.1).fit(training_data)

    # The midpoint of the ranges normal_feature() draws from -- the most
    # "typical" possible normal flow, not just another random sample that
    # could itself land near the 10% contamination boundary.
    typical_point = {
        "duration": 2.5, "src_bytes": 275, "dst_bytes": 275,
        "count": 3, "srv_count": 3, "same_srv_rate": 1.0, "serror_rate": 0.0,
    }

    typical_is_anomaly, _ = detector.score(typical_point)
    outlier_is_anomaly, outlier_conf = detector.score(outlier_feature())

    assert outlier_is_anomaly is True
    assert typical_is_anomaly is False
    assert outlier_conf > 0.5
