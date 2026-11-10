"""Unit tests for leakage-free ML evaluation harness and benchmark comparison vs rules."""

import pytest
from backend.detection.rules.base import parse_timestamp_epoch
from backend.ml.config import MLConfig
from backend.ml.evaluation import evaluate_ml_pipeline, generate_synthetic_benchmark_dataset


def test_synthetic_dataset_leakage_free_partitioning():
    """Verify train and test datasets strictly enforce temporal separation and entity hygiene."""
    train_events, test_events, ground_truth = generate_synthetic_benchmark_dataset(seed=42)

    assert len(train_events) > 50
    assert len(test_events) > 50
    assert len(ground_truth) > 0

    # 1. Temporal barrier check: max timestamp in train must be earlier than min timestamp in test
    train_max_epoch = max(parse_timestamp_epoch(e.timestamp) for e in train_events)
    test_min_epoch = min(parse_timestamp_epoch(e.timestamp) for e in test_events)

    assert train_max_epoch < test_min_epoch, (
        f"Data leakage detected! Training max time ({train_max_epoch}) >= Testing min time ({test_min_epoch})"
    )

    # 2. Verify all training events are benign (no ground truth attacks in train set)
    # Check that training source IPs and test attack IPs do not overlap
    train_ips = set(e.source_ip for e in train_events)
    attack_ips = {item["entity"] for item in ground_truth if item["is_attack"]}

    assert bool(train_ips & attack_ips) is False, "Attack entities leaked into training set!"


def test_leakage_free_evaluation_metrics_and_rule_comparison():
    """Verify evaluation pipeline achieves high F1 and outperforms static rules on slow attacks."""
    cfg = MLConfig(
        contamination=0.08,
        n_estimators=100,
        random_state=42,
        alert_threshold=0.55,
        min_events_per_window=3,
    )

    train_events, test_events, ground_truth = generate_synthetic_benchmark_dataset(seed=42)
    metrics = evaluate_ml_pipeline(
        train_events=train_events,
        test_events=test_events,
        ground_truth_labels=ground_truth,
        ml_config=cfg,
    )

    # Verify metric sanity
    assert metrics.total_samples == len(ground_truth)
    assert metrics.true_positives >= 2  # Must catch at least rapid and slow or spray attacks
    assert metrics.precision >= 0.70
    assert metrics.recall >= 0.65
    assert metrics.f1_score >= 0.70
    assert metrics.accuracy >= 0.80

    # Verify comparative analysis vs deterministic rules
    comparison = metrics.rule_comparison
    assert "rule_engine" in comparison
    assert "isolation_forest" in comparison

    # Scientific assertion: Static rules miss slow-and-low (spaced 2m apart), while ML flags it
    assert comparison["rule_engine"]["slow_and_low_detected"] is False
    assert comparison["isolation_forest"]["slow_and_low_detected"] is True
    assert "scientific_insight" in comparison
