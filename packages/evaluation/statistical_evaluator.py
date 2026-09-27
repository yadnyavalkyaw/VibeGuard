import random
import numpy as np
from typing import List, Dict, Tuple

class StatisticalEvaluator:
    """
    Research Evaluation Engine:
    Calculates Precision, Recall, F1-Score, False Positive Rate (FPR),
    and computes 95% Non-Parametric Bootstrap Confidence Intervals over experimental trials.
    """
    @staticmethod
    def calculate_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4)
        }

    @staticmethod
    def bootstrap_confidence_interval(trials: List[Dict[str, int]], metric_name: str = "f1_score", n_resamples: int = 1000, ci_level: float = 0.95, seed: int = 42) -> Tuple[float, float, float]:
        """
        Computes Mean and 95% Bootstrap Confidence Interval [CI_lower, CI_upper].
        """
        random.seed(seed)
        np.random.seed(seed)
        
        scores = []
        for trial in trials:
            metrics = StatisticalEvaluator.calculate_metrics(trial["tp"], trial["fp"], trial["fn"], trial["tn"])
            scores.append(metrics[metric_name])

        if not scores:
            return 0.0, 0.0, 0.0

        mean_score = float(np.mean(scores))
        bootstrapped_means = []

        for _ in range(n_resamples):
            resample = np.random.choice(scores, size=len(scores), replace=True)
            bootstrapped_means.append(np.mean(resample))

        alpha = (1.0 - ci_level) / 2.0
        ci_lower = float(np.percentile(bootstrapped_means, alpha * 100))
        ci_upper = float(np.percentile(bootstrapped_means, (1.0 - alpha) * 100))

        return round(mean_score, 4), round(ci_lower, 4), round(ci_upper, 4)
