//! Anomaly scoring with EMA smoothing.
//!
//! Takes raw reconstruction error from the model and produces a smoothed
//! health status with hysteresis to avoid flapping.

use crate::config::{EMA_ALPHA, MIN_CONSECUTIVE_UNHEALTHY, UNHEALTHY_THRESHOLD, WARNING_THRESHOLD};

/// GPU health status based on anomaly scores.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum HealthStatus {
    Normal { score: f32 },
    Warning { score: f32 },
    Unhealthy { score: f32 },
}

impl HealthStatus {
    pub fn score(&self) -> f32 {
        match self {
            HealthStatus::Normal { score }
            | HealthStatus::Warning { score }
            | HealthStatus::Unhealthy { score } => *score,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Normal { .. } => "normal",
            HealthStatus::Warning { .. } => "warning",
            HealthStatus::Unhealthy { .. } => "unhealthy",
        }
    }
}

/// EMA-smoothed anomaly scorer with consecutive-unhealthy gating.
pub struct AnomalyScorer {
    ema_score: f32,
    alpha: f32,
    consecutive_unhealthy: u32,
    min_consecutive: u32,
    initialized: bool,
}

impl AnomalyScorer {
    pub fn new() -> Self {
        Self {
            ema_score: 0.0,
            alpha: EMA_ALPHA,
            consecutive_unhealthy: 0,
            min_consecutive: MIN_CONSECUTIVE_UNHEALTHY,
            initialized: false,
        }
    }

    /// Update the scorer with a new raw anomaly score from the model.
    pub fn update(&mut self, raw_score: f32) {
        if !self.initialized {
            self.ema_score = raw_score;
            self.initialized = true;
        } else {
            self.ema_score = self.alpha * raw_score + (1.0 - self.alpha) * self.ema_score;
        }

        if self.ema_score >= UNHEALTHY_THRESHOLD {
            self.consecutive_unhealthy = self.consecutive_unhealthy.saturating_add(1);
        } else {
            self.consecutive_unhealthy = 0;
        }
    }

    /// Get the current health status.
    pub fn status(&self) -> HealthStatus {
        if self.consecutive_unhealthy >= self.min_consecutive {
            HealthStatus::Unhealthy {
                score: self.ema_score,
            }
        } else if self.ema_score >= WARNING_THRESHOLD {
            HealthStatus::Warning {
                score: self.ema_score,
            }
        } else {
            HealthStatus::Normal {
                score: self.ema_score,
            }
        }
    }

    /// Get the current EMA-smoothed score.
    pub fn score(&self) -> f32 {
        self.ema_score
    }
}

impl Default for AnomalyScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_normal() {
        let scorer = AnomalyScorer::new();
        assert!(matches!(scorer.status(), HealthStatus::Normal { .. }));
    }

    #[test]
    fn first_update_sets_score_directly() {
        let mut scorer = AnomalyScorer::new();
        scorer.update(0.3);
        assert!((scorer.score() - 0.3).abs() < f32::EPSILON);
    }

    #[test]
    fn ema_smoothing() {
        let mut scorer = AnomalyScorer::new();
        scorer.update(1.0); // ema = 1.0
        scorer.update(0.0); // ema = 0.1 * 0.0 + 0.9 * 1.0 = 0.9
        assert!((scorer.score() - 0.9).abs() < 0.01);
    }

    #[test]
    fn warning_threshold() {
        let mut scorer = AnomalyScorer::new();
        scorer.update(0.6);
        assert!(matches!(scorer.status(), HealthStatus::Warning { .. }));
    }

    #[test]
    fn unhealthy_requires_consecutive() {
        let mut scorer = AnomalyScorer::new();
        // Single high score should not be unhealthy (need MIN_CONSECUTIVE_UNHEALTHY)
        scorer.update(0.9);
        // After first update, consecutive_unhealthy=1, min=3, so Warning
        assert!(matches!(scorer.status(), HealthStatus::Warning { .. }));

        scorer.update(0.95); // consecutive=2, still Warning
        assert!(matches!(scorer.status(), HealthStatus::Warning { .. }));

        // Force EMA above threshold for 3 consecutive
        // ema after update(0.95): 0.1*0.95 + 0.9*0.9 = 0.095 + 0.81 = 0.905
        // ema after another: stays high
        scorer.update(0.99);
        assert!(matches!(scorer.status(), HealthStatus::Unhealthy { .. }));
    }

    #[test]
    fn recovery_from_unhealthy() {
        let mut scorer = AnomalyScorer::new();
        // Drive to unhealthy
        for _ in 0..5 {
            scorer.update(0.95);
        }
        assert!(matches!(scorer.status(), HealthStatus::Unhealthy { .. }));

        // Feed enough low scores to bring EMA below unhealthy threshold.
        // EMA(0.1) decays slowly: need ~15 updates of 0.0 to drop from 0.95 below 0.8
        for _ in 0..20 {
            scorer.update(0.0);
        }
        // EMA should be well below unhealthy threshold, consecutive counter reset
        assert!(!matches!(scorer.status(), HealthStatus::Unhealthy { .. }));
    }

    #[test]
    fn normal_stays_normal_for_low_scores() {
        let mut scorer = AnomalyScorer::new();
        for _ in 0..10 {
            scorer.update(0.1);
        }
        assert!(matches!(scorer.status(), HealthStatus::Normal { .. }));
    }

    #[test]
    fn as_str_values() {
        assert_eq!(HealthStatus::Normal { score: 0.0 }.as_str(), "normal");
        assert_eq!(HealthStatus::Warning { score: 0.5 }.as_str(), "warning");
        assert_eq!(HealthStatus::Unhealthy { score: 0.9 }.as_str(), "unhealthy");
    }
}
