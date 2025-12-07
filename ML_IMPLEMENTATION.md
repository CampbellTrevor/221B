# Machine Learning Implementation Guide for 221B

## Overview

221B now includes **machine learning enhancements** for threat hunting strategies, providing automated anomaly detection, pattern discovery, and intelligent explanations while maintaining a zero-code experience for analysts.

## 🎯 Goals

1. **Zero-Code Experience**: Analysts never write code - ML runs automatically
2. **Explainability**: Every ML detection explained in plain English
3. **Graceful Fallback**: Falls back to rule-based detection when insufficient data
4. **Interactive Performance**: Fast enough for real-time analysis
5. **Accessibility**: Clear for junior analysts, powerful for seniors

## 🤖 ML-Enhanced Strategies

### 1. Beacon Hunter (C2 Detection)

**ML Method**: Isolation Forest (Anomaly Detection)

**What It Does**:
- Analyzes timing patterns of network connections
- Identifies beaconing that deviates from normal periodic traffic
- Distinguishes malicious C2 callbacks from legitimate scheduled tasks

**Features Used**:
- `coeff_variation`: Timing consistency (lower = more regular)
- `mean_delta_sec`: Average interval between connections
- `connection_count`: Number of beaconing connections
- `delta_variance`: Timing variability

**When ML Activates**: 50+ source/destination pairs with beaconing behavior

**New Columns**:
- `ml_anomaly_score` (0-100): How unusual this pattern is
- `ml_confidence`: HIGH/MEDIUM/LOW/NORMAL confidence level
- `ml_explanation`: Plain English explanation with feature contributions

**Example Output**:
```
ml_anomaly_score: 87.5
ml_confidence: HIGH
ml_explanation: 🔴 ML HIGH CONFIDENCE: This beaconing pattern is highly unusual. 
                Features like timing consistency and connection frequency are 
                outliers compared to other traffic. Key factors: High timing_consistency, 
                High connection_frequency, High interval_regularity
```

**Interpretation for Analysts**:
- **Score 75-100**: Very unusual beaconing - likely C2 malware
- **Score 50-74**: Suspicious pattern - investigate further
- **Score <50**: Rule-based detection only, ML sees it as normal periodic traffic

---

### 2. Entropy Analyzer (DNS Tunneling)

**ML Method**: KMeans Clustering (Pattern Discovery)

**What It Does**:
- Groups similar high-entropy DNS queries together
- Identifies if multiple suspicious domains follow the same generation pattern
- Helps analysts understand if threats are related (same malware family)

**Features Used**:
- `entropy_score`: Shannon entropy (randomness measure)
- `string_length`: Length of domain/query string

**When ML Activates**: 50+ suspicious high-entropy strings detected

**New Columns**:
- `ml_cluster` (0-4): Which pattern group this belongs to
- `ml_cluster_risk`: CRITICAL/HIGH/MEDIUM risk level for the cluster
- `ml_explanation`: Detailed cluster description with pattern type

**Example Output**:
```
ml_cluster: 2
ml_cluster_risk: 🔴 CRITICAL
ml_explanation: 🤖 ML CLUSTER 2: High-risk DGA pattern cluster (avg score: 82.3). 
                Contains 18 similar strings. Pattern: High randomness (DGA domains 
                or encoded data). Avg entropy: 4.67, avg length: 35 chars. This 
                cluster likely represents the same malware family or attack.
```

**Cluster Interpretation**:
- **Cluster Size >10**: Strong evidence of coordinated attack/malware campaign
- **Cluster Size 5-10**: Possible related activity
- **Cluster Size <5**: May be isolated incidents

**Pattern Types Identified**:
1. Long, high-entropy strings → DNS tunneling/data exfiltration
2. High randomness → DGA domains from malware
3. Long subdomains → Potential DNS tunneling
4. Moderate patterns → Mixed suspicious activity

---

### 3. Exfiltration Monitor (Producer/Consumer Ratio)

**ML Method**: Local Outlier Factor (Density-Based Outlier Detection)

**What It Does**:
- Identifies hosts with dramatically different traffic patterns from neighbors
- Detects data exfiltration by finding unusual upload/download ratios
- More sensitive than rule-based thresholds for subtle exfiltration

**Features Used**:
- `total_bytes_out` (log-scaled): Upload volume
- `total_bytes_in` (log-scaled): Download volume  
- `exfil_ratio` (capped at 100): Upload/download ratio
- `total_bytes` (log-scaled): Total traffic volume

**When ML Activates**: 50+ hosts with traffic data

**New Columns**:
- `ml_outlier_score` (0-100): How different from neighbors
- `ml_confidence`: HIGH/MEDIUM/LOW/NORMAL confidence level
- `ml_explanation`: Explanation of why host is an outlier

**Example Output**:
```
ml_outlier_score: 91.2
ml_confidence: HIGH
ml_explanation: 🔴 ML HIGH CONFIDENCE: This host traffic pattern is extremely 
                unusual compared to others. Upload/download ratio and volume are 
                outliers. Key factors: High upload_ratio, High upload_volume, 
                Moderate total_traffic
```

**LOF Explanation**:
Local Outlier Factor measures how isolated a data point is from its neighbors:
- **Normal hosts**: Cluster together with similar upload/download patterns
- **Outliers**: Significantly different from all nearby hosts
- **Exfiltration**: Stands out due to unusual producer behavior

---

## 📊 ML Architecture

### Minimum Sample Requirements

All ML features require **50+ samples** to activate:

| Strategy | What Counts as a Sample | Why 50? |
|----------|------------------------|---------|
| BeaconStrategy | Source/dest pairs showing beaconing | Need enough pairs for statistical significance |
| EntropyStrategy | Suspicious high-entropy strings | Clustering requires sufficient data points |
| ExfilStrategy | Hosts with traffic data | LOF needs neighbors to compare against |

**Below 50 samples**: Graceful fallback to rule-based detection with explanation message.

### Feature Engineering

**BeaconStrategy** (Timing Features):
```python
Features = {
    'coeff_variation': std_delta / mean_delta,  # Normalized consistency
    'mean_delta_sec': mean(time_between_connections),
    'connection_count': total_connections,
    'delta_variance': variance(time_deltas)
}
```

**EntropyStrategy** (String Features):
```python
Features = {
    'entropy_score': shannon_entropy(string),  # 0-8 bits
    'string_length': len(string)
}
```

**ExfilStrategy** (Traffic Features):
```python
Features = {
    'total_bytes_out': log1p(upload_bytes),  # Log-scaled
    'total_bytes_in': log1p(download_bytes),
    'exfil_ratio': min(bytes_out / bytes_in, 100),  # Capped
    'total_bytes': log1p(total_traffic)
}
```

### Feature Scaling

All features are **normalized using StandardScaler** before ML training:
- Converts to zero mean, unit variance
- Critical for distance-based algorithms (Isolation Forest, LOF, KMeans)
- Prevents features with large ranges from dominating

### Model Parameters

**Isolation Forest** (BeaconStrategy):
```python
IsolationForest(
    contamination=0.1,      # Expect 10% anomalies
    n_estimators=100,       # 100 trees for stability
    random_state=42,        # Reproducible results
    n_jobs=-1              # Use all CPU cores
)
```

**KMeans Clustering** (EntropyStrategy):
```python
KMeans(
    n_clusters=min(n_samples // 10, 5),  # 3-5 clusters typical
    random_state=42,
    n_init=10               # 10 initializations
)
```

**Local Outlier Factor** (ExfilStrategy):
```python
LocalOutlierFactor(
    n_neighbors=min(20, n_samples - 1),  # Adaptive neighbor count
    contamination='auto',    # Auto-determine threshold
    novelty=False           # Detect in training set
)
```

---

## 🎓 For Junior Analysts

### What is Machine Learning?

Machine learning helps computers **learn patterns from data** without being explicitly programmed. In 221B:

1. **Learns what's "normal"** from your network traffic
2. **Identifies unusual patterns** that deviate from normal
3. **Explains why** something is flagged as suspicious

### How to Read ML Results

**Confidence Levels**:
- 🔴 **HIGH CONFIDENCE**: ML strongly agrees this is suspicious - prioritize investigation
- 🟡 **MEDIUM CONFIDENCE**: ML detects anomaly but moderate - worth checking
- 🟢 **LOW CONFIDENCE**: ML sees as mostly normal - rule-based logic flagged it
- ℹ️ **NORMAL**: ML considers it normal periodic traffic - may be false positive

**Anomaly Scores (0-100)**:
- **90-100**: Extremely unusual - very likely threat
- **75-89**: Highly suspicious - investigate urgently
- **50-74**: Moderately suspicious - review when able
- **<50**: Borderline or rule-based only

### Common Questions

**Q: Why does ML sometimes say "N/A"?**
A: ML needs at least 50 samples to work. With fewer detections, it falls back to rule-based logic. This is intentional - ML with too little data is unreliable.

**Q: Can I trust ML more than rule-based detection?**
A: Use both together! ML catches unusual patterns rules might miss, but rules catch known bad behaviors. When ML and rules both agree (HIGH confidence), that's the strongest signal.

**Q: What if ML says NORMAL but rule-based flagged it?**
A: This can happen with legitimate scheduled tasks that look like beaconing. Investigate the context - is it from a known service? Regular business hours? Known IP?

**Q: How does clustering help?**
A: If you see 20 domains in the same cluster, they're likely from the same malware campaign. Finding one lets you block the whole family.

---

## 🔬 For Senior Analysts

### Model Selection Rationale

**Isolation Forest** (BeaconStrategy):
- **Why**: Excellent for detecting anomalies in time-series patterns
- **Advantages**: Fast, handles high-dimensional data, works well with imbalanced data
- **Alternatives considered**: One-Class SVM (too slow), Autoencoders (overkill for this use case)

**KMeans Clustering** (EntropyStrategy):
- **Why**: Simple, interpretable pattern discovery
- **Advantages**: Fast convergence, easy to explain clusters to analysts
- **Alternatives considered**: DBSCAN (requires distance parameter tuning), Hierarchical (slower)

**Local Outlier Factor** (ExfilStrategy):
- **Why**: Density-based outlier detection captures local anomalies
- **Advantages**: Finds outliers in heterogeneous data where global methods fail
- **Alternatives considered**: Isolation Forest (less sensitive to local variations)

### Performance Characteristics

| Model | Training Time | Prediction Time | Memory | Scalability |
|-------|--------------|----------------|--------|-------------|
| Isolation Forest | O(n log n) | O(log n) | Low | Excellent to 100k+ |
| KMeans | O(n × k × i) | O(k) | Low | Good to 50k+ |
| LOF | O(n²) or O(n log n) | O(n) | Medium | Limited to 10k |

**Note**: All models optimized for interactive analysis (<1 second on typical datasets).

### Hyperparameter Tuning

**Current Approach**: Sensible defaults based on threat hunting experience

**Contamination (Isolation Forest)**:
- Default: 0.1 (10% anomalies expected)
- Rationale: Most traffic is benign, true threats are minority
- Could tune: Use cross-validation if ground truth labels available

**n_clusters (KMeans)**:
- Default: `min(n_samples // 10, 5)`
- Rationale: Adaptive to dataset size, 3-5 clusters typical for malware families
- Could tune: Use elbow method or silhouette score for optimal k

**n_neighbors (LOF)**:
- Default: `min(20, n_samples - 1)`
- Rationale: 20 neighbors provides good local density estimation
- Could tune: Smaller for tighter clusters, larger for smoother boundaries

### Extending ML to Other Strategies

To add ML to a new strategy:

```python
def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
    # 1. Perform rule-based analysis (existing logic)
    result_df = self._rule_based_analysis(df, col_map)
    
    # 2. Apply ML if sufficient data
    if not result_df.empty and HAS_SKLEARN and len(result_df) >= ML_MIN_SAMPLES:
        result_df = self._apply_ml_analysis(result_df)
    else:
        # Add placeholder ML columns
        result_df['ml_score'] = 0.0
        result_df['ml_confidence'] = 'N/A'
        result_df['ml_explanation'] = 'Insufficient data for ML'
    
    return result_df

def _apply_ml_analysis(self, result_df: pd.DataFrame) -> pd.DataFrame:
    # 1. Feature engineering
    ml_features = ['feature1', 'feature2', 'feature3']
    X = result_df[ml_features].copy()
    
    # 2. Preprocessing
    X = X.fillna(X.median())  # Handle NaNs
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 3. Model training & prediction
    model = YourMLModel()
    predictions = model.fit_predict(X_scaled)
    scores = model.score_samples(X_scaled)  # or decision_function
    
    # 4. Add results & explanations
    result_df['ml_score'] = normalize_scores(scores)
    result_df['ml_confidence'] = determine_confidence(predictions, scores)
    result_df['ml_explanation'] = generate_explanations(result_df, predictions)
    
    return result_df
```

---

## 🧪 Testing

### ML Test Suite

Run ML-specific tests:
```bash
python -m unittest test_ml_features -v
```

**Tests Include**:
1. ML activation with sufficient data (50+ samples)
2. Graceful fallback with insufficient data (<50 samples)
3. Column explanations include ML indicators
4. ML scores are numeric and in expected ranges
5. Confidence levels are properly assigned

### Manual Validation

Create synthetic test data:

```python
from strategies import BeaconStrategy
import pandas as pd
from datetime import datetime, timedelta

# Generate 60 beaconing pairs
base_time = datetime.now()
data = []
for pair in range(60):
    for i in range(20):
        data.append({
            'timestamp': base_time + timedelta(seconds=60*i),
            'source_ip': f'192.168.1.{pair}',
            'dest_ip': f'10.0.0.{pair % 10}'
        })

df = pd.DataFrame(data)
strategy = BeaconStrategy()
results = strategy.analyze(df, {
    'timestamp': 'timestamp',
    'source_ip': 'source_ip',
    'dest_ip': 'dest_ip'
})

# Check ML columns
print(results[['source_ip', 'beacon_score', 'ml_anomaly_score', 'ml_confidence']].head())
```

---

## 📚 References

### Algorithms

1. **Isolation Forest**: Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). "Isolation Forest"
2. **Local Outlier Factor**: Breunig, M. M., et al. (2000). "LOF: Identifying Density-Based Local Outliers"
3. **KMeans**: Lloyd, S. (1982). "Least squares quantization in PCM"

### Threat Hunting with ML

- MITRE ATT&CK: Machine Learning for Threat Detection
- SANS: Applying Data Science to Threat Hunting
- Anomaly Detection in Network Traffic: A Survey

### Scikit-Learn Documentation

- [Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Local Outlier Factor](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html)
- [KMeans](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.KMeans.html)

---

## 🚀 Future Enhancements

### Short Term
- [ ] Add ML to PortScanStrategy (Isolation Forest for scan patterns)
- [ ] Add ML to BruteForceStrategy (Clustering for attack patterns)
- [ ] UI enhancements to visualize ML confidence
- [ ] Feature importance visualization

### Medium Term
- [ ] Model persistence (save/load trained models)
- [ ] Online learning (update models with new data)
- [ ] Ensemble methods (combine multiple models)
- [ ] Automated hyperparameter tuning

### Long Term  
- [ ] Active learning (analyst feedback improves models)
- [ ] Transfer learning (share models across similar networks)
- [ ] Explainable AI (SHAP/LIME for detailed feature attribution)
- [ ] Adversarial robustness (detect ML evasion attempts)

---

## 💡 Best Practices

### For Analysts

1. **Trust but Verify**: ML helps prioritize, but always investigate context
2. **Use Both Signals**: When ML and rules agree, confidence is highest
3. **Watch for Patterns**: Multiple detections in same ML cluster = campaign
4. **Baseline Normal**: ML learns from your data - unusual for you, not universal

### For Developers

1. **Fail Gracefully**: Always provide fallback when ML unavailable
2. **Explain Everything**: Every ML decision must have plain English explanation
3. **Validate Robustly**: Test with edge cases (NaNs, infinities, single samples)
4. **Monitor Performance**: Track ML prediction time and resource usage
5. **Document Thoroughly**: Future maintainers need to understand model choices

---

## 📞 Support

Questions about ML implementation? Check:
1. This document for architecture and usage
2. `test_ml_features.py` for examples
3. Column explanations in strategies (`get_column_explanations()`)
4. Code comments in strategies.py

Remember: Machine learning enhances human analysis, it doesn't replace it. The best threat hunting combines ML insights with analyst expertise and contextual knowledge. 🎯
