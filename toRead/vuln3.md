# Deliverable 3/4 — Deep Understanding Document

## Vulnerability Prioritization & Triage System

**Purpose:** This document is for learning the project deeply enough that you can explain, defend, modify, and rebuild it yourself. It is intentionally different from the formal report: it focuses on **why things exist, what they mean, how they connect, and what assumptions can break them.**

---

# 0. The Project in One Sentence

The system investigates whether **machine learning and nonlinear risk modeling can improve vulnerability prioritization**, while enforcing the crucial rule that a historical prediction may only use information that would actually have been available at the prediction time.

Everything else follows from that.

---

# 1. First Principles: What Problem Are We Solving?

A vulnerability is not automatically equally dangerous just because it exists.

Consider:

```text
Vulnerability A
CVSS = 9.8
EPSS = 0.01
Not KEV
Installed on isolated test server

Vulnerability B
CVSS = 7.5
EPSS = 0.70
KEV
Internet-facing critical payment server
```

A simplistic system might say:

> A has the higher CVSS, therefore fix A first.

A practical security team needs to ask more:

* Is it being exploited?
* How likely is exploitation?
* Which asset contains it?
* How important is that asset?
* Is it internet-facing?
* Are compensating controls present?
* How much effort does remediation require?
* What information was actually known when the decision was made?

The project therefore investigates **risk-based prioritization rather than severity-only ranking**.

---

# 2. CVE, CVSS, EPSS, KEV — Know the Difference

This is foundational.

## CVE

A **CVE** identifies a publicly disclosed vulnerability.

Think:

```text
CVE-2021-44228
```

It is an identifier, not a risk score.

---

## CVSS

**CVSS — Common Vulnerability Scoring System**

CVSS attempts to characterize vulnerability severity using a standardized scoring framework.

The project uses:

```text
CVSS v3.1 Base Score
```

typically represented on a:

```text
0.0 → 10.0
```

scale.

Important distinction:

> CVSS measures vulnerability severity characteristics. It is not equivalent to real-world exploitation probability.

---

## EPSS

**EPSS — Exploit Prediction Scoring System**

EPSS estimates the likelihood that a vulnerability will be exploited in the wild within the relevant prediction framework.

The project uses an EPSS dataset/snapshot.

But this creates a major temporal problem.

Suppose:

```text
CVE published: 2021
EPSS snapshot: 2026
```

You cannot train a historical 2021 prediction model using the 2026 EPSS value and then claim:

> "This model predicted what we knew in 2021."

It did not.

That is **future information leakage**.

---

## KEV

**CISA Known Exploited Vulnerabilities Catalog**

KEV contains vulnerabilities identified as being exploited in the wild according to CISA's catalog criteria.

The project uses:

```text
is_kev
```

as a prediction target.

But:

> KEV membership is not identical to "probability of exploitation."

It is a useful operational target/proxy, but it has limitations.

---

# 3. The Central Research Problem: Time

This is arguably the most important concept in the entire project.

Suppose we want to predict:

> Will CVE X eventually enter KEV?

For a vulnerability published in 2021, imagine the following timeline:

```text
2021
│
├── CVE published
├── description available
├── initial metadata available
│
│      ← prediction point
│
├── vulnerability evolves
├── exploitation may occur
├── EPSS changes
│
2022
│
├── more information becomes available
│
...
│
2026
└── EPSS snapshot available
```

If our model uses a 2026 EPSS score to make the "2021 prediction," we're cheating unintentionally.

Therefore:

```text
Prediction time
       ↓
Only information available by then
       ↓
Model prediction
       ↓
Future outcome
```

This is the fundamental logic behind EXP-B2.

---

# 4. Why Random Train/Test Splitting Was Rejected

A conventional ML workflow might do:

```text
shuffle all CVEs
        ↓
80% train
20% test
```

That is problematic for historical cybersecurity research.

Imagine:

```text
2002 → train
...
2026 → train
2023 → test
```

The model has already seen future-era vulnerability patterns while being evaluated on older vulnerabilities.

This is not a realistic deployment scenario.

Instead:

```text
2002–2022 → TRAIN
2023–2024 → VALIDATION
2025–2026 → TEST
```

Now the model is asked to move forward through time.

This is called a **temporal split**.

---

# 5. Why the Test Set Must Be Untouched

The test set is supposed to answer:

> How does the finalized model perform on future-like unseen data?

If you repeatedly inspect test performance and change the model because of it:

```text
model
 ↓
test
 ↓
change model
 ↓
test
 ↓
change model
 ↓
test
```

the test set is no longer genuinely unseen.

Therefore:

```text
TRAIN
  ↓
model development

VALIDATION
  ↓
model selection

FREEZE
  ↓
final configuration

TEST
  ↓
final evaluation
```

This distinction is critical for defending the research.

---

# 6. Why the Dataset Was Frozen

Imagine the experiment says:

> XGBoost achieved 0.975 MAE.

But someone later changes the underlying NVD/KEV data and reruns the model.

Now:

```text
Experiment result
     ≠
original dataset
```

The result is no longer reproducible.

Therefore the project deliberately established:

```text
raw data
   ↓
ETL
   ↓
canonical processed data
   ↓
FREEZE
```

Experiments and application code read the frozen data.

They don't modify it.

---

# 7. What ETL Means Here

**ETL = Extract, Transform, Load**

In this project:

### Extract

Read:

* NVD
* CPE
* KEV
* EPSS
* vendor statements

### Transform

Normalize and combine them into useful relationships.

For example:

```text
CVE
 ├── description
 ├── CWE
 ├── CPE
 ├── CVSS
 ├── KEV
 └── EPSS
```

### Load

Store canonical datasets as Parquet.

---

# 8. Why Parquet?

Parquet is a columnar data format.

This is useful for analytical datasets because we often want:

```text
Give me:
CVE ID
CVSS
publication date
KEV
EPSS
```

without loading every possible field.

It also works well with analytical query engines such as DuckDB.

The architecture therefore became:

```text
Parquet
   ↓
DuckDB
   ↓
FastAPI
```

rather than immediately introducing a large mutable database.

---

# 9. The Reproducibility Bug

One of the best lessons from the project was that **reproducibility itself needs to be implemented correctly**.

Suppose:

```text
CVE-1, CPE-X, flag=A
CVE-1, CPE-X, flag=B
```

If we sort only by:

```text
CVE
CPE
```

both rows have the same sorting key.

Their relative order can differ.

Then:

```text
CSV representation A
≠
CSV representation B
```

even though:

```text
logical rows A
=
logical rows B
```

Therefore the original fingerprinting method was insufficient.

The fix was canonicalization using **all columns**.

Conceptually:

```text
columns → alphabetically sorted
rows → sorted using every column
NULL → standardized
floats → standardized
timestamps → standardized
line endings → standardized
        ↓
canonical bytes
        ↓
SHA-256
```

That is a much stronger reproducibility check.

---

# 10. Why SHA-256?

SHA-256 creates a fixed-length cryptographic digest of data.

Conceptually:

```text
dataset
   ↓
SHA-256
   ↓
64 hexadecimal characters
```

If the underlying byte stream changes, the digest should change.

It doesn't prove that two datasets are semantically identical by itself.

That is why this project additionally performed **row-by-row logical comparisons**.

The important distinction:

```text
hash comparison
+
logical row comparison
+
schema comparison
+
null-count comparison
```

gave us much stronger evidence.

---

# 11. Experiment A1 — What Are We Actually Predicting?

A1 asks:

> Can we estimate the authoritative CVSS v3.1 base score from information available before formal scoring?

The target is:

```text
y = CVSS v3.1 Base Score
```

This is a regression problem because the output is continuous.

For example:

```text
7.2
8.1
9.8
4.3
```

---

# 12. Ridge Regression

Ridge is the linear baseline.

Conceptually:

[
\hat y = w_1x_1+w_2x_2+\dots+w_nx_n+b
]

Ridge adds regularization.

The important idea is:

> It assumes the prediction can largely be represented as a weighted linear combination of features.

This gives us a baseline.

If a complex nonlinear model only marginally beats Ridge, nonlinear complexity may not be justified.

---

# 13. XGBoost

XGBoost is a gradient-boosted decision-tree model.

Instead of one linear equation, it builds many decision trees sequentially.

Conceptually:

```text
input
 ↓
tree 1
 ↓
error
 ↓
tree 2 improves error
 ↓
tree 3 improves remaining error
 ↓
...
 ↓
prediction
```

It can naturally model nonlinear relationships and interactions.

That makes it a reasonable candidate for the project's hypothesis that vulnerability characteristics may interact rather than simply add together.

---

# 14. What MAE Means

MAE:

[
MAE = \frac{1}{n}\sum |y_i-\hat y_i|
]

If:

```text
actual = 8.5
predicted = 7.5
```

the absolute error is:

```text
1.0
```

An MAE of:

```text
0.975
```

means the average absolute prediction error is approximately **0.975 CVSS points** over the evaluated observations.

It does **not** mean every prediction is within 0.975.

---

# 15. Why RMSE Also Matters

RMSE:

[
RMSE=
\sqrt{
\frac{1}{n}
\sum(y_i-\hat y_i)^2
}
]

Because errors are squared, large errors matter more.

Therefore:

```text
MAE → average absolute error
RMSE → penalizes large errors more heavily
```

---

# 16. What R² Means

R² measures how much variation in the target is explained relative to a baseline formulation.

A simplified interpretation:

```text
R² = 0
```

means no improvement over the relevant mean-based baseline.

Higher values indicate more explained variance.

But R² is not:

> "percentage accuracy."

That distinction matters in a viva.

---

# 17. A1 Result Interpretation

The test results were:

```text
Ridge:
MAE = 1.0954
R²  = 0.3194

XGBoost:
MAE = 0.9750
R²  = 0.4153
```

Therefore XGBoost performed better.

But the correct statement is:

> XGBoost achieved lower prediction error and higher explained variance than the Ridge baseline on the temporally held-out test partition.

Do **not** say:

> XGBoost predicts CVSS perfectly.

---

# 18. A1 Does Not Replace CVSS

This distinction is important.

The system has:

```text
Authoritative CVSS
```

and:

```text
Predicted CVSS
```

The model prediction is an estimate.

The authoritative score remains authoritative.

The purpose is research into whether pre-scoring information contains predictive signal.

---

# 19. Experiment B2 — Classification

B2 asks:

> Can we predict whether a vulnerability will eventually appear in KEV using publication-time information?

The target:

```text
is_kev ∈ {0,1}
```

This is binary classification.

---

# 20. Logistic Regression

Logistic regression predicts a probability through a logistic function:

[
P(y=1|x)=\frac{1}{1+e^{-z}}
]

where:

[
z=w^Tx+b
]

It is therefore a linear decision model in feature space.

Again, it provides a baseline.

---

# 21. XGBoost Classifier

The XGBoost classifier provides a nonlinear alternative.

The important comparison is:

```text
Logistic Regression
        vs
XGBoost
```

If XGBoost performs better, this suggests nonlinear structure may contain useful predictive information.

---

# 22. Why Accuracy Is Bad for B2

Suppose:

```text
100,000 vulnerabilities
300 KEV
99,700 non-KEV
```

A stupid model could predict:

```text
NOT KEV
```

for everything.

Accuracy:

```text
99.7%
```

That sounds amazing.

But the model detects:

```text
0 KEV vulnerabilities
```

So accuracy is misleading.

This is why the project emphasizes **PR-AUC**.

---

# 23. Precision

[
Precision=
\frac{TP}{TP+FP}
]

Meaning:

> Of everything we predicted as positive, how much was actually positive?

For a triage queue, this is useful because analysts care about how many of the top candidates are genuinely relevant.

---

# 24. Recall

[
Recall=
\frac{TP}{TP+FN}
]

Meaning:

> Of all actual positives, how many did we find?

For security triage, missing important vulnerabilities can be costly.

Therefore precision and recall represent different operational concerns.

---

# 25. PR-AUC

A Precision-Recall curve shows the tradeoff between:

```text
precision
```

and:

```text
recall
```

across thresholds.

PR-AUC summarizes that behavior.

For heavily imbalanced problems, it is generally much more informative than accuracy.

---

# 26. Why Precision@500 Exists

Imagine an analyst can investigate only:

```text
500 vulnerabilities
```

today.

The question becomes:

> How many useful candidates appear in the top 500?

That is directly operational.

The B2 XGBoost result:

```text
Precision@500 = 6.4%
```

means approximately:

```text
32 positive candidates
```

among 500, under that evaluation setup.

This is still not a magical result—but it is much more meaningful than saying:

> "The model is 99% accurate."

---

# 27. B2's Most Important Result

The strongest methodological result isn't necessarily:

```text
XGBoost beats Logistic Regression.
```

It is:

```text
B2 without future EPSS
        ↓
PR-AUC = 0.02884

B1 with 2026 retrospective EPSS
        ↓
PR-AUC = 0.33153
```

That enormous difference shows how dangerous temporal leakage can be.

---

# 28. Why B1 Is Not a "Better Model"

This is a likely viva trap.

Someone may ask:

> Why don't you simply use EPSS since it gives much better performance?

Answer:

Because the experiment asks a historical publication-time question.

If the model predicts from the perspective of publication time, a 2026 EPSS value cannot be used for a 2021 prediction.

B1 is therefore useful precisely because it demonstrates the **inflation caused by retrospective information**.

---

# 29. C1 — Why Not Just Use ML?

C1 is intentionally different.

We wanted to investigate prioritization itself.

Suppose we define:

```text
CVSS
EPSS
KEV
Asset Criticality
```

A simple approach is to add them.

That gives the linear baseline.

But adding signals assumes a relatively simple relationship.

Real risk can involve interactions.

For example:

```text
moderate vulnerability
+
high exploit likelihood
+
critical asset
```

may be considerably more important than the individual scores suggest.

---

# 30. Linear Baseline

The project-controlled baseline is:

[
S_L=
0.25x_1+
0.25x_2+
0.25x_3+
0.25x_4
]

This means each normalized factor contributes equally.

The critical academic wording is:

> **Project-controlled equal weights baseline.**

It is not claimed to be a universally correct risk formula.

---

# 31. Nonlinear Surface

The nonlinear model is:

[
S_N=
x_4
\left[
1-
(1-x_1)^{1+x_3}
(1-x_2)^{1+1.5x_3}
\right]
]

Here the variables interact.

The exponent changes based on (x_3).

That means:

```text
effect of x1
```

can depend on:

```text
x3
```

and similarly for:

```text
effect of x2
```

This is the core idea of an interaction.

---

# 32. What Asset Criticality Does

Asset criticality is:

```text
Tier 1 = 0.25
Tier 2 = 0.50
Tier 3 = 0.75
Tier 4 = 1.00
```

It acts as contextual information.

The same vulnerability can therefore receive different prioritization depending on the asset it affects.

That is much closer to the idea of **risk-based prioritization** than treating every installation equally.

---

# 33. Why C1 Uses Synthetic Tiers

Because we don't possess real enterprise asset data.

We therefore cannot honestly claim:

> "Criticality Tier 4 corresponds to actual enterprise risk."

Instead:

> "We controlled asset criticality as an experimental variable."

This allows us to study the mathematical behavior without fabricating enterprise evidence.

---

# 34. Understanding the C1 Results

The overall ranking correlation was extremely high:

```text
Spearman ρ = 0.9962
```

At first glance that sounds like:

> The two models are basically identical.

But then:

```text
Top-100 Jaccard = 0.005
```

That is dramatically different.

Why?

Because correlation measures the overall ordering relationship.

Security teams often care about:

```text
TOP 100
```

rather than the entire 200,000+ vulnerability population.

Two ranking systems can therefore agree almost everywhere while disagreeing heavily about the exact vulnerabilities at the top.

That is a central insight of the project.

---

# 35. Jaccard Similarity

For two sets A and B:

[
J(A,B)=\frac{|A\cap B|}{|A\cup B|}
]

If:

```text
A = model 1's top 100
B = model 2's top 100
```

then Jaccard tells us how much the sets overlap.

A very low value means the actual remediation queue is substantially different.

---

# 36. SHAP — What It Actually Does

SHAP is based on Shapley-value ideas from cooperative game theory.

The conceptual question is:

> How much did each feature contribute to this particular prediction?

For a prediction:

```text
baseline prediction
       +
feature contributions
       =
model prediction
```

This lets us investigate which features drive model behavior.

---

# 37. SHAP Does Not Mean Causality

Suppose SHAP says:

```text
feature X → +0.8 contribution
```

That means:

> Feature X contributed positively to the model's prediction.

It does **not** prove:

> Feature X causes the real-world vulnerability outcome.

This distinction is essential.

---

# 38. Why the Original LOO Explanation Was Replaced

The initial implementation used word deletion.

Example:

```text
"remote unauthenticated SQL injection"
```

Remove:

```text
"SQL"
```

and see how prediction changes.

That is useful, but problematic.

The model used:

```text
unigrams + bigrams
```

so:

```text
SQL injection
```

could itself be a feature.

Removing one token can destroy a meaningful phrase.

Therefore the attribution doesn't perfectly correspond to the actual feature representation.

This was one reason the final system moved to SHAP for the tree models.

---

# 39. Backend Architecture

The backend exists to turn the research artifacts into an actual usable system.

Conceptually:

```text
HTTP request
     ↓
FastAPI
     ↓
service layer
     ↓
data/model/scoring layer
     ↓
response
```

The major responsibilities are separated.

---

# 40. Vulnerability Service

Responsible for:

* search
* filtering
* pagination
* vulnerability details

It interacts with the frozen dataset.

---

# 41. Inference Service

Responsible for loading:

```text
A1 XGBoost
B2 XGBoost
```

and their associated preprocessing.

This prevents the API layer from containing ML implementation details.

---

# 42. Scoring Service

Responsible for:

```text
Linear baseline
Nonlinear surface
```

and asset tiers.

This keeps mathematical prioritization logic separate from HTTP handling.

---

# 43. Explanation Service

Responsible for:

```text
SHAP
```

and returning model feature contributions.

Again:

```text
API
≠
SHAP implementation
```

This separation makes the system easier to test and reason about.

---

# 44. Provenance Service

This exists because research systems need to answer:

> Where did this number come from?

It exposes information such as:

* dataset state
* model version
* research experiment
* temporal boundaries
* EPSS snapshot
* limitations

The frontend therefore does not have to independently know these facts.

---

# 45. Why DuckDB?

The dataset is large enough that:

```text
load everything into every request
```

would be poor architecture.

DuckDB can query Parquet directly.

Conceptually:

```text
Parquet files
     ↓
DuckDB query
     ↓
only required rows/columns
     ↓
FastAPI
```

This preserves the immutable dataset while giving the application query capabilities.

---

# 46. Why No Traditional Database?

A mutable PostgreSQL database could have been used.

But the core research dataset is fundamentally:

```text
analytical
large
mostly immutable
```

DuckDB + Parquet therefore fits the current research prototype well.

A production system might eventually use another architecture.

---

# 47. API Boundary

One particularly important architectural rule is:

> The frontend cannot be trusted to enforce research constraints.

For example:

```text
Frontend says:
"Don't send EPSS to B2."
```

is not enough.

The backend also checks.

If forbidden information is submitted:

```text
HTTP 422
```

is returned.

This makes the methodological boundary enforceable rather than merely documented.

---

# 48. Why the Frontend Came Last

The project deliberately followed:

```text
data
 ↓
research
 ↓
models
 ↓
backend
 ↓
UI
```

rather than:

```text
pretty dashboard
 ↓
invent what the dashboard needs
 ↓
build ML around it
```

This was important because the UI should represent validated research capabilities rather than determine them.

---

# 49. The Frontend's Job

The frontend is essentially the **human interaction layer**.

It allows an analyst to:

```text
find vulnerabilities
      ↓
inspect vulnerability
      ↓
understand severity/threat
      ↓
run predictions
      ↓
evaluate asset context
      ↓
compare prioritization
      ↓
inspect explanations
      ↓
understand provenance
```

It does not own the research logic.

---

# 50. The Most Important Distinctions to Memorize

These are worth knowing almost verbatim.

### CVE

> Vulnerability identifier.

### CVSS

> Standardized vulnerability severity scoring system.

### EPSS

> Exploit prediction signal that must be time-aligned when used for historical prediction.

### KEV

> CISA catalog of known exploited vulnerabilities; used in this project as a prediction target/proxy.

### Regression

> Predicting a continuous numerical value.

A1:

```text
CVSS score
```

### Classification

> Predicting a class/probability.

B2:

```text
future KEV membership
```

### Temporal split

> Partitioning observations chronologically to preserve realistic prediction direction.

### Data leakage

> Information entering model development/evaluation that would not legitimately have been available at the prediction point.

### SHAP

> Post-hoc feature attribution method for explaining model predictions.

### Precision

> Fraction of predicted positives that are actually positive.

### Recall

> Fraction of actual positives that are successfully identified.

### PR-AUC

> Area under the precision-recall curve, particularly informative under class imbalance.

### Jaccard

> Intersection divided by union of two sets.

---

# 51. The Complete Data Flow

You should be able to draw this from memory:

```text
                 NVD
                  │
        ┌─────────┼─────────┐
        │         │         │
       CPE       CWE       CVSS
        │         │         │
        └─────────┼─────────┘
                  │
              Deterministic
                  ETL
                  │
      ┌───────────┴────────────┐
      │ Frozen Parquet Dataset │
      └───────────┬────────────┘
                  │
       ┌──────────┼──────────┐
       │          │          │
      A1         B2         C1
       │          │          │
    CVSS ML    KEV ML     Risk Surface
       │          │          │
       └──────────┼──────────┘
                  │
                SHAP
                  │
                  ▼
              FastAPI
                  │
        ┌─────────┼──────────┐
        │         │          │
      Search   Predict   Prioritize
        │         │          │
        └─────────┼──────────┘
                  │
                  ▼
               Frontend
```

---

# 52. The Complete Research Logic

The project can also be understood as four questions:

### Question A

> Can we estimate vulnerability severity before formal CVSS scoring?

Experiment:

```text
A1
```

Answer:

> Partially supported; measurable predictive signal exists and XGBoost outperformed Ridge, but predictions are imperfect.

---

### Question B

> Can publication-time information predict future KEV inclusion?

Experiment:

```text
B2
```

Answer:

> Partially supported; measurable signal exists, but absolute predictive performance remains limited.

---

### Question B2

> What happens if we accidentally use future EPSS information?

Experiment:

```text
B1
```

Answer:

> Apparent performance increases dramatically, demonstrating the importance of temporal feature boundaries.

---

### Question C

> Does a nonlinear context-aware prioritization surface behave differently from a linear additive baseline?

Experiment:

```text
C1
```

Answer:

> Yes, particularly at the top of the remediation queue, although the experiment does not prove that the nonlinear surface is superior in real enterprise environments.

---

# 53. What You Should Be Able to Defend

If you understand this project properly, you should be able to answer:

### Why XGBoost?

Because the research hypothesis concerns nonlinear relationships and feature interactions, while Ridge/Logistic Regression provide interpretable linear baselines.

### Why temporal splitting?

Because cybersecurity information evolves over time and random splitting can allow future information to influence historical evaluation.

### Why no EPSS in B2?

Because the static EPSS snapshot is later than many prediction points and would introduce temporal leakage.

### Why have B1?

To empirically demonstrate how severe that leakage can be.

### Why PR-AUC?

Because KEV membership is extremely imbalanced and accuracy would be misleading.

### Why C1?

Because prediction and prioritization are not identical problems. C1 investigates how vulnerability/threat signals interact with asset context.

### Why synthetic asset tiers?

Because real enterprise asset data aren't available; controlled tiers let us study the mathematical behavior without fabricating enterprise evidence.

### Why SHAP?

To explain the behavior of the nonlinear models after they are frozen.

### Why not call SHAP causal?

Because feature contribution to a predictive model is not evidence of causal effect.

### Why freeze the dataset?

To make experiments reproducible and prevent later application changes from altering historical results.

### Why DuckDB?

Efficient analytical querying of immutable Parquet without immediately introducing a mutable database.

### Why frontend last?

Because the research methodology should determine what the application represents, not the other way around.

---

# 54. The Most Important Mental Model

Do not think of the project as:

> "A website with some ML."

Think of it as:

```text
RESEARCH QUESTION
       ↓
METHODOLOGICAL DEFINITION
       ↓
DATA AVAILABILITY RULE
       ↓
TEMPORAL EXPERIMENT
       ↓
MODEL
       ↓
EVALUATION
       ↓
INTERPRETATION
       ↓
APPLICATION
```

The website is the **last layer**.

The actual intellectual core is the chain above.

---

# 55. Where the Project Is Weak

Knowing weaknesses is part of understanding it.

### Weakness 1 — KEV is imperfect ground truth

KEV membership is not the same thing as all real exploitation.

### Weakness 2 — C1 uses synthetic asset context

The nonlinear prioritization result has not been validated against real enterprise remediation decisions.

### Weakness 3 — B2 performance is limited

The model has meaningful signal but does not produce a highly accurate exploitation predictor.

### Weakness 4 — Dataset snapshot

The research is based on a frozen historical data snapshot.

### Weakness 5 — No real remediation outcomes

We don't know whether the model actually causes organizations to remediate better.

### Weakness 6 — Model generalization

Future vulnerability distributions can change.

### Weakness 7 — Explainability limitations

SHAP explains the model, not reality.

Knowing these weaknesses prevents overclaiming.

---

# 56. If You Had to Rebuild the Project Yourself

The correct order would be:

```text
1. Acquire and verify raw NVD/CISA/EPSS data

2. Build deterministic ETL

3. Validate joins and schemas

4. Generate canonical Parquet

5. Freeze dataset

6. Verify reproducibility

7. Define temporal train/validation/test split

8. Define feature availability at prediction time

9. Build A1 baseline

10. Build A1 XGBoost

11. Evaluate A1

12. Build B2 Logistic baseline

13. Build B2 XGBoost

14. Evaluate using PR-AUC etc.

15. Build B1 only as retrospective sensitivity analysis

16. Build controlled C1 scoring experiment

17. Perform post-hoc SHAP

18. Freeze experiment outputs

19. Serialize final models

20. Build read-only backend

21. Expose prediction/scoring APIs

22. Enforce temporal boundaries at API level

23. Build frontend

24. Verify end-to-end
```

That sequence is the architecture.

---

# 57. Final Understanding Check

Before considering yourself fully prepared, you should eventually be able to explain these without looking anything up:

```text
□ What is CVE?
□ What is CVSS?
□ What is EPSS?
□ What is KEV?
□ Why is KEV not identical to exploitation probability?
□ Regression vs classification?
□ Ridge regression?
□ Logistic regression?
□ Decision trees?
□ Gradient boosting?
□ XGBoost?
□ TF-IDF?
□ What is an n-gram?
□ Why can bigrams matter?
□ What is temporal leakage?
□ Why is random splitting problematic?
□ Why is the test set untouched?
□ Why PR-AUC instead of accuracy?
□ Precision vs recall?
□ Precision@500?
□ MAE?
□ RMSE?
□ R²?
□ Spearman correlation?
□ Jaccard similarity?
□ What is nonlinear interaction?
□ What is the C1 equation?
□ Why synthetic asset tiers?
□ What is SHAP?
□ Why isn't SHAP causal?
□ Why freeze Parquet?
□ Why canonicalize fingerprints?
□ Why DuckDB?
□ What does FastAPI do?
□ What does the inference service do?
□ What does the scoring service do?
□ Why must B2 reject EPSS?
□ Why is B1 retrospective?
□ Why did the UI come last?
□ What does the project actually prove?
□ What does it explicitly NOT prove?
```

That checklist is essentially the boundary between **having used the system** and **actually understanding the system**.

---

## The one idea to carry into the presentation

If everything else temporarily disappears, remember this:

> **The project's central contribution is not simply applying XGBoost to vulnerabilities. It is demonstrating how vulnerability prioritization must respect information availability over time, while investigating nonlinear relationships between vulnerability characteristics, exploitation signals, and asset context.**

The B1/B2 leakage comparison is especially important because it demonstrates **why methodological discipline matters**, rather than merely reporting another model score.

This completes **Deliverable 3/4**.

