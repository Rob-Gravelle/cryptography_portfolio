
\#  The Enigma Key Space

## A Mathematical and Statistical Analysis of Brute-Force Impossibility

------------------------------------------------------------------------

##  Overview

The German Enigma cipher machine achieved its perceived security through
combinatorial explosion.\
In practical WWII configurations, its key space was approximately:

$$
\sim 10^{23} \approx 2^{77} \text{ possible keys}
$$

A naive brute-force search over this space is infeasible --- even with
modern computing power.

This project demonstrates:

-   The mathematical breakdown of Enigma's key space\
-   Why brute-force attacks fail historically and computationally\
-   How statistical cryptanalysis collapses combinatorial complexity\
-   How heuristic search defeats the 150 trillion plugboard
    combinations\
-   A roadmap for ML-guided cryptanalysis (v4)

------------------------------------------------------------------------

##  Mathematical Key Space Breakdown

### 1️ Rotor Selection (Walzenlage)

From 5 rotors:

$$
P(5,3) = 60
$$

From 8 rotors:

$$
P(8,3) = 336
$$

------------------------------------------------------------------------

### 2️ Initial Rotor Positions (Grundstellung)

$$
26^3 = 17,576
$$

------------------------------------------------------------------------

### 3️ Ring Settings (Ringstellung)

All three ring settings affect the internal wiring offset:

$$
26^3
$$

Historically:

-   Only the middle and left rotors influence turnover timing.\
-   The rightmost ring setting does not affect stepping behavior but
    still changes substitution offset.

For practical wartime modeling many analyses focus on:

$$
26^2 = 676
$$

------------------------------------------------------------------------

### 4️ Plugboard (Steckerbrett)

For 10 plug pairs:

$$
\frac{26!}{(26-20)! \cdot 10! \cdot 2^{10}}
\approx 150{,}738{,}274{,}937{,}250
$$

≈ **150 trillion combinations**

------------------------------------------------------------------------

##  Total Practical Key Space

$$
60 \times 17,576 \times 676 \times 150{,}738{,}274{,}937{,}250
\approx 1.07 \times 10^{23}
$$

Equivalent to:

$$
\approx 2^{77} \text{ bits of security}
$$

------------------------------------------------------------------------

##  Brute‑Force Reality Check

At:

$$
1{,}000{,}000 \text{ keys per second}
$$

Brute force would require **millions to billions of years**.

Even at:

$$
10^{12} \text{ keys/sec}
$$

the search remains computationally impractical without structural
constraints.

------------------------------------------------------------------------

#  v2: Statistical Collapse of Key Space

**Key Insight:**

$$
\text{Statistical fitness collapses combinatorial complexity}
$$

### v2 Attack Strategy

1.  Scan all $17,576$ rotor positions\
2.  Score decryptions via trigram/bigram fitness\
3.  Keep top $20$ candidates\
4.  Perform plugboard hill‑climbing\
5.  Detect English marker density

**Result:**

-   $17,576 \rightarrow \sim20$ rotor candidates\
-   $150$ trillion plugboard combinations → a few thousand evaluations\
-   Search reduced from astronomical to seconds

We do **not** search the full key space.\
We search the **fitness landscape**.

------------------------------------------------------------------------

#  v4 (Planned): ML‑Guided Cryptanalysis

v4 explores replacing hand‑weighted n‑grams with:

-   Character‑level neural language models\
-   Domain‑specific models trained on recovered traffic\
-   Distributed beam search across rotor partitions

Important clarification:

$$
\text{ML does not reduce Enigma combinatorics — it improves the scoring function}
$$

After decrypting confirmed messages we can:

1.  Train a model on recovered traffic\
2.  Capture repetitive military phrasing\
3.  Use the model to improve early pruning

------------------------------------------------------------------------

##  Theoretical Maximum Key Space (Clarified)

Often cited value:

$$
\sim 3 \times 10^{114}
$$

This represents a purely theoretical combinatorial extreme assuming:

-   Arbitrary rotor wirings\
-   Maximum plugboard pairings\
-   Variable reflectors\
-   All permutations of components

Operational wartime Enigma security was closer to:

$$
2^{77} \text{ bits}
$$

Large --- but structurally exploitable.

------------------------------------------------------------------------

#  Core Takeaway

Security based purely on combinatorics is fragile when structure exists.

Enigma was not broken by brute force.

It was broken by:

-   Mathematical insight\
-   Statistical structure\
-   Constraint propagation\
-   Intelligent search

------------------------------------------------------------------------

Robert Gravelle

