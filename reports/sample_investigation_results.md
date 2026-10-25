# Sample Investigation Results

## Overview
This report demonstrates the output of the Digital Detective cybersecurity log analysis pipeline using a small synthetic dataset.

## Investigation Summary

| User ID | Failed Logins | Successful Logins | Large File Access Events | Total Data Accessed | Priority |
|---|---:|---:|---:|---:|---|
| U104 | 3 | 1 | 2 | 2,050 MB | HIGH PRIORITY |
| U101 | 0 | 1 | 0 | 5 MB | REVIEW |
| U102 | 0 | 1 | 0 | 0 MB | REVIEW |

## Finding: U104

The synthetic log data records:
- Three failed login attempts at 09:10, 09:11, and 09:12.
- A successful login at 09:14.
- Access to `customer_records.csv`, involving 850 MB.
- Access to `financial_records.csv`, involving 1,200 MB.

The investigation rule flags this activity because it combines repeated failed logins with multiple large file-access events.

## Interpretation
U104 is assigned **HIGH PRIORITY** for further investigation. This is a rule-based alert using synthetic data, not proof of an actual cyberattack or malicious intent.

## Limitations
- The dataset is small and synthetic.
- Detection thresholds are illustrative.
- Production deployment would require testing against representative, labelled security logs and reviewing false positives.
