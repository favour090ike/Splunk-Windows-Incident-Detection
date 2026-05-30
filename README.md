# Splunk-Windows-Incident-Detection


# Windows Event Log Threat Detection Dashboard (Splunk)

## Project Overview
This project simulates a corporate Security Operations Center (SOC) incident response scenario. Using Splunk Cloud, I engineered a detection data pipeline to parse Windows Security Event logs, isolate unauthorized brute-force attempts, and visualize malicious adversary activities.

## Architectural Objectives
- Emulate enterprise log ingestion using structured mock datasets.
- Filter out system noise to identify specific Windows Event IDs.
- Build metric aggregation dashboards for threat visibility.

## Threats Hunted & Splunk Queries Used

### 1. Host Brute-Force Monitoring (Event ID: 4625)
To isolate unauthorized access attempts and track password guessing patterns across the network:
```spl
| makeresults count=5 
| streamstats count as id
| eval _time=now()
| eval EventID=case(id=1, "4625", id=2, "4625", id=3, "4720", id=4, "4625", id=5, "4624")
| eval AccountName=case(id=1, "Administrator", id=2, "sql_svc", id=3, "backdoor_user", id=4, "guest", id=5, "alvin")
| eval Source_IP=case(id=1, "192.168.1.50", id=2, "45.122.3.12", id=3, "127.0.0.1", id=4, "185.220.101.5", id=5, "192.168.1.15")
| eval Status=case(EventID="4625", "Failed Logon", EventID="4720", "New User Created", EventID="4624", "Successful Logon")
| fields _time, EventID, AccountName, Source_IP, Status
| search EventID="4625"
| stats count by Source_IP, AccountName
| sort - count
