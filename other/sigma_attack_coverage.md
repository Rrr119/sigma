# MITRE ATT&CK Coverage Report

- ATT&CK version: 20.1
- Rules scanned: 3807
- Rules with ATT&CK techniques: 3337 (87.65%)
- Rules with ATT&CK tactics: 3805
- Rules without a technique: 470
- Techniques covered: 401/706 (56.80%)

## Coverage by tactic

| Tactic | Covered | Total | Coverage | Rules |
| --- | ---: | ---: | ---: | ---: |
| reconnaissance | 12 | 46 | 26.09% | 26 |
| resource-development | 10 | 51 | 19.61% | 39 |
| initial-access | 17 | 22 | 77.27% | 354 |
| execution | 41 | 66 | 62.12% | 1056 |
| persistence | 74 | 113 | 65.49% | 869 |
| privilege-escalation | 67 | 96 | 69.79% | 775 |
| stealth | 84 | 151 | 55.63% | 1101 |
| credential-access | 45 | 68 | 66.18% | 398 |
| discovery | 36 | 49 | 73.47% | 266 |
| lateral-movement | 17 | 23 | 73.91% | 171 |
| collection | 23 | 41 | 56.10% | 126 |
| command-and-control | 24 | 45 | 53.33% | 312 |
| exfiltration | 10 | 20 | 50.00% | 92 |
| impact | 18 | 33 | 54.55% | 168 |
| defense-impairment | 33 | 57 | 57.89% | 424 |

## Top covered techniques

| Technique | Name | Tactic | Rules |
| --- | --- | --- | ---: |
| T1059.001 | PowerShell | execution | 222 |
| T1685 | Disable or Modify Tools | defense-impairment | 168 |
| T1218 | System Binary Proxy Execution | stealth | 158 |
| T1190 | Exploit Public-Facing Application | initial-access | 149 |
| T1112 | Modify Registry | defense-impairment, persistence | 98 |
| T1027 | Obfuscated Files or Information | stealth | 95 |
| T1059 | Command and Scripting Interpreter | execution | 95 |
| T1574.001 | DLL | stealth, execution | 93 |
| T1105 | Ingress Tool Transfer | command-and-control | 87 |
| T1003.001 | LSASS Memory | credential-access | 79 |
| T1078 | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 56 |
| T1548.002 | Bypass User Account Control | privilege-escalation | 56 |
| T1053.005 | Scheduled Task | execution, persistence, privilege-escalation | 53 |
| T1047 | Windows Management Instrumentation | execution | 52 |
| T1543.003 | Windows Service | persistence, privilege-escalation | 47 |
| T1059.003 | Windows Command Shell | execution | 46 |
| T1219.002 | Remote Desktop Software | command-and-control | 46 |
| T1218.011 | Rundll32 | stealth | 43 |
| T1569.002 | Service Execution | execution | 43 |
| T1071.001 | Web Protocols | command-and-control | 42 |

## Uncovered techniques by tactic

| Tactic | Uncovered | Examples |
| --- | ---: | --- |
| reconnaissance | 34 | T1589.001, T1589.003, T1590.003, T1590.004, T1590.005, T1590.006, T1591, T1591.001, T1591.002, T1591.003, T1592, T1592.001, ... |
| resource-development | 41 | T1583, T1583.001, T1583.002, T1583.003, T1583.004, T1583.005, T1583.006, T1583.007, T1583.008, T1584.001, T1584.002, T1584.003, ... |
| initial-access | 5 | T1195.003, T1566.003, T1566.004, T1659, T1669 |
| execution | 25 | T1053.006, T1053.007, T1059.008, T1059.010, T1059.011, T1059.013, T1127.002, T1127.003, T1204.003, T1204.005, T1559.003, T1569.003, ... |
| persistence | 39 | T1037, T1037.002, T1037.003, T1037.004, T1053.006, T1053.007, T1098.002, T1098.004, T1098.006, T1098.007, T1137.001, T1137.004, ... |
| privilege-escalation | 29 | T1037, T1037.002, T1037.003, T1037.004, T1053.006, T1053.007, T1055.002, T1055.004, T1055.005, T1055.008, T1055.013, T1055.014, ... |
| stealth | 67 | T1027.006, T1027.007, T1027.008, T1027.012, T1027.013, T1027.014, T1027.015, T1027.016, T1027.017, T1027.018, T1036.001, T1036.009, ... |
| credential-access | 23 | T1003.007, T1003.008, T1056.003, T1056.004, T1110.003, T1110.004, T1111, T1552.005, T1552.008, T1555.002, T1555.006, T1556.001, ... |
| discovery | 13 | T1016.001, T1016.002, T1087.003, T1497, T1497.002, T1497.003, T1518.002, T1538, T1614, T1652, T1654, T1673, ... |
| lateral-movement | 6 | T1021.008, T1080, T1534, T1550.004, T1563, T1563.001 |
| collection | 18 | T1025, T1056.003, T1056.004, T1074.002, T1114.002, T1213.001, T1213.002, T1213.004, T1213.005, T1213.006, T1530, T1557.002, ... |
| command-and-control | 21 | T1001, T1001.001, T1001.002, T1071.002, T1071.003, T1071.005, T1092, T1104, T1132, T1132.002, T1205, T1205.001, ... |
| exfiltration | 10 | T1011, T1011.001, T1020.001, T1029, T1048.002, T1052, T1052.001, T1567.003, T1567.004, T1700 |
| impact | 15 | T1485.001, T1491, T1491.002, T1496.001, T1496.002, T1496.003, T1496.004, T1498.001, T1498.002, T1499.002, T1499.003, T1561, ... |
| defense-impairment | 24 | T1553.006, T1556.001, T1556.003, T1556.005, T1556.007, T1556.008, T1556.009, T1578.001, T1578.002, T1578.004, T1578.005, T1599, ... |

## Rules without a technique

- `rules/application/github/audit/github_repository_archive_status_changed.yml (GitHub Repository Archive Status Changed)`
- `rules/application/kubernetes/audit/kubernetes_audit_cronjob_modification.yml (Kubernetes CronJob/Job Modification)`
- `rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml (Kubernetes Rolebinding Modification)`
- `rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml (Kubernetes Secrets Modified or Deleted)`
- `rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml (Kubernetes Unauthorized or Unauthenticated Access)`
- `rules/application/rpc_firewall/rpc_firewall_atsvc_recon.yml (Remote Schedule Task Recon via AtScv)`
- `rules/application/rpc_firewall/rpc_firewall_efs_abuse.yml (Remote Encrypting File System Abuse)`
- `rules/application/rpc_firewall/rpc_firewall_eventlog_recon.yml (Remote Event Log Recon)`
- `rules/application/rpc_firewall/rpc_firewall_itaskschedulerservice_recon.yml (Remote Schedule Task Recon via ITaskSchedulerService)`
- `rules/application/rpc_firewall/rpc_firewall_printing_lateral_movement.yml (Remote Printing Abuse for Lateral Movement)`
- `rules/application/rpc_firewall/rpc_firewall_remote_registry_recon.yml (Remote Registry Recon)`
- `rules/application/rpc_firewall/rpc_firewall_remote_server_service_abuse.yml (Remote Server Service Abuse)`
- `rules/application/rpc_firewall/rpc_firewall_sasec_recon.yml (Recon Activity via SASec)`
- `rules/cloud/aws/cloudtrail/aws_cloudtrail_bucket_deleted.yml (AWS Bucket Deleted)`
- `rules/cloud/aws/cloudtrail/aws_cloudtrail_region_enabled.yml (AWS EnableRegion Command Monitoring)`
- `rules/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted.yml (AWS VPC Flow Logs Deleted)`
- `rules/cloud/aws/cloudtrail/aws_efs_fileshare_modified_or_deleted.yml (AWS EFS Fileshare Modified or Deleted)`
- `rules/cloud/aws/cloudtrail/aws_lambda_function_url.yml (New AWS Lambda Function URL Configuration Created)`
- `rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml (AWS New Lambda Layer Attached)`
- `rules/cloud/aws/cloudtrail/aws_passed_role_to_glue_development_endpoint.yml (AWS Glue Development Endpoint Activity)`
- `rules/cloud/azure/activity_logs/azure_application_gateway_modified_or_deleted.yml (Azure Application Gateway Modified or Deleted)`
- `rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml (Azure Application Security Group Modified or Deleted)`
- `rules/cloud/azure/activity_logs/azure_kubernetes_pods_deleted.yml (Azure Kubernetes Pods Deleted)`
- `rules/cloud/azure/activity_logs/azure_network_firewall_rule_modified_or_deleted.yml (Azure Firewall Rule Configuration Modified or Deleted)`
- `rules/cloud/azure/activity_logs/azure_network_p2s_vpn_modified_or_deleted.yml (Azure Point-to-site VPN Modified or Deleted)`
- ... and 445 more
