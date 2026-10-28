# Threat model

63 threats for the architecture described by this plan.

| Element | Threat | Title | Severity |
|---|---|---|---|
| aws_instance.api | AA01 | Authentication Abuse/ByPass | Medium |
| aws_instance.api | AA02 | Principal Spoof | Medium |
| aws_instance.api | AA03 | Exploitation of Trusted Credentials | High |
| aws_instance.api | AA04 | Exploiting Trust in Client | High |
| aws_instance.api | AC01 | Privilege Abuse | Medium |
| aws_instance.api | AC06 | Using Malicious Files | Very High |
| aws_instance.api | AC07 | Exploiting Incorrectly Configured Access Control Security Levels | Medium |
| aws_instance.api | AC08 | Manipulate Registry Information | Medium |
| aws_instance.api | AC09 | Functionality Misuse | Medium |
| aws_instance.api | AC11 | Session Credential Falsification through Manipulation | Medium |
| aws_instance.api | AC16 | Session Credential Falsification through Prediction | High |
| aws_instance.api | AC17 | Session Hijacking - ServerSide | Very High |
| aws_instance.api | CR03 | Dictionary-based Password Attack | High |
| aws_instance.api | CR05 | Encryption Brute Forcing | Low |
| aws_instance.api | DE02 | Double Encoding | Medium |
| aws_instance.api | DO01 | Flooding | Medium |
| aws_instance.api | DO02 | Excessive Allocation | Medium |
| aws_instance.api | DS01 | Excavation | Medium |
| aws_instance.api | DS03 | Footprinting | Very Low |
| aws_instance.api | DS04 | XSS Targeting Error Pages | Medium |
| aws_instance.api | HA01 | Path Traversal | Very High |
| aws_instance.api | HA03 | Web Application Fingerprinting | Low |
| aws_instance.api | INP03 | Server Side Include (SSI) Injection | High |
| aws_instance.api | INP05 | Command Line Execution through SQL Injection | Very High |
| aws_instance.api | INP08 | Format String Injection | High |
| aws_instance.api | INP09 | LDAP Injection | High |
| aws_instance.api | INP10 | Parameter Injection | Medium |
| aws_instance.api | INP11 | Relative Path Traversal | High |
| aws_instance.api | INP14 | Input Data Manipulation | Medium |
| aws_instance.api | INP16 | PHP Remote File Inclusion | High |
| aws_instance.api | INP17 | XSS Using MIME Type Mismatch | Medium |
| aws_instance.api | INP18 | Fuzzing and observing application log data/errors for application mapping | Low |
| aws_instance.api | INP19 | XML External Entities Blowup | Medium |
| aws_instance.api | INP21 | DTD Injection | Medium |
| aws_instance.api | INP22 | XML Attribute Blowup | High |
| aws_instance.api | INP28 | XSS Targeting URI Placeholders | High |
| aws_instance.api | INP29 | XSS Using Doubled Characters | Medium |
| aws_instance.api | INP34 | SOAP Array Overflow | High |
| aws_instance.api | INP36 | HTTP Response Smuggling | Medium |
| aws_instance.api | INP37 | HTTP Request Smuggling | High |
| aws_instance.api | SC02 | XSS Targeting Non-Script Elements | Very High |
| aws_instance.api | SC03 | Embedding Scripts within Scripts | High |
| aws_instance.api | SC04 | XSS Using Alternate Syntax | High |
| aws_instance.api | SC05 | Removing Important Client Functionality | High |
| aws_s3_bucket.ledger | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.ledger | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.ledger | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.ledger | DO02 | Excessive Allocation | Medium |
| aws_instance.api → IMDS of aws_instance.api | AC05 | Content Spoofing | Medium |
| aws_instance.api → IMDS of aws_instance.api | CR06 | Communication Channel Manipulation | High |
| aws_instance.api → IMDS of aws_instance.api | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_instance.api → IMDS of aws_instance.api | DE01 | Interception | Medium |
| aws_instance.api → IMDS of aws_instance.api | DE03 | Sniffing Attacks | Medium |
| aws_instance.api → aws_s3_bucket.ledger | AC05 | Content Spoofing | Medium |
| aws_instance.api → aws_s3_bucket.ledger | CR06 | Communication Channel Manipulation | High |
| aws_instance.api → aws_s3_bucket.ledger | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_instance.api → aws_s3_bucket.ledger | DE01 | Interception | Medium |
| aws_instance.api → aws_s3_bucket.ledger | DE03 | Sniffing Attacks | Medium |
| Internet client → aws_instance.api | AC05 | Content Spoofing | Medium |
| Internet client → aws_instance.api | CR06 | Communication Channel Manipulation | High |
| Internet client → aws_instance.api | CR08 | Client-Server Protocol Manipulation | Medium |
| Internet client → aws_instance.api | DE01 | Interception | Medium |
| Internet client → aws_instance.api | DE03 | Sniffing Attacks | Medium |
