# Threat model

122 threats for the architecture described by this plan.

| Element | Threat | Title | Severity |
|---|---|---|---|
| aws_lb.web → aws_instance.app | AC05 | Content Spoofing | Medium |
| aws_lb.web → aws_instance.app | CR06 | Communication Channel Manipulation | High |
| aws_lb.web → aws_instance.app | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_lb.web → aws_instance.app | DE01 | Interception | Medium |
| aws_lb.web → aws_instance.app | DE03 | Sniffing Attacks | Medium |
| Internet client → aws_lb.web | AC05 | Content Spoofing | Medium |
| Internet client → aws_lb.web | CR06 | Communication Channel Manipulation | High |
| Internet client → aws_lb.web | CR08 | Client-Server Protocol Manipulation | Medium |
| Internet client → aws_lb.web | DE01 | Interception | Medium |
| Internet client → aws_lb.web | DE03 | Sniffing Attacks | Medium |
| aws_instance.app | AA01 | Authentication Abuse/ByPass | Medium |
| aws_instance.app | AA02 | Principal Spoof | Medium |
| aws_instance.app | AA03 | Exploitation of Trusted Credentials | High |
| aws_instance.app | AA04 | Exploiting Trust in Client | High |
| aws_instance.app | AC01 | Privilege Abuse | Medium |
| aws_instance.app | AC06 | Using Malicious Files | Very High |
| aws_instance.app | AC07 | Exploiting Incorrectly Configured Access Control Security Levels | Medium |
| aws_instance.app | AC08 | Manipulate Registry Information | Medium |
| aws_instance.app | AC09 | Functionality Misuse | Medium |
| aws_instance.app | AC11 | Session Credential Falsification through Manipulation | Medium |
| aws_instance.app | AC16 | Session Credential Falsification through Prediction | High |
| aws_instance.app | AC17 | Session Hijacking - ServerSide | Very High |
| aws_instance.app | CR03 | Dictionary-based Password Attack | High |
| aws_instance.app | CR05 | Encryption Brute Forcing | Low |
| aws_instance.app | DE02 | Double Encoding | Medium |
| aws_instance.app | DO01 | Flooding | Medium |
| aws_instance.app | DO02 | Excessive Allocation | Medium |
| aws_instance.app | DS01 | Excavation | Medium |
| aws_instance.app | DS03 | Footprinting | Very Low |
| aws_instance.app | DS04 | XSS Targeting Error Pages | Medium |
| aws_instance.app | HA01 | Path Traversal | Very High |
| aws_instance.app | HA03 | Web Application Fingerprinting | Low |
| aws_instance.app | INP03 | Server Side Include (SSI) Injection | High |
| aws_instance.app | INP04 | HTTP Request Splitting | High |
| aws_instance.app | INP05 | Command Line Execution through SQL Injection | Very High |
| aws_instance.app | INP08 | Format String Injection | High |
| aws_instance.app | INP09 | LDAP Injection | High |
| aws_instance.app | INP10 | Parameter Injection | Medium |
| aws_instance.app | INP11 | Relative Path Traversal | High |
| aws_instance.app | INP14 | Input Data Manipulation | Medium |
| aws_instance.app | INP16 | PHP Remote File Inclusion | High |
| aws_instance.app | INP17 | XSS Using MIME Type Mismatch | Medium |
| aws_instance.app | INP18 | Fuzzing and observing application log data/errors for application mapping | Low |
| aws_instance.app | INP19 | XML External Entities Blowup | Medium |
| aws_instance.app | INP21 | DTD Injection | Medium |
| aws_instance.app | INP22 | XML Attribute Blowup | High |
| aws_instance.app | INP28 | XSS Targeting URI Placeholders | High |
| aws_instance.app | INP29 | XSS Using Doubled Characters | Medium |
| aws_instance.app | INP34 | SOAP Array Overflow | High |
| aws_instance.app | INP36 | HTTP Response Smuggling | Medium |
| aws_instance.app | INP37 | HTTP Request Smuggling | High |
| aws_instance.app | SC02 | XSS Targeting Non-Script Elements | Very High |
| aws_instance.app | SC03 | Embedding Scripts within Scripts | High |
| aws_instance.app | SC04 | XSS Using Alternate Syntax | High |
| aws_instance.app | SC05 | Removing Important Client Functionality | High |
| aws_lb.web | AA01 | Authentication Abuse/ByPass | Medium |
| aws_lb.web | AA02 | Principal Spoof | Medium |
| aws_lb.web | AA03 | Exploitation of Trusted Credentials | High |
| aws_lb.web | AA04 | Exploiting Trust in Client | High |
| aws_lb.web | AC01 | Privilege Abuse | Medium |
| aws_lb.web | AC06 | Using Malicious Files | Very High |
| aws_lb.web | AC07 | Exploiting Incorrectly Configured Access Control Security Levels | Medium |
| aws_lb.web | AC08 | Manipulate Registry Information | Medium |
| aws_lb.web | AC09 | Functionality Misuse | Medium |
| aws_lb.web | AC11 | Session Credential Falsification through Manipulation | Medium |
| aws_lb.web | AC16 | Session Credential Falsification through Prediction | High |
| aws_lb.web | AC17 | Session Hijacking - ServerSide | Very High |
| aws_lb.web | CR03 | Dictionary-based Password Attack | High |
| aws_lb.web | CR05 | Encryption Brute Forcing | Low |
| aws_lb.web | DE02 | Double Encoding | Medium |
| aws_lb.web | DO01 | Flooding | Medium |
| aws_lb.web | DO02 | Excessive Allocation | Medium |
| aws_lb.web | DS01 | Excavation | Medium |
| aws_lb.web | DS03 | Footprinting | Very Low |
| aws_lb.web | DS04 | XSS Targeting Error Pages | Medium |
| aws_lb.web | HA01 | Path Traversal | Very High |
| aws_lb.web | HA03 | Web Application Fingerprinting | Low |
| aws_lb.web | INP03 | Server Side Include (SSI) Injection | High |
| aws_lb.web | INP05 | Command Line Execution through SQL Injection | Very High |
| aws_lb.web | INP08 | Format String Injection | High |
| aws_lb.web | INP09 | LDAP Injection | High |
| aws_lb.web | INP10 | Parameter Injection | Medium |
| aws_lb.web | INP11 | Relative Path Traversal | High |
| aws_lb.web | INP14 | Input Data Manipulation | Medium |
| aws_lb.web | INP16 | PHP Remote File Inclusion | High |
| aws_lb.web | INP17 | XSS Using MIME Type Mismatch | Medium |
| aws_lb.web | INP18 | Fuzzing and observing application log data/errors for application mapping | Low |
| aws_lb.web | INP19 | XML External Entities Blowup | Medium |
| aws_lb.web | INP21 | DTD Injection | Medium |
| aws_lb.web | INP22 | XML Attribute Blowup | High |
| aws_lb.web | INP28 | XSS Targeting URI Placeholders | High |
| aws_lb.web | INP29 | XSS Using Doubled Characters | Medium |
| aws_lb.web | INP34 | SOAP Array Overflow | High |
| aws_lb.web | INP36 | HTTP Response Smuggling | Medium |
| aws_lb.web | INP37 | HTTP Request Smuggling | High |
| aws_lb.web | SC02 | XSS Targeting Non-Script Elements | Very High |
| aws_lb.web | SC03 | Embedding Scripts within Scripts | High |
| aws_lb.web | SC04 | XSS Using Alternate Syntax | High |
| aws_lb.web | SC05 | Removing Important Client Functionality | High |
| aws_s3_bucket.customer_data | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.customer_data | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.customer_data | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.customer_data | DO02 | Excessive Allocation | Medium |
| aws_s3_bucket.reports | AC01 | Privilege Abuse | Medium |
| aws_s3_bucket.reports | CR05 | Encryption Brute Forcing | Low |
| aws_s3_bucket.reports | DE04 | Audit Log Manipulation | High |
| aws_s3_bucket.reports | DO02 | Excessive Allocation | Medium |
| aws_instance.app → IMDS of aws_instance.app | AC05 | Content Spoofing | Medium |
| aws_instance.app → IMDS of aws_instance.app | CR06 | Communication Channel Manipulation | High |
| aws_instance.app → IMDS of aws_instance.app | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_instance.app → IMDS of aws_instance.app | DE01 | Interception | Medium |
| aws_instance.app → IMDS of aws_instance.app | DE03 | Sniffing Attacks | Medium |
| aws_instance.app → aws_s3_bucket.customer_data | AC05 | Content Spoofing | Medium |
| aws_instance.app → aws_s3_bucket.customer_data | CR06 | Communication Channel Manipulation | High |
| aws_instance.app → aws_s3_bucket.customer_data | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_instance.app → aws_s3_bucket.customer_data | DE01 | Interception | Medium |
| aws_instance.app → aws_s3_bucket.customer_data | DE03 | Sniffing Attacks | Medium |
| aws_instance.app → aws_s3_bucket.reports | AC05 | Content Spoofing | Medium |
| aws_instance.app → aws_s3_bucket.reports | CR06 | Communication Channel Manipulation | High |
| aws_instance.app → aws_s3_bucket.reports | CR08 | Client-Server Protocol Manipulation | Medium |
| aws_instance.app → aws_s3_bucket.reports | DE01 | Interception | Medium |
| aws_instance.app → aws_s3_bucket.reports | DE03 | Sniffing Attacks | Medium |
