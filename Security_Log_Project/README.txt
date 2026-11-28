COMP H2702 – Scripting for Security
Project Dataset (Student Version)

Scenario: Security Log Investigation. Analyze supplied firewall and authentication logs and identify meaningful security patterns.

What this contains
Security_Log_Project
|_ Logs
   |_ authentication.log (EXAMPLE LOG)
   |_ firewall.log (EXAMPLE LOG)
|_ Main
   |_ Log_Scanner.py
|_ Summaries
   |_ Authentication_Summary.csv
   |_ Firewall_Summary.csv
|_ README.md

Needed libraries to run:
1. pathlib
2. datetime
3. re
4. csv

How to run/use:
1. Install the above libraries
2. Place security logs in /Logs (Optionally rename you firewall and authentication logs to the example logs)
3. Run Log_Scanner.py in /Main
4. Select "1" to summarize the authentication log
5. Select "2" to summarize the firewall log
6. Select "3" to quit the program