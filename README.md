# nist-feed
A python script to get CVE's from nist based on CPE or keywords to find.


For CPE search:
python3 nist-feed.py --cpe cpe:/a:apache:tomcat:2.3.4

For keyword search:
python3 nist-feed.py --keyword IIS\ 6.0

For top 3 CVSS add --repo.
