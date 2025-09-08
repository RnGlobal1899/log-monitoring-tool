# Changelog
All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.1.0] - 2025-09-08
### Added
- Support for parsing **Apache** logs
- Support for parsing **Nginx** logs
- Support for parsing **SSH** logs

---

## [1.0.0] - 2025-08-22
### Added
- Initial version with basic log parser
- Regex to extract structured data
- Login failure detection
- Generation of `alert_ips.txt`
- Generation of `blocked_ips.txt`
- Integration with **ipinfo** API + **pycountry**
- Country name normalization
- IP cache to reduce API calls
