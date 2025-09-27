# Changelog
All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/).

--- 

## [1.3.0] - 2025-09-27
### Added
- Persistence layer with **SQLite** to store processed logs, blocked IPs, and alerts.
- New file: `src/database.py` to manage all database operations.
- New file: `report.py` to generate security statistics directly from the database.

### Changed
- Replaced `blocked_ips.txt` and `alert_ips.txt` with the `log_analyzer.db` database.
- The application now reads the initial state of blocked IPs from the database, ensuring persistence between executions.

---

## [1.2.0] - 2025-09-15
### Added
 - Support for real-time log monitoring
 - New file: realtime.py

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