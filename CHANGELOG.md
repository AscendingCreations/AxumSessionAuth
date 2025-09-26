# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
## Unreleased

## 0.17.0 (26. September, 2025)
### Changed
- (Breaking)  axum_session 0.17"

## 0.16.0 (17. Janurary, 2025)
### Changed
- (Breaking)  axum_session 0.16"

## 0.15.0 (1. Janurary, 2025)
### Changed
- (Breaking)  Axum 0.8.1 and axum_session 0.15"

## 0.14.1 (6. September, 2024)
### Changed
- cache hit/miss traces from warn level to debug level @jhoobergs

## 0.14.0 (12. April, 2024)
### Changed
- (Breaking) Updated to Axum Session 0.14.0

## 0.13.0 (11. March, 2024)
### Changed
- (Breaking) Updated to Axum Session 0.13.0

## 0.12.1 (14. February, 2024)
### Fixed
- Multiple Cache Existing due to Service fn getting called per async thread. In older versions please Disable cache unless you upgrade to this version.

## 0.12.0 (1. January, 2024)
### Changed
- (Breaking) Updated to Axum_session 0.12.0
- added tracing for debugging.
- Fixed the return to not be an unwrap if session doesnt exist.

## 0.11.0 (21. December, 2023)
### Changed
- (Breaking) Updated to Axum_session 0.11.0 for Redis_pool 0.3

## 0.10.1 (12. December, 2023)
### Fixed
- Documents not building.

## 0.10.0 (27. November, 2023)
### Changed
- (Breaking) Updated to axum_session 0.10.0
- (Breaking) Updated to axum 0.7
- (Breaking) merged all surreal features under a single surreal feature

## 0.9.0 (13. November, 2023)
### Changed
- Updated axum_session to 0.9.0.
- Made AuthStatus Publically visiable

### Added
- sync_user_id function to Session.
- StaleUser to AuthStatus Enum.

### Fixed
- Config session_id is no longer ignored for login and logout.

## 0.8.0 (23. October, 2023)
### Changed
- Updated axum_session to 0.8.0.

### Added
- Added `AuthStatus`, `AuthSession::is_logged_in()`, `AuthSession::reload_user` and `AuthSession::update_user_expiration`.
- Features locked behind an advanced feature.

## 0.7.0 (4. October, 2023)
### Changed
- Updated axum_session to 0.7.0.
- Removed uneeded clone.

## 0.6.0 (18. September, 2023)
### Changed
- Updated axum_session to 0.6.0.

## 0.5.0 (6. September, 2023)
### Changed
- Updated axum_session to 0.5.0.

## 0.4.0 (3. September, 2023)
### Changed
- Updated axum_session to 0.4.0.

## 0.3.1 (7. August, 2023)
### Changed
- Updated github link to renamed repo.

## 0.3.0 (7. July, 2023)
### Changed
- Updated to axum_session 0.3.0.

## 0.2.1 (5. May, 2023)
### Fixed
- RUSTSEC-2020-0071 from chrono. (damccull)

## 0.2.0 (11. April, 2023)
### Changed
- Updated to axum_session 0.2.0.

## 0.1.1 (31. March, 2023)
### Added
- Added Surrealdb features.

## 0.1.0 (13. March, 2023)
### Added
- Initial rename and release.
