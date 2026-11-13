# Feature changelog

## v1.2.1

- The bundle inventory subtly highlights controller, vdiagent, gateway and tsagent filenames in all three themes.

## v1.2.0 — 13 November 2026

- Individual uploads are parsed once into a temporary SQLite index. Search, file/date/severity filters, pagination and full-log navigation query that index. Opening a bundle log builds its index on demand; selecting the same log again reuses it.
- Each investigation shows its one-hour expiry in the browser's local time. **Clear investigation** removes that investigation's index and extracted files. Expired investigations are swept every 15 seconds while the service is running. Active reads finish before deletion.
- **Parsing settings → Restore defaults** loads the release's shipped error phrases and activity rules into the editor. Select **Save and apply** to use them for newly indexed files.
- Temporary indexes use the server's temporary disk. Allow headroom above the upload size for parsed rows, search indexes and SQLite working space. The service supports up to 16 active investigations, including up to three open bundles.

## Earlier 1.1 releases

- Docker deployment with a persistent shared issue library, settings and backups.
- Azure HTTPS setup, partner guide, session disclaimer, theme selection and numeric release display.
- Support for 1 GiB uploads and nested RAS archives, with oversized ZIP performance captures skipped during inspection.
