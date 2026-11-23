# Partner guide to the RAS Log Analyser

Use the analyser to investigate an incident in saved Parallels RAS logs. You can open a farm support bundle to find the right server and file, or compare several individual text logs in one analysis.

The RAS Log Analyser is a Sales Engineering project. It is not an official Parallels product and is not supported by Parallels. Please direct questions to your Sales Engineer, whose familiarity with the project may vary. Use the tool with caution and at your own risk. Independently verify findings before acting on them.

## Open the analyser

Open the HTTPS address supplied by your Sales Engineer or deployment owner. If your organisation restricts access to its network, connect to the approved network or VPN. Select **Continue to analyser** on the session notice. The upload screen appears immediately.

The selected logs are sent to the server hosting that address for processing. Use an instance approved for the customer data involved. Each tab has its own analysis view. The issue library and parsing settings are shared across users of the same instance. Keep the tab open during your investigation. Refreshing it clears your current view.

Use **Theme** in the header to choose **Dark**, **Light** or **Parallels**. The browser remembers your choice on this site when local storage is available. **Partner guide** opens this guide in another tab so you can keep your results on screen.

## Clearing temporary data

The expiry time above the upload controls uses your local clock. **Clear investigation** removes this tab’s server-side index and temporary bundle files, then clears its selected files, filters and results. Starting a different upload replaces the current investigation. Closing the tab leaves server cleanup to the expiry timer. The shared issue library keeps the resolutions and sample messages you explicitly saved. Individual uploads use a temporary SQLite index on the server; it can contain the original message text and parsed fields until cleanup.

## Usage stats

Select **Stats** in the header for installation-wide totals. **Browser sessions** counts visits per tab session; **Sessions with uploads** counts tab sessions that successfully uploaded at least one file or bundle. One person can use multiple tabs. Storage restrictions can prevent a visit from being counted. Opening the Stats page itself does not count as an analyser visit.

Uploaded MB measures accepted individual files and compressed bundles. Processed MB measures successfully indexed decoded log text. A bundle can therefore contribute more processed MB than uploaded MB. Each newly indexed log counts once; filtering or reopening its existing index does not increment the totals. Only numeric counters and their fixed metric names are stored in the usage database. Totals start when the update is deployed. Use **Refresh stats** for the latest values.

## Upload limits

| Input | Limit per upload |
| --- | --- |
| Individual logs | Up to **10 files** totalling **1 GiB combined**. The selected files and their decoded UTF-8 text must each fit within that combined size. |
| Support bundle (ZIP or TAR.GZ) | **1 GiB compressed** for the uploaded archive. Each file extracted from it can be up to **1 GiB**. ZIP members named `perf.dat` are skipped before extraction. |
| Nested bundle inspection | **8 GiB cumulative** across the uploaded archive and the contents written during inspection, including nested archives. Up to **20,000 inspected entries** and **8 levels** of nesting. |
| Text analysis | Up to **5 million processed lines** per analysis and **1 MiB** per line. |

A 90 MB compressed bundle can exceed an inspection limit if it contains a large expanded entry. If the error names a file, select a smaller server archive or split that text log at line boundaries.

## Try a three-line investigation

To learn the controls without customer data, save these synthetic lines as a plain-text file named `example.log`:

```text
[W01] 13-11-26 09:10:00 - Test gateway timed out
[I01] 13-11-26 09:10:03 - Retrying the test connection
[W01] 13-11-26 09:10:07 - Test gateway timed out
```

1. Under **Uploaded log analysis**, choose the file in **Log files** and select **Analyze files**. Leave **Log date** on **All logs**.
2. The totals should show three lines, two warnings and one information entry. The default **Errors and warnings** view shows the two warnings.
3. Under **Most frequent issues**, select **Test gateway timed out**. Its count is two. The analyser selects the latest occurrence, line 3.
4. On that warning, select **View in full log**. The surrounding lines reveal the retry on line 2. This is the context to record alongside the warning when investigating a real incident.

## Work with individual logs

Choose up to ten text logs under **Log files**. Leave **File encoding** on **Detect automatically** first. If the output contains garbled characters or unexpected spacing, choose the encoding used by the source, such as UTF-16 little endian or Windows-1252, then select **Analyze files** again.

Selecting several files lets you compare recurring messages across them. Use **Log file** to focus on one file. If filenames repeat, the selector includes a file number. Rows retain their original filename and line number.

## Work with a farm support bundle

1. Under **RAS farm support bundle**, choose the original ZIP or TAR.GZ and select **Open support bundle**. Wait for the server and log inventory.
2. The **Bundle overview** automatically counts events, successful and failed logins, errors, and distinct users and hosts across all readable logs and dates. Uploads show bytes transferred as a percentage. After extraction you can open any log while the overview continues in the background. The progress bar counts completed logs; large files can take longer than small ones. Login totals use controller logs, while entries and errors span all analysed logs. The status shows how many logs contributed and flags partial totals. **Top 5 logs by error count** ranks logs with errors across the farm. Select a ranked entry to open its server and log with errors filtered in. The archive path distinguishes repeated filenames. Opening an individual log shows a separate selected-range summary. Use **Server** to narrow the inventory. Read the archive path to distinguish files with the same name. Nested server debug ZIPs are inspected automatically. Farm-level files can appear in their own group.
3. Select **Analyse log** beside the file you want. The results below apply to that selected log. Check the source server and archive path before interpreting the counts.
4. To investigate another server, select its log from the inventory. When finished, select **Clear investigation** to remove the temporary server copy. The displayed expiry is one hour from investigation creation. The server checks for expired files every 15 seconds, including while idle. An in-flight operation finishes before its files are removed. Closing the tab alone does not immediately clear the copy.

Text files ending in `.log`, `.txt` or `.out` can appear in the bundle inventory. Binary files such as Windows event logs (`.evtx`) are skipped.

## Read and narrow the results

| Control or result | How to use it |
| --- | --- |
| Severity totals | RAS lines starting with `[E`, `[W` and `[I` are classified as error, warning and information respectively. Other lines use the configured parser. Totals cover the selected date range across the input files. The table can show fewer rows after filtering. |
| **Log date** | Choose **Today**, **Last 24 hours**, **Last 7 days** or **All logs**. Windows are calculated using your computer's local clock and compared with timestamps as written in the logs. For older incidents or servers in another time zone, start with **All logs**. Entries without a readable timestamp are excluded by date filters. |
| **Search results** | Enter part of a message, filename, user or host. Matching ignores case. A distinctive phrase usually works better than a whole line containing a timestamp or changing ID. |
| **Show** | Choose errors, warnings, information or **All log entries**. Use the last option to see nearby context, including continuation lines. |
| **Previous / Next** | Browse matching entries in original file order, 500 per page. Check the matching-entry count above the table. |
| **Most frequent issues** | Shows up to 25 error/warning groups ranked by count. Grouping removes the usual RAS prefix and timestamp. Different IDs in the message body can produce separate groups. A frequent message indicates repetition; investigate its surrounding events to determine significance. |
| **Latest occurrence** | Click a group to jump to its latest matching message. Readable timestamps take precedence. If none are available, the later scanned occurrence is used. **View in full log** opens the relevant file and page, clears search/date restrictions and highlights the line. |

## Use message actions and shared resolutions

**Copy message** copies the selected log text to your clipboard. When handing off a finding, also note the source server, file, timestamp and line number. Review the message for customer identifiers before sharing it.

**Search Google AI** opens Google and sends a query containing the selected message text (up to 1,500 characters). Use this only when you have permission to send that content to an external service.

**Save as known issue** opens an editable library entry based on the message. Choose a clear title, a stable **Matching phrase** and the appropriate **Match severity**. For example, use `Test gateway timed out` as the phrase instead of copying the timestamp. Add verified resolution notes and full HTTP or HTTPS KB URLs, one per line. Review the example message for sensitive data, then select **Save issue**. Saved entries persist and are visible to other users of this instance.

When a message contains a saved phrase and the severity matches, select **Resolution: …** beside the row to read the notes. Open **Issue library** to search, create or edit entries. Treat each resolution as a lead to verify against the affected environment.

**Restore defaults** loads the shipped error phrases and user/host rules into the parser editor. Review or edit them, then choose **Save and apply**. Cancel discards the draft. Already indexed files retain their original classifications. Upload or open a new investigation to use the new settings.

**Parsing settings** changes how subsequent analyses recognise error phrases and extract users or hosts. These settings apply to the whole instance. Coordinate changes with its owner. For a single investigation, use the result filters.

## Troubleshooting

| Symptom | What to try |
| --- | --- |
| No rows, or a known message is missing | Set **Log date** to **All logs**, **Log file** to **All files**, **Show** to **All log entries**, and clear the search. For a bundle, confirm you selected **Analyse log** for the intended file. |
| A small compressed bundle fails inspection | Check the exact error. A 90 MB upload can contain a single entry larger than **1 GiB** once expanded. There is also a **20,000-entry** inspection limit across nested archives, a **8 GiB** cumulative inspection budget and a nesting limit. Try the relevant server's debug ZIP on its own. If one text log is too large, split a copy at line boundaries and retain the original for line references. |
| Individual uploads exceed a limit | Use at most **10 files** per run. The browser checks combined file size and the server checks decoded text against **1 GiB**. Analysis also limits processed lines to **5 million**, with a **1 MiB** line limit. Narrow the input to the incident period and retry. |
| The bundle expired or three bundles are already open | Reopen an expired bundle. For a busy instance, clear your finished bundle or try again after another session clears or expires. Three bundle slots are shared across users. |
| Analysis is slow or reports a failure | The first analysis builds a temporary index. Filters and pages query the index. A broad text search can still take time. Wait for completion and read the status message. A failed analysis can leave the previous results on screen. Recheck the source before using them. |

For help, give your Sales Engineer the exact error text, the upload type and approximate size, the filters used, and the last step that worked. A short, redacted example is usually enough to begin investigating.
