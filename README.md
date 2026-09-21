# LogRead

Read the logs on this computer without knowing where they live or what format
they are in.

LogRead is a GTK4 / libadwaita application for the GNOME desktop. It scans the
places Linux programs write logs, groups what it finds by the application or
service the log belongs to, and then reads each log three ways: a summary of
what went wrong and when, a list of the individual problems, and the raw text.

It is built for Fedora Workstation first, and works on Debian, Ubuntu, Arch,
openSUSE and anything else with a reasonably standard filesystem layout.

## What it does

**Finds the logs for you.** There is no path to type. LogRead scans
`/var/log`, `/run/log`, `~/.local/state`, `~/.cache`, `~/.config`, the Flatpak
per-application directories under `~/.var/app`, Snap's `~/snap`, and the
systemd journal. Files are grouped into the application or service that owns
them — `/var/log/cups/*` becomes "Printing", `/var/log/dnf*.log` becomes
"Software Updates (DNF)", `~/.var/app/org.gnome.Fractal/…` becomes Fractal,
with the app's own name and icon.

**Explains a log before you read it.** The Overview counts the errors and
warnings, charts them over time so a burst is visible at a glance, and lists
the problems that recur most — with repeats collapsed into one row and a
count, so 4,000 identical failures read as one problem rather than 4,000
lines.

**Puts every problem one click from the clipboard.** The Highlights view shows
each error and warning as its own card with a copy button, an occurrence
count, and an expander for stack traces. "Copy all" takes the lot.

**Shows the log as it really is.** The Full log view is the file verbatim,
coloured by severity, searchable, with match counts and next/previous.

**Handles the formats you will actually meet.** syslog (RFC 3164 and RFC 5424),
the systemd journal, JSON lines (including the Python, bunyan and pino level
scales), logfmt, nginx, Apache, web access logs, Xorg, the kernel ring buffer,
DNF, dpkg/APT, pacman, Python `logging`, Java stack traces — and plain text,
where severity is inferred from the message and labelled as inferred so you
know. Multi-line entries such as tracebacks stay attached to the error that
produced them.

**Copes with awkward files.** Rotated archives, gzip/bzip2/xz/zstd
compression, unknown encodings, files larger than memory (read from the end),
binary records such as `wtmp` (named as such rather than shown as noise), and
files that have been rotated away mid-read. Nothing raises; every failure
becomes a page that says what happened and what to do next.

**Asks for administrator access, graphically, only when you say so.** Most of
`/var/log` is root-only on a stock system. LogRead marks those logs, shows a
banner offering to unlock them, and — when you click it — uses polkit so your
desktop shows its own authentication dialog. It only ever reads, only ever
through a fixed list of system tools, and only ever inside log directories.

## Screenshots

The Overview of an nginx error log: counts, the activity strip, and the
problems that repeat most.

## Installing

### From a package

Every commit to `main` builds a wheel, an sdist, a `.deb` and an `.rpm`; they
are attached to the workflow run, and to the release for tagged versions.

```
sudo dnf install ./logread-1.0.0-1.noarch.rpm      # Fedora, RHEL
sudo apt install ./logread_1.0.0_all.deb           # Debian, Ubuntu
```

### From source

LogRead needs GTK 4.6 or newer, libadwaita 1.4 or newer, and PyGObject. These
come from your distribution, not from pip:

```
# Fedora
sudo dnf install python3-gobject gtk4 libadwaita

# Debian, Ubuntu
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libadwaita-1-0

# Arch
sudo pacman -S python-gobject gtk4 libadwaita
```

Then run it straight from the checkout:

```
./logread
```

Or install it:

```
meson setup _build --prefix=/usr/local && sudo meson install -C _build
```

## Reading system logs without being asked each time

Adding yourself to the `systemd-journal` group lets journalctl show you the
system journal without a password prompt:

```
sudo usermod -aG systemd-journal "$USER"
```

Log back in for it to take effect. LogRead will tell you this itself when it
finds the journal locked.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| <kbd>Ctrl</kbd>+<kbd>1/2/3</kbd> | Overview, Highlights, Full log |
| <kbd>Ctrl</kbd>+<kbd>K</kbd> | Find an application |
| <kbd>Ctrl</kbd>+<kbd>F</kbd> | Search this log |
| <kbd>Ctrl</kbd>+<kbd>G</kbd> | Next match (<kbd>Shift</kbd> for previous) |
| <kbd>Ctrl</kbd>+<kbd>R</kbd> | Read this log again |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>R</kbd> | Look for logs again |
| <kbd>Ctrl</kbd>+<kbd>U</kbd> | Read with administrator access |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> | Copy all highlights |
| <kbd>Ctrl</kbd>+<kbd>S</kbd> | Save a copy |

## How it is put together

```
src/logread/
├── app.py            the Adw.Application, styles and about
├── config.py         preferences, stored as JSON under XDG config
├── core/             no GTK in here, so it is all testable headlessly
│   ├── discovery.py    scanning and grouping into applications
│   ├── catalog.py      names, icons and categories for known logs
│   ├── reader.py       compression, encodings, tailing, read failures
│   ├── parsers.py      the format rules and continuation folding
│   ├── journal.py      journalctl as a log source
│   ├── analysis.py     summaries, the activity strip, problem grouping
│   ├── privileged.py   the polkit path, and the limits on it
│   └── document.py     one loaded log, ready to display
└── ui/               GTK4 and libadwaita widgets
```

The core has no GTK dependency at all, which is why the parsers and the
scanner have as many tests as they do:

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Why it does not ship as a Flatpak

A Flatpak would be sandboxed away from `/var/log` and the journal, which is
the whole job. Running as a native package is what makes it useful.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
