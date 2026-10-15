# -*- coding: utf-8 -*-
# Log Viewer by i96751414 / fightnight; GPL-2.0-or-later.
# Adapted journal timestamps/severity patterns; see THIRD_PARTY.md.
import re

from . import core

log_entry_regex = re.compile(r"^(?:(?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2} +\d+)")
log_error_regex = re.compile(r"\b(?:ERROR|ERRO|FATA|failed|failure)\b", re.I)
log_warning_regex = re.compile(r"\b(?:WARNING|WARN)\b", re.I)
log_exception_regex = re.compile(log_error_regex.pattern + "EXCEPTION ")


def with_style(color):
    def wrapper(match):
        return "[COLOR {}]{}[/COLOR]".format(color, match.group(0))

    return wrapper


def set_styles(content):
    content = log_error_regex.sub(with_style("red"), content)
    content = log_warning_regex.sub(with_style("gold"), content)

    return content


def preserve_indentation(line):
    stripped = line.lstrip(" ")
    return (len(line) - len(stripped)) * "\u00a0" + stripped


def parse_errors(content, exceptions_only=False):
    pattern = log_exception_regex if exceptions_only else log_error_regex
    found_error = False

    for line in content.splitlines():
        if log_entry_regex.match(line):
            if pattern.search(line):
                found_error = True
                yield line
            else:
                found_error = False
        elif found_error:
            yield line


def process_content_lines(lines, set_style=False):
    content = "\n".join(preserve_indentation(line) for line in lines)

    if set_style:
        content = set_styles(content)

    return content


def get_errors(content, set_style=False, exceptions_only=False):
    if not content:
        return ""

    return process_content_lines(parse_errors(content, exceptions_only=exceptions_only), set_style=set_style)


def escape_markup(content):
    """Keep ASCII brackets; prevent log text from supplying Kodi formatting.

    Kodi 21 GUITextLayout::ParseText requires a tag immediately after '['.
    Inserting an ASCII space only before recognized tags makes them literal;
    ordinary brackets (including [service.harpywing]) stay unchanged.
    Our own severity color tags are added after this escaping step.
    """
    return re.sub(r"\[(?=/?(?:B\]|I\]|UPPERCASE\]|LOWERCASE\]|CAPITALIZE\]|LIGHT\]|TABS\]|CR\]|COLOR))",
                  "[ ", content)


def journal_contents(system, kodi_newest_first):
    """Display reverse lines like Log Viewer; keep the saved log chronological."""
    kodi = list(kodi_newest_first)
    separator = "\n\n--- Kodi / Harpy Wing ---\n"
    raw = core.redact(system + separator + "\n".join(reversed(kodi)))
    recent = core.redact("\n".join(reversed(system.splitlines())) + separator + "\n".join(kodi))
    content = process_content_lines(escape_markup(recent).splitlines(), set_style=True)
    return raw, content
