#!/usr/bin/env python3
# Copyright (c) 2025 seranov. MIT; see repository.harpywing/LICENSE.
# Adapted for a configurable base URL, complete packages and atomic index update.
# Upstream commit and copied files: THIRD_PARTY.md.
"""Generate a local Kodi repository. No publication or network access.

Usage: python3 scripts/generate_repo.py --base-url https://example.net/repo
"""

import argparse
import ipaddress
import tempfile
from urllib.parse import urlsplit
import copy
import os
import re
import sys
import shutil
import hashlib
import html
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


# Check Python version
if sys.version_info < (3, 9):
    print("Error: This script requires Python 3.9 or higher")
    print(f"Current version: {sys.version}")
    sys.exit(1)


def get_addon_dirs(base_path=None):
    """Get all addon directories (starting with 'plugin.', 'service.', 'context.', or 'repository.')"""
    base_path = Path(base_path or Path(__file__).parent.parent)
    addon_dirs = []

    for item in base_path.iterdir():
        if item.is_symlink() and item.is_dir():
            # A linked add-on directory could publish files from elsewhere.
            raise ValueError(f"refusing symbolic link: {item}")
        if item.is_dir() and (
            item.name.startswith('plugin.') or
            item.name.startswith('service.') or
            item.name.startswith('context.') or
            item.name.startswith('repository.')
        ):
            addon_xml = item / 'addon.xml'
            if addon_xml.exists():
                addon_dirs.append(item)

    return sorted(addon_dirs)


def validate_addon(addon_id, version, directory=None):
    if not addon_id or not re.fullmatch(r'[a-z0-9][a-z0-9._-]*', addon_id):
        raise ValueError('Invalid Kodi addon id')
    if directory is not None and addon_id != Path(directory).name:
        raise ValueError('Addon id must match its directory name')
    if not version or any(part in version for part in ('/', '\\', '..')):
        raise ValueError('Invalid addon version')


def staging_path(staging, *parts):
    """Validate resolved destinations, including existing symlink components."""
    staging = Path(staging).resolve()
    destination = staging.joinpath(*parts).resolve()
    if destination == staging or not destination.is_relative_to(staging):
        raise ValueError('Destination must stay inside staging')
    return destination


def get_addon_info(addon_dir):
    """Extract addon id and version from addon.xml"""
    addon_xml = addon_dir / 'addon.xml'
    tree = ET.parse(addon_xml)
    root = tree.getroot()

    addon_id = root.get('id')
    version = root.get('version')
    validate_addon(addon_id, version, addon_dir)

    return addon_id, version, tree


def create_zip(addon_dir, addon_id, version, output_dir, manifest=None):
    """Create a zip file for the addon"""
    validate_addon(addon_id, version, addon_dir)
    zip_filename = f"{addon_id}-{version}.zip"
    final_path = staging_path(output_dir, zip_filename)
    zip_path = staging_path(output_dir, zip_filename + ".part")

    print(f"Creating {zip_filename}...")

    # Remove old zip if exists
    if zip_path.exists():
        zip_path.unlink()

    # Create zip file
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(addon_dir):
            # A link could pull a private file of the build machine into the zip.
            for entry in dirs + files:
                if (Path(root) / entry).is_symlink():
                    raise ValueError(f"refusing symbolic link: {Path(root) / entry}")
            # Skip hidden files and directories, and __pycache__
            files = [f for f in files if not f.startswith('.')]
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']

            for file in files:
                file_path = Path(root) / file
                arcname = Path(addon_id) / file_path.relative_to(addon_dir)
                if file == 'addon.xml' and file_path.parent == addon_dir and manifest is not None:
                    zipf.writestr(str(arcname), ET.tostring(manifest, encoding='utf-8', xml_declaration=True))
                else:
                    zipf.write(file_path, arcname)

    os.replace(zip_path, final_path)
    print(f"Created {zip_filename}")
    return zip_filename


def indent_xml(elem, level=0):
    """Add pretty-printing indentation to XML"""
    indent = "\n" + "    " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "    "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        for child in elem:
            indent_xml(child, level + 1)
        # Update tail for last child
        if len(elem) > 0:
            last_child = elem[-1]
            if not last_child.tail or not last_child.tail.strip():
                last_child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent


def generate_addons_xml(addon_dirs, output_dir, manifests=None):
    """Generate addons.xml file"""
    print("Generating addons.xml...")

    root = ET.Element('addons')

    for addon_dir in addon_dirs:
        addon_id, version, tree = get_addon_info(addon_dir)
        addon_element = tree.getroot()
        root.append(copy.deepcopy(manifests[addon_id] if manifests else addon_element))

    # Create tree and write to file
    tree = ET.ElementTree(root)
    indent_xml(root)

    addons_xml_path = staging_path(output_dir, 'addons.xml')
    temp = staging_path(output_dir, "addons.xml.part")
    tree.write(temp, encoding='utf-8', xml_declaration=True)

    os.replace(temp, addons_xml_path)
    print(f"Generated addons.xml")
    return addons_xml_path


def generate_md5(file_path):
    """Generate MD5 hash for a file"""
    print(f"Generating MD5 for {file_path.name}...")

    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        md5_hash.update(f.read())

    md5_file = staging_path(file_path.parent, f"{file_path.name}.md5")
    with open(md5_file, 'w') as f:
        f.write(md5_hash.hexdigest())

    print(f"Generated {md5_file.name}")


def configure_manifest(root, base_url):
    manifest = copy.deepcopy(root)
    for element in manifest.iter():
        if element.text:
            element.text = element.text.replace('@BASE_URL@', base_url.rstrip('/'))
    return manifest


def write_indexes(output_dir):
    """Static hosts (GitHub Pages) list no directory: Kodi's file browser
    needs an HTML page of links to reach the repository zip."""
    for directory in [output_dir] + sorted(p for p in output_dir.iterdir() if p.is_dir()):
        entries = sorted(p for p in directory.iterdir() if not p.name.startswith('.') and p.name != 'index.html')
        links = ''.join('<li><a href="{0}">{0}</a></li>\n'.format(
            html.escape(p.name + ('/' if p.is_dir() else ''), quote=True)) for p in entries)
        (directory / 'index.html').write_text(
            '<!doctype html>\n<meta charset="utf-8">\n<title>Harpy Branch</title>\n<ul>\n' + links + '</ul>\n',
            encoding='utf-8')


def validate_repo(output_dir):
    """Every index entry must resolve to a zip with matching addon.xml."""
    root = ET.parse(output_dir / 'addons.xml').getroot()
    for addon in root:
        addon_id, version = addon.get('id'), addon.get('version')
        validate_addon(addon_id, version)
        archive_path = staging_path(output_dir, addon_id, f'{addon_id}-{version}.zip')
        with zipfile.ZipFile(archive_path) as archive:
            manifest = ET.fromstring(archive.read(addon_id + '/addon.xml'))
            if ET.tostring(manifest) != ET.tostring(addon).rstrip():
                # Whitespace indentation differs after index formatting.
                for tree in (manifest, addon):
                    for element in tree.iter():
                        if element.text and not element.text.strip():
                            element.text = None
                        element.tail = None
                if ET.tostring(manifest) != ET.tostring(addon):
                    raise ValueError('Index / zip manifest mismatch: ' + addon_id)
            if addon_id == 'service.harpywing':
                for filename in ('bin/netbird-arm64', 'bin/netbird-amd64',
                                 'bin/netbird', 'bin/harpywing-daemon', 'bin/harpywing-hosts',
                                 'LICENSES/NETBIRD-LICENSE', 'THIRD_PARTY.md'):
                    if addon_id + '/' + filename not in archive.namelist():
                        raise ValueError('Incomplete universal addon: ' + filename)
    actual = hashlib.md5((output_dir / 'addons.xml').read_bytes()).hexdigest()
    if (output_dir / 'addons.xml.md5').read_text().strip() != actual:
        raise ValueError('Index checksum mismatch')


def validate_base_url(base_url, allow_http=False):
    url = urlsplit(base_url)
    if (url.scheme not in ('https', 'http') or not url.hostname or url.query or url.fragment
            or url.username is not None or url.password is not None
            or (url.port is not None and not 1 <= url.port <= 65535)):
        raise ValueError('A base HTTPS URL without credentials is required')
    if url.scheme == 'http':
        local = url.hostname.lower() == 'localhost'
        try:
            address = ipaddress.ip_address(url.hostname)
            # RFC1918 and IPv6 unique-local, not Python's broader is_private.
            local = address.is_loopback or any(address in network for network in (
                ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('fc00::/7')))
        except ValueError:
            pass  # Never resolve a hostname: no DNS rebinding or network access.
        if not allow_http or not local:
            raise ValueError('HTTP requires --allow-http and a loopback or private LAN address')


def generate(base_path, output_dir, base_url, allow_http=False):
    validate_base_url(base_url, allow_http)
    base_path, output_dir = Path(base_path).resolve(), Path(output_dir).resolve()
    if not output_dir.is_relative_to(base_path) or output_dir == base_path:
        raise ValueError('Output directory must be inside the worktree')
    for name in ('.git', 'scripts', 'tests', 'service.harpywing', 'repository.harpywing'):
        if output_dir.is_relative_to(base_path / name):
            raise ValueError('Output cannot be inside protected source directories')
    marker = '.harpywing-repo'
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError('Output must be a directory')
        if any(output_dir.iterdir()) and not (output_dir / marker).is_file():
            raise ValueError('Refusing to replace non-generated, non-empty output')
    addon_dirs = get_addon_dirs(base_path)
    if any(output_dir.is_relative_to(directory) or directory.is_relative_to(output_dir)
           for directory in addon_dirs):
        raise ValueError('Output cannot overlap addon sources')
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.harpywing-repo-', dir=output_dir.parent) as folder:
        staging = Path(folder) / 'new'
        staging.mkdir()
        manifests = {}
        for directory in addon_dirs:
            addon_id, version, tree = get_addon_info(directory)
            manifest = configure_manifest(tree.getroot(), base_url)
            manifests[addon_id] = manifest
            destination = staging_path(staging, addon_id)
            destination.mkdir(exist_ok=True)
            if addon_id == 'service.harpywing':
                package = base_path / 'dist' / f'{addon_id}-{version}.zip'
                if not package.is_file():
                    raise ValueError('Run bash build.sh before generating the repository')
                with zipfile.ZipFile(package) as archive:
                    packaged = ET.fromstring(archive.read(addon_id + '/addon.xml'))
                    if packaged.get('version') != version:
                        raise ValueError('Stale service package')
                shutil.copyfile(package, staging_path(staging, addon_id, package.name))
            else:
                create_zip(directory, addon_id, version, destination, manifest)
            for filename in ('icon.png', 'fanart.jpg'):
                if (directory / filename).is_symlink():
                    raise ValueError(f"refusing symbolic link: {directory / filename}")
                if (directory / filename).is_file():
                    shutil.copy(directory / filename, staging_path(staging, addon_id, filename))
        # Check all referenced zips before replacing the visible index.
        for addon_id, manifest in manifests.items():
            package = staging_path(staging, addon_id, f"{addon_id}-{manifest.get('version')}.zip")
            if not package.is_file():
                raise ValueError('Missing package: ' + str(package))
        index = generate_addons_xml(addon_dirs, staging, manifests)
        generate_md5(index)
        validate_repo(staging)
        write_indexes(staging)
        staging_path(staging, marker).write_text('Generated by scripts/generate_repo.py\n', encoding='utf-8')
        # Publish only a complete, validated directory. Retain the old one
        # until replacement succeeds, and restore it on a rename failure.
        previous = Path(folder) / 'previous'
        if output_dir.exists():
            os.replace(output_dir, previous)
        try:
            os.replace(staging, output_dir)
        except BaseException:
            if previous.exists():
                os.replace(previous, output_dir)
            raise
    return output_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--output', default='repo')
    parser.add_argument('--allow-http', action='store_true', help='Allow HTTP on loopback/private LAN only')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent.parent
    generate(base, base / args.output, args.base_url, allow_http=args.allow_http)


if __name__ == '__main__':
    main()
