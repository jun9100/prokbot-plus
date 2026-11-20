"""Preserve the shipped extensions and isolate their storage and app links."""
import hashlib
import plistlib
import re
import struct

EXTENSIONS = {
    'Widgets.appex': ('widgets', 'bb9293d61347ec69fc68b51319ee161e382ab985694296a4ffb21c566561cabd'),
    'ImageShareExtension.appex': ('share', '4fa14f55ba2300059a9bf7caf9b6ddc8cf30daa2713e0c4e4a4a10ed73eacbc6'),
    'NotificationService.appex': ('NotificationService', '72ccc1ee5c3e80bdcc45a551306ae0a8dc8355b0368fdeadc74022cf0098cbfd'),
}

# The widget embeds its deep-link scheme as four back-to-back MOV-wide
# immediates spelling "grokbot\0". Locate that exact sequence instead of
# hard-coding an address that moves between releases.
WIDGETS_SCHEME_IMMEDIATES = (0x7267, 0x6B6F, 0x6F62, 0x0074)
WIDGETS_SCHEME_PARTS = (0x6267, 0x6F6C, 0x6163, 0x006C)


def scheme_sites(data, start, length):
    found = []
    for index in range(start, start + length - 16, 4):
        values = struct.unpack_from('<4I', data, index)
        if tuple((value >> 5) & 0xFFFF for value in values) == WIDGETS_SCHEME_IMMEDIATES:
            found.append(index)
    return found


def identifier(value):
    if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', value):
        raise ValueError('Invalid bundle or App Group identifier')
    return value


def text_section(data, commands):
    for command, offset, size in commands(data):
        if command in (0x21, 0x2c) and struct.unpack_from('<I', data, offset + 16)[0]:
            raise ValueError('Extensions must also be decrypted; use --remove-extensions only to explicitly omit them')
        if command == 0x19:
            for index in range(struct.unpack_from('<I', data, offset + 64)[0]):
                section = offset + 72 + 80 * index
                if data[section:section + 16].rstrip(b'\0') == b'__text':
                    length = struct.unpack_from('<Q', data, section + 40)[0]
                    start = struct.unpack_from('<I', data, section + 48)[0]
                    result = (start, length)
    if 'result' not in locals():
        raise ValueError('Extension has no text section')
    return result


def prepare_extensions(app, bundle_id, group, commands):
    plugins = app / 'PlugIns'
    if not plugins.exists():
        raise ValueError('Missing original extensions; provide the complete IPA or explicitly use --remove-extensions')
    if {p.name for p in plugins.iterdir()} != set(EXTENSIONS):
        raise ValueError('Expected all three original extensions')
    records = []
    for name, (suffix, expected) in EXTENSIONS.items():
        extension = plugins / name
        info = plistlib.loads((extension / 'Info.plist').read_bytes())
        if info['CFBundleIdentifier'] != 'co.anysphere.sand.' + suffix:
            raise ValueError('Unexpected extension bundle ID: ' + name)
        executable = info['CFBundleExecutable']
        if '/' in executable or executable in ('.', '..'):
            raise ValueError('Invalid extension executable')
        path = extension / executable
        data = bytearray(path.read_bytes())
        start, length = text_section(data, commands)
        if hashlib.sha256(data[start:start + length]).hexdigest() != expected:
            raise ValueError('Unsupported original extension: ' + name)
        if name == 'Widgets.appex':
            # Original GrokBotActionURL builds a seven-character Swift string.
            # Keep its ABI/length and change only the four MOV-wide immediates.
            offset = scheme_sites(data, start, length)
            if len(offset) != 1:
                raise ValueError('Expected exactly one widget scheme construction, found %d' % len(offset))
            offset = offset[0]
            for index, part in enumerate(WIDGETS_SCHEME_PARTS):
                instruction = struct.unpack_from('<I', data, offset + index * 4)[0]
                instruction = (instruction & ~(0xffff << 5)) | (part << 5)
                struct.pack_into('<I', data, offset + index * 4, instruction)
        elif name == 'ImageShareExtension.appex':
            # Equal-length replacement also preserves the original CFString size.
            if data.count(b'sand-mobile\0') != 1:
                raise ValueError('Unexpected original share URL scheme')
            data = data.replace(b'sand-mobile\0', b'gblocal-ios\0')
        path.write_bytes(data)
        info['CFBundleIdentifier'] = bundle_id + '.' + suffix
        info['SandAppGroupIdentifier'] = group
        info.pop('UISupportedDevices', None)
        (extension / 'Info.plist').write_bytes(plistlib.dumps(info))
        records.append({'name': name, 'bundleId': info['CFBundleIdentifier'],
                        'sourceTextSha256': expected, 'appGroup': group})
    return records
