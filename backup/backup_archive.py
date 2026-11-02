import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile

import py7zr
from py7zr.exceptions import PasswordRequired


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_archive(path, password, output):
    with py7zr.SevenZipFile(path, 'r', password=password) as archive:
        for name in archive.getnames():
            value = PurePosixPath(name.replace('\\', '/'))
            if value.is_absolute() or '..' in value.parts or ':' in name:
                raise ValueError('Unsafe archive path')
        if archive.testzip() is not None:
            raise ValueError('Archive checksum mismatch')
    with py7zr.SevenZipFile(path, 'r', password=password) as archive:
        archive.extractall(path=output)
    return {
        str(item.relative_to(output)): file_hash(item)
        for item in output.rglob('*') if item.is_file()
    }


def main():
    payload = json.load(sys.stdin)
    password = payload.pop('password')
    archive = Path(payload['archive'])
    if payload['operation'] == 'create':
        source = Path(payload['source'])
        expected = {
            str(item.relative_to(source)): file_hash(item)
            for item in source.rglob('*') if item.is_file()
        }
        filters = [
            {'id': py7zr.FILTER_LZMA2, 'preset': 3},
            {'id': py7zr.FILTER_CRYPTO_AES256_SHA256},
        ]
        with py7zr.SevenZipFile(
            archive, 'w', password=password, header_encryption=True,
            filters=filters,
        ) as writer:
            for name in sorted(expected):
                writer.write(source / name, arcname=name)
        try:
            with py7zr.SevenZipFile(archive, 'r') as reader:
                reader.getnames()
        except PasswordRequired:
            pass
        else:
            raise ValueError('Archive headers are not encrypted')
        with tempfile.TemporaryDirectory() as directory:
            actual = inspect_archive(archive, password, Path(directory))
        if actual != expected:
            raise ValueError('Archive round-trip mismatch')
        result = {'files': len(expected), 'round_trip': True, 'headers_encrypted': True, 'sha256': file_hash(archive)}
    elif payload['operation'] == 'extract':
        output = Path(payload['output'])
        output.mkdir(parents=True, exist_ok=True)
        actual = inspect_archive(archive, password, output)
        result = {'files': len(actual), 'sha256': file_hash(archive), 'round_trip': True}
    else:
        raise ValueError('Unknown archive operation')
    password = None
    print(json.dumps(result))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        print('Archive operation failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
