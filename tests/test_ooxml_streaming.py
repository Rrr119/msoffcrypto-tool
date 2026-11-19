"""Tests for streaming OOXML decryption."""

import io
import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.ecma376_agile import ECMA376Agile
from msoffcrypto.method.ecma376_standard import ECMA376Standard

DATA_DIR = join(dirname(__file__), "inputs")
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

OOXML_FILES = (
    ("example_password.docx", "example.docx", "agile"),
    ("ecma376agile_sha1_password.xlsx", "example.xlsx", "agile"),
    ("ecma376standard_password.docx", "ecma376standard_password_plain.docx", "standard"),
)


class _WriteOnlySink:
    """A non-seekable output destination."""

    def __init__(self):
        self.data = bytearray()

    def write(self, buf):
        self.data.extend(buf)
        return len(buf)


class _ShortReadStream:
    """A seekable input whose reads may return fewer bytes than requested."""

    def __init__(self, data, chunk_size):
        self.data = data
        self.chunk_size = chunk_size
        self.pos = 0

    def seek(self, offset, whence=0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        else:
            self.pos = len(self.data) + offset
        return self.pos

    def tell(self):
        return self.pos

    def read(self, size=-1):
        if size < 0:
            size = len(self.data) - self.pos
        size = min(size, self.chunk_size)
        data = self.data[self.pos : self.pos + size]
        self.pos += len(data)
        return data


class OOXMLStreamingTest(unittest.TestCase):
    def test_decrypt_to_write_only_stream(self):
        for in_name, out_name, encryption_type in OOXML_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                officefile = OfficeFile(f)
                self.assertEqual(officefile.type, encryption_type)
                officefile.load_key(password=PASSWORD, verify_password=True)

                sink = _WriteOnlySink()
                officefile.decrypt(sink)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(bytes(sink.data), f.read())

    def test_wrong_password_raises_before_decryption(self):
        for in_name, _, _ in OOXML_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                officefile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    officefile.load_key(password="incorrect", verify_password=True)

    def test_agile_stream_matches_buffered_decrypt(self):
        with open(join(DATA_DIR, "example_password.docx"), "rb") as f:
            officefile = OfficeFile(f)
            officefile.load_key(password=PASSWORD)

            with officefile.file.openstream("EncryptedPackage") as stream:
                expected = ECMA376Agile.decrypt(
                    officefile.secret_key,
                    officefile.info["keyDataSalt"],
                    officefile.info["keyDataHashAlgorithm"],
                    stream,
                )
            with officefile.file.openstream("EncryptedPackage") as stream:
                chunks = list(
                    ECMA376Agile.decrypt_stream(
                        officefile.secret_key,
                        officefile.info["keyDataSalt"],
                        officefile.info["keyDataHashAlgorithm"],
                        stream,
                    )
                )

        self.assertGreater(len(chunks), 1)
        self.assertEqual(b"".join(chunks), expected)

    def test_standard_stream_matches_buffered_decrypt(self):
        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            officefile = OfficeFile(f)
            officefile.load_key(password=PASSWORD)

            with officefile.file.openstream("EncryptedPackage") as stream:
                expected = ECMA376Standard.decrypt(officefile.secret_key, stream)
            with officefile.file.openstream("EncryptedPackage") as stream:
                chunks = list(
                    ECMA376Standard.decrypt_stream(officefile.secret_key, stream)
                )

        self.assertTrue(chunks)
        self.assertEqual(b"".join(chunks), expected)

    def test_stream_handles_short_reads(self):
        with open(join(DATA_DIR, "example_password.docx"), "rb") as f:
            officefile = OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            with officefile.file.openstream("EncryptedPackage") as stream:
                package = stream.read()
                expected = ECMA376Agile.decrypt(
                    officefile.secret_key,
                    officefile.info["keyDataSalt"],
                    officefile.info["keyDataHashAlgorithm"],
                    io.BytesIO(package),
                )

        stream = _ShortReadStream(package, 137)
        actual = b"".join(
            ECMA376Agile.decrypt_stream(
                officefile.secret_key,
                officefile.info["keyDataSalt"],
                officefile.info["keyDataHashAlgorithm"],
                stream,
            )
        )
        self.assertEqual(actual, expected)

        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            officefile = OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            with officefile.file.openstream("EncryptedPackage") as stream:
                package = stream.read()
                expected = ECMA376Standard.decrypt(
                    officefile.secret_key, io.BytesIO(package)
                )

        stream = _ShortReadStream(package, 137)
        actual = b"".join(
            ECMA376Standard.decrypt_stream(officefile.secret_key, stream)
        )
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
