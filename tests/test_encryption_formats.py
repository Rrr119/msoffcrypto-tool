"""Cover parsing, password verification, and decryption for four encryption formats."""

import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions

DATA_DIR = join(dirname(__file__), "inputs")
OUTPUT_DIR = join(dirname(__file__), "outputs")

ENCRYPTION_FORMATS = (
    (
        "agile_sha512",
        "agile",
        "example_password.docx",
        "example.docx",
        "Password1234_",
        "ooxml",
    ),
    (
        "agile_sha1",
        "agile",
        "ecma376agile_sha1_password.xlsx",
        "example.xlsx",
        "Password1234_",
        "ooxml",
    ),
    (
        "standard_aes",
        "standard",
        "ecma376standard_password.docx",
        "ecma376standard_password_plain.docx",
        "Password1234_",
        "ooxml",
    ),
    (
        "rc4_cryptoapi",
        "rc4_cryptoapi",
        "rc4cryptoapi_password.doc",
        "rc4cryptoapi_password_plain.doc",
        "Password1234_",
        "doc97",
    ),
)


class EncryptionFormatsTest(unittest.TestCase):
    def test_parse_verify_and_decrypt(self):
        for (
            name,
            encryption_type,
            in_name,
            out_name,
            password,
            file_format,
        ) in ENCRYPTION_FORMATS:
            with self.subTest(name), open(join(DATA_DIR, in_name), "rb") as f:
                officefile = OfficeFile(f)
                self.assertEqual(officefile.format, file_format)
                if file_format == "ooxml":
                    self.assertEqual(officefile.type, encryption_type)
                    if encryption_type == "agile":
                        self.assertIn(
                            officefile.info["passwordHashAlgorithm"],
                            ("SHA1", "SHA512"),
                        )
                        self.assertGreater(officefile.info["spinValue"], 0)
                    else:
                        self.assertEqual(officefile.info["header"]["algId"], 0x660E)
                        self.assertEqual(
                            officefile.info["verifier"]["verifierHashSize"], 20
                        )
                    officefile.load_key(password=password, verify_password=True)
                else:
                    officefile.load_key(password=password)
                    self.assertEqual(officefile.type, encryption_type)

                sink = bytearray()
                officefile.decrypt(_ByteArrayWriter(sink))

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(sink, f.read())

    def test_wrong_password(self):
        for (
            name,
            _,
            in_name,
            __,
            ___,
            file_format,
        ) in ENCRYPTION_FORMATS:
            with self.subTest(name), open(join(DATA_DIR, in_name), "rb") as f:
                officefile = OfficeFile(f)
                kwargs = {"verify_password": True} if file_format == "ooxml" else {}
                with self.assertRaises(exceptions.InvalidKeyError):
                    officefile.load_key(password="incorrect", **kwargs)


class _ByteArrayWriter:
    def __init__(self, target):
        self.target = target

    def write(self, data):
        self.target.extend(data)
        return len(data)


if __name__ == "__main__":
    unittest.main()
