import unittest
from pwn import *

# includes parent folder, allows including files from parent folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import bufferfly
from helpers import *


vulnerable_binary = "./test"
vulnerable_binary_large_buffer = "./test500"
binary_no_bof = "./test-no-bof"


class Test_find_string(unittest.TestCase):
    def test_find_match(self):
        binaryName = vulnerable_binary
        expected = [('0x4003c0', '/bin/sh'),
                    ('0xf7f4679f', '/bin/sh'),
                    ]
        string = "/bin/sh"
        result = find_strings(binaryName, string)
        self.assertEqual(result, expected)

    def test_find_many_matches(self):
        binaryName = vulnerable_binary
        string = "/bin"
        expected = [('0x4003c0', '/bin/sh'),
                    ('0xf7f4679f', '/bin/sh'),
                    ('0xf7f47c77', '/bin:/usr/bin'),
                    ('0xf7f47c80', '/bin'),
                    ('0xf7f480ea', '/bin/csh'),
                    ('0xf7f4c6cc', '/bin:/usr/bin'),
                    ('0xf7f4c6d5',  '/bin')
                    ]
        result = find_strings(binaryName, string)
        self.assertEqual(result, expected)

    def test_no_match(self):
        binaryName = vulnerable_binary
        expected = []
        string = "string_not_present"
        result = find_strings(binaryName, string)
        self.assertEqual(result, expected)


class Test_find_function(unittest.TestCase):
    def test_function_present(self):
        binaryName = vulnerable_binary
        nPadding = 20
        expected = [('0x401120', 'supersecret')]
        goalFunction = "supersecret"
        result = find_function(binaryName, goalFunction)
        self.assertEqual(result, expected)

    def test_function_not_present(self):
        binaryName = vulnerable_binary
        nPadding = 20
        expected = []
        goalFunction = "goal"
        result = find_function(binaryName, goalFunction)
        self.assertEqual(result, expected)


class Test_find_rop_gadget(unittest.TestCase):
    def test_rop_gadget_present(self):
        binaryName = vulnerable_binary
        rop = "pop ebx ; pop ebp"
        result = find_rop_gadget(binaryName, rop)
        exp = ["b'0x004010e7 : add byte ptr [eax], al ; add byte "
               "ptr [ecx], al ; add esp, 4 ; pop ebx ; pop ebp ; ret\\n'",
               "b'0x004010e9 : add byte ptr [ecx], al ; add esp, 4 ; "
               "pop ebx ; pop ebp ; ret\\n'",
               "b'0x004010eb : add esp, 4 ; pop ebx ; pop ebp ; ret\\n'",
               "b'0x004010ee : pop ebx ; pop ebp ; ret\\n'"]

        self.assertEqual(result, exp)

    def test_rop_gadget_not_present(self):
        binaryName = vulnerable_binary
        rop = "jmp esp"
        result = find_rop_gadget(binaryName, rop)
        expected = []
        self.assertEqual(result, expected)


class Test_find_padding(unittest.TestCase):
    def test_20_bytes(self):
        binaryName = vulnerable_binary
        min = 20
        expected = 28
        result = find_padding(binaryName, min)
        self.assertEqual(result, expected)

    def test_500_bytes(self):
        binaryName = vulnerable_binary_large_buffer
        min = 300
        expected = 508  # because stack alignment
        result = find_padding(binaryName, min)
        self.assertEqual(result, expected)

    def test_no_bov(self):
        binaryName = binary_no_bof
        min = 50
        expected = 0  # because stack alignment
        result = find_padding(binaryName, min)
        self.assertEqual(result, expected)


class TestProtections(unittest.TestCase):
    def test_binaryName(self):
        pass

    def test_nx(self):
        pass

    def test_canary(self):
        pass

    def test_pie(self):
        pass

    def test_rwxSegents(self):
        pass

    def test_relro(self):
        pass


if __name__ == '__main__':
    context.log_level = 'error'  # no printing of each process' start and close
    unittest.main()
