import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os

# Add current directory to path so we can import the script
sys.path.append(os.getcwd())
from fast_pair_demo import (
    scan_for_targets,
    aes_encrypt,
    aes_decrypt,
    build_raw_kbp_request,
    build_retroactive_request,
    build_extended_request,
    calculate_entropy,
    is_valid_mac,
    extract_address,
    parse_kbp_response,
    MessageType,
    ExploitStrategy,
    ExploitResult,
    WhisperPairExploit,
)


class TestAESCrypto(unittest.TestCase):
    """Test AES encryption/decryption functions"""

    def test_aes_encrypt_decrypt_roundtrip(self):
        """Test that encrypt followed by decrypt returns original data"""
        key = b'0123456789abcdef'
        data = b'Test data here!'  # 16 bytes

        encrypted = aes_encrypt(key, data)
        decrypted = aes_decrypt(key, encrypted)

        self.assertEqual(decrypted, data)

    def test_aes_encrypt_with_short_key(self):
        """Test that short keys are padded properly"""
        short_key = b'short'
        data = b'1234567890123456'

        # Should not raise an exception
        encrypted = aes_encrypt(short_key, data)
        self.assertEqual(len(encrypted), 16)

    def test_aes_decrypt_with_short_key(self):
        """Test decryption with short key padding"""
        short_key = b'short'
        data = b'1234567890123456'

        encrypted = aes_encrypt(short_key, data)
        decrypted = aes_decrypt(short_key, encrypted)

        self.assertEqual(decrypted, data)


class TestRequestBuilders(unittest.TestCase):
    """Test KBP request builder functions"""

    def test_build_raw_kbp_request_format(self):
        """Test raw KBP request has correct format"""
        target_address = "11:22:33:44:55:66"
        request, shared_secret = build_raw_kbp_request(target_address)

        self.assertEqual(len(request), 16)
        self.assertEqual(request[0], MessageType.KEY_BASED_PAIRING_REQUEST)
        self.assertEqual(request[1], 0x11)  # Flags
        # Address bytes should be at positions 2-7
        self.assertEqual(request[2:8], bytes.fromhex("112233445566"))
        # Shared secret should be 16 bytes
        self.assertEqual(len(shared_secret), 16)

    def test_build_retroactive_request_format(self):
        """Test retroactive request has correct format"""
        target_address = "AA:BB:CC:DD:EE:FF"
        request, shared_secret = build_retroactive_request(target_address)

        self.assertEqual(len(request), 16)
        self.assertEqual(request[0], MessageType.KEY_BASED_PAIRING_REQUEST)
        self.assertEqual(request[1], 0x0A)  # Retroactive flags
        self.assertEqual(request[2:8], bytes.fromhex("AABBCCDDEEFF"))
        self.assertEqual(len(shared_secret), 16)

    def test_build_extended_request_format(self):
        """Test extended response request has correct format"""
        target_address = "00:11:22:33:44:55"
        request, shared_secret = build_extended_request(target_address)

        self.assertEqual(len(request), 16)
        self.assertEqual(request[0], MessageType.KEY_BASED_PAIRING_REQUEST)
        self.assertEqual(request[1], 0x10)  # Extended response flag
        self.assertEqual(len(shared_secret), 16)


class TestResponseParsing(unittest.TestCase):
    """Test response parsing functions"""

    def test_calculate_entropy_empty(self):
        """Test entropy of empty data"""
        self.assertEqual(calculate_entropy(b''), 0.0)

    def test_calculate_entropy_uniform(self):
        """Test entropy of uniform data (low entropy)"""
        data = bytes([0x00] * 16)
        entropy = calculate_entropy(data)
        self.assertEqual(entropy, 0.0)

    def test_calculate_entropy_varied(self):
        """Test entropy of varied data (higher entropy)"""
        data = bytes(range(16))  # 0-15, all different
        entropy = calculate_entropy(data)
        self.assertGreater(entropy, 3.0)  # Should be high entropy

    def test_is_valid_mac_valid(self):
        """Test valid MAC addresses"""
        self.assertTrue(is_valid_mac("11:22:33:44:55:66"))
        self.assertTrue(is_valid_mac("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(is_valid_mac("01:23:45:67:89:AB"))

    def test_is_valid_mac_invalid(self):
        """Test invalid MAC addresses"""
        self.assertFalse(is_valid_mac("00:00:00:00:00:00"))
        self.assertFalse(is_valid_mac("FF:FF:FF:FF:FF:FF"))
        self.assertFalse(is_valid_mac("invalid"))
        self.assertFalse(is_valid_mac("11:22:33:44:55"))  # Too short
        self.assertFalse(is_valid_mac("GG:HH:II:JJ:KK:LL"))  # Invalid hex

    def test_extract_address(self):
        """Test MAC address extraction from bytes"""
        data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

        addr = extract_address(data, 0)
        self.assertEqual(addr, "11:22:33:44:55:66")

        addr = extract_address(data, 2)
        self.assertEqual(addr, "33:44:55:66:77:88")

    def test_extract_address_out_of_bounds(self):
        """Test extraction with insufficient data"""
        data = bytes([0x11, 0x22, 0x33])
        addr = extract_address(data, 0)
        self.assertEqual(addr, "00:00:00:00:00:00")

    def test_parse_kbp_response_standard_format(self):
        """Test parsing standard response format (type 0x01)"""
        # Standard response: type byte + 6 bytes MAC
        response = bytes([0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])

        addr = parse_kbp_response(response)
        self.assertEqual(addr, "AA:BB:CC:DD:EE:FF")

    def test_parse_kbp_response_too_short(self):
        """Test parsing response that's too short"""
        response = bytes([0x01, 0xAA, 0xBB])

        addr = parse_kbp_response(response)
        self.assertIsNone(addr)


class TestFastPairScanner(unittest.IsolatedAsyncioTestCase):
    """Test BLE scanner functionality"""

    @patch('fast_pair_demo.BleakScanner')
    async def test_scan_finds_fast_pair_device(self, MockScanner):
        """Test that the scanner correctly identifies a device with the Fast Pair service UUID"""
        mock_dev = MagicMock()
        mock_dev.name = "Test Buds"

        mock_adv = MagicMock()
        mock_adv.service_uuids = ["0000fe2c-0000-1000-8000-00805f9b34fb"]
        mock_adv.service_data = {}
        mock_adv.rssi = -50
        mock_adv.local_name = None

        mock_results = {
            "11:22:33:44:55:66": (mock_dev, mock_adv)
        }
        MockScanner.discover = AsyncMock(return_value=mock_results)

        result = await scan_for_targets()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], "Test Buds")
        self.assertEqual(result[0]['address'], "11:22:33:44:55:66")
        self.assertEqual(result[0]['rssi'], -50)

    @patch('fast_pair_demo.BleakScanner')
    async def test_scan_finds_device_via_service_data(self, MockScanner):
        """Test scanner finds device via service_data instead of service_uuids"""
        mock_dev = MagicMock()
        mock_dev.name = "Data Device"

        mock_adv = MagicMock()
        mock_adv.service_uuids = []
        mock_adv.service_data = {"0000fe2c-0000-1000-8000-00805f9b34fb": b'\x01\x02'}
        mock_adv.rssi = -60
        mock_adv.local_name = None

        mock_results = {
            "AA:BB:CC:DD:EE:FF": (mock_dev, mock_adv)
        }
        MockScanner.discover = AsyncMock(return_value=mock_results)

        result = await scan_for_targets()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], "Data Device")

    @patch('fast_pair_demo.BleakScanner')
    async def test_scan_returns_empty_when_no_devices(self, MockScanner):
        """Test scanner returns empty list when no Fast Pair devices found"""
        MockScanner.discover = AsyncMock(return_value={})

        result = await scan_for_targets()

        self.assertEqual(result, [])

    @patch('fast_pair_demo.BleakScanner')
    async def test_scan_sorts_by_rssi(self, MockScanner):
        """Test that results are sorted by RSSI (strongest first)"""
        mock_dev1 = MagicMock()
        mock_dev1.name = "Far Device"
        mock_adv1 = MagicMock()
        mock_adv1.service_uuids = ["0000fe2c-0000-1000-8000-00805f9b34fb"]
        mock_adv1.service_data = {}
        mock_adv1.rssi = -80
        mock_adv1.local_name = None

        mock_dev2 = MagicMock()
        mock_dev2.name = "Close Device"
        mock_adv2 = MagicMock()
        mock_adv2.service_uuids = ["0000fe2c-0000-1000-8000-00805f9b34fb"]
        mock_adv2.service_data = {}
        mock_adv2.rssi = -40
        mock_adv2.local_name = None

        mock_results = {
            "11:11:11:11:11:11": (mock_dev1, mock_adv1),
            "22:22:22:22:22:22": (mock_dev2, mock_adv2),
        }
        MockScanner.discover = AsyncMock(return_value=mock_results)

        result = await scan_for_targets()

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], "Close Device")  # Stronger signal first
        self.assertEqual(result[1]['name'], "Far Device")


class TestExploitResult(unittest.TestCase):
    """Test ExploitResult dataclass"""

    def test_exploit_result_creation(self):
        """Test creating an ExploitResult"""
        result = ExploitResult(
            success=True,
            vulnerable=True,
            br_edr_address="11:22:33:44:55:66",
            paired=True,
            account_key_written=True,
            message="Test message",
            notifications=[]
        )

        self.assertTrue(result.success)
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.br_edr_address, "11:22:33:44:55:66")
        self.assertTrue(result.paired)
        self.assertTrue(result.account_key_written)
        self.assertEqual(result.message, "Test message")
        self.assertEqual(result.notifications, [])


class TestWhisperPairExploit(unittest.TestCase):
    """Test WhisperPairExploit class initialization"""

    def test_exploit_initialization(self):
        """Test that exploit initializes with correct defaults"""
        exploit = WhisperPairExploit("11:22:33:44:55:66")

        self.assertEqual(exploit.target_address, "11:22:33:44:55:66")
        self.assertIsNone(exploit.client)
        self.assertEqual(exploit.notifications, [])
        self.assertIsNone(exploit.shared_secret)
        self.assertIsNone(exploit.br_edr_address)
        self.assertIsNone(exploit.model_id)
        self.assertIsNone(exploit.kbp_response)


if __name__ == '__main__':
    unittest.main()
