import os
import unittest
from unittest.mock import patch

from keylime import fs_util


class TestChDir(unittest.TestCase):

    @patch("keylime.fs_util.os.path.exists")
    @patch("keylime.fs_util.os.makedirs")
    @patch("keylime.fs_util.os.chdir")
    def test_ch_dir_present(self, chdir_mock, makedirs_mock, exists_mock):
        """Test ch_dir when the directory exists."""
        exists_mock.return_value = True

        fs_util.ch_dir("/tmp/dir")
        makedirs_mock.assert_not_called()
        chdir_mock.assert_called_once()

    @patch("keylime.fs_util.os.path.exists")
    @patch("keylime.fs_util.os.makedirs")
    @patch("keylime.fs_util.os.chdir")
    def test_ch_dir_missing(self, chdir_mock, makedirs_mock, exists_mock):
        """Test ch_dir when the directory is missing."""
        exists_mock.return_value = False

        fs_util.ch_dir("/tmp/dir")
        makedirs_mock.assert_called_once()
        chdir_mock.assert_called_once()


class TestCreate(unittest.TestCase):

    @patch("keylime.fs_util.os.fdopen")
    @patch("keylime.fs_util.os.open")
    def test_create_default(self, open_mock, fdopen_mock):
        """Test create with default parameters."""
        with fs_util.create("/tmp/file") as f:
            open_mock.assert_called_once_with("/tmp/file", os.O_WRONLY | os.O_CREAT, 0o600)
            fdopen_mock.assert_called_once()
            self.assertTrue("wb" in fdopen_mock.call_args.args)
        f.close.assert_called_once()

    @patch("keylime.fs_util.os.fdopen")
    @patch("keylime.fs_util.os.open")
    def test_create_mode(self, open_mock, fdopen_mock):
        """Test create with the mode parameter."""
        with fs_util.create("/tmp/file", mode="w") as f:
            open_mock.assert_called_once_with("/tmp/file", os.O_WRONLY | os.O_CREAT, 0o600)
            fdopen_mock.assert_called_once()
            self.assertTrue("w" in fdopen_mock.call_args.args)
        f.close.assert_called_once()

    @patch("keylime.fs_util.os.fdopen")
    @patch("keylime.fs_util.os.open")
    def test_create_mask(self, open_mock, fdopen_mock):
        """Test create with the mask parameter."""
        with fs_util.create("/tmp/file", mask=0o660) as f:
            open_mock.assert_called_once_with("/tmp/file", os.O_WRONLY | os.O_CREAT, 0o660)
            fdopen_mock.assert_called_once()
            self.assertTrue("wb" in fdopen_mock.call_args.args)
        f.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
