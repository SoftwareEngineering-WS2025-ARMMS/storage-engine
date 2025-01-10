import unittest
from unittest.mock import patch, MagicMock
from src.rest.server import app, DropboxToken, Session
from flask import jsonify
import dropbox
from datetime import datetime
import zipfile
import io

class TestDropboxApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test client before all tests."""
        app.config['TESTING'] = True
        cls.client = app.test_client()

    def setUp(self):
        """Mock session and other setups before each test."""
        self.mock_session = patch("src.rest.server.Session").start()

    def tearDown(self):
        """Stop all patches after each test."""
        patch.stopall()

    @patch("src.rest.server.oidc")
    def test_home_page_not_logged_in(self, mock_oidc):
        """Test home page when user is not logged in."""
        mock_oidc.user_loggedin = False
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome! Please <a href=\"/login\">log in</a>.", response.data)

    @patch("src.rest.server.oidc")
    def test_home_page_logged_in(self, mock_oidc):
        """Test home page when user is logged in."""
        mock_oidc.user_loggedin = True
        mock_oidc.user_getfield.return_value = "test@example.com"
        mock_session_instance = MagicMock()
        self.mock_session.return_value = mock_session_instance
        mock_session_instance.query().filter_by().first.return_value = DropboxToken()

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, test@example.com!", response.data)

    @patch("src.rest.server.DropboxOAuth2Flow")
    @patch("src.rest.server.oidc")
    def test_dropbox_login(self, mock_oidc, mock_oauth_flow):
        """Test Dropbox login redirection."""
        mock_oidc.user_loggedin = True
        mock_flow_instance = mock_oauth_flow.return_value
        mock_flow_instance.start.return_value = "https://dropbox-auth-url"

        response = self.client.get("/dropbox_login", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://dropbox-auth-url")

    @patch("src.rest.server.DropboxOAuth2Flow")
    @patch("src.rest.server.oidc")
    def test_dropbox_callback(self, mock_oidc, mock_oauth_flow):
        """Test Dropbox callback handling."""
        mock_oidc.user_getfield.return_value = "user-123"
        mock_flow_instance = mock_oauth_flow.return_value
        mock_flow_instance.finish.return_value = MagicMock(
            refresh_token="test-refresh-token", account_id="dbx-123"
        )

        mock_session_instance = MagicMock()
        self.mock_session.return_value = mock_session_instance

        response = self.client.get("/dropbox_callback", query_string={"code": "auth-code"})
        self.assertEqual(response.status_code, 302)

    @patch("src.rest.server.get_dropbox_client")
    def test_list_files(self, mock_get_client):
        """Test listing files in Dropbox."""
        mock_dbx_client = MagicMock()
        mock_get_client.return_value = mock_dbx_client

        # Mock the Dropbox API call
        mock_dbx_client.files_list_folder.return_value.entries = [
            dropbox.files.FileMetadata(
                name="file1.txt", path_lower="/file1.txt", server_modified=datetime(2025, 1, 1)
            ),
            dropbox.files.FileMetadata(
                name="file2.txt", path_lower="/file2.txt", server_modified=datetime(2025, 2, 1)
            ),
        ]

        response = self.client.get("/list_files")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"file1.txt", response.data)
        self.assertIn(b"file2.txt", response.data)

    @patch("src.rest.server.get_dropbox_client")
    def test_upload_file(self, mock_get_client):
        """Test uploading a file to Dropbox."""
        mock_dbx_client = MagicMock()
        mock_get_client.return_value = mock_dbx_client

        mock_dbx_client.files_upload.return_value = MagicMock()

        fake_file_data = b"This is some test data."
        fake_file = (io.BytesIO(fake_file_data), "test_file.txt")

        response = self.client.post(
            "/upload_file/",
            data={"file": (fake_file[0], fake_file[1])},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        mock_dbx_client.files_upload.assert_called_once_with(fake_file_data, "/test_file.txt")
        self.assertEqual(b"File uploaded successfully", response.data)

        fake_file = (io.BytesIO(fake_file_data), "test_file.txt")
        response = self.client.post(
            "/upload_file/test_folder",
            data={"file": (fake_file[0], fake_file[1])},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        mock_dbx_client.files_upload.assert_called_with(fake_file_data, "/test_folder/test_file.txt")
        self.assertEqual(b"File uploaded successfully", response.data)

    @patch("src.rest.server.get_dropbox_client")
    def test_download_file(self, mock_get_client):
        """Test downloading a file from Dropbox."""
        mock_dbx_client = MagicMock()
        mock_get_client.return_value = mock_dbx_client

        # Mock the Dropbox API call
        mock_dbx_client.files_download.return_value = (
            MagicMock(),
            MagicMock(content=b"file content"),
        )

        response = self.client.get("/download/test_file.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"file content")

    @patch("src.rest.server.get_dropbox_client")
    def test_download_all_files(self, mock_get_client):
        """Test downloading all files as a ZIP."""
        mock_dbx_client = MagicMock()
        mock_get_client.return_value = mock_dbx_client

        # Mock Dropbox API calls
        mock_dbx_client.files_list_folder.return_value.entries = [
            dropbox.files.FileMetadata(
                name="file1.txt", path_lower="/file1.txt"
            ),
            dropbox.files.FileMetadata(
                name="file2.txt", path_lower="/file2.txt"
            ),
        ]
        mock_dbx_client.files_download.side_effect = [
            (None, MagicMock(content=b"content1")),
            (None, MagicMock(content=b"content2")),
        ]

        response = self.client.get("/download_all")
        self.assertEqual(response.status_code, 200)
        zip_file = zipfile.ZipFile(io.BytesIO(response.data))
        self.assertEqual(zip_file.namelist(), ["file1.txt", "file2.txt"])
        self.assertEqual(zip_file.read("file1.txt"), b"content1")
        self.assertEqual(zip_file.read("file2.txt"), b"content2")

    @patch("src.rest.server.get_dropbox_client")
    def test_download_all_files_after(self, mock_get_client):
        """Test downloading files modified after a certain date."""
        mock_dbx_client = MagicMock()
        mock_get_client.return_value = mock_dbx_client

        # Mock Dropbox API calls
        mock_dbx_client.files_list_folder.return_value.entries = [
            dropbox.files.FileMetadata(
                name="file1.txt", path_lower="/file1.txt", server_modified=datetime(2025, 1, 1)
            ),
            dropbox.files.FileMetadata(
                name="file2.txt", path_lower="/file2.txt", server_modified=datetime(2024, 12, 31)
            ),
        ]
        mock_dbx_client.files_download.return_value = (None, MagicMock(content=b"content1"))

        response = self.client.get("/download_all_after/01-01-2025")
        self.assertEqual(response.status_code, 200)
        zip_file = zipfile.ZipFile(io.BytesIO(response.data))
        self.assertEqual(zip_file.namelist(), ["file1.txt"])
        self.assertEqual(zip_file.read("file1.txt"), b"content1")

if __name__ == "__main__":
    unittest.main()