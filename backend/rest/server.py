import os
from flask import Flask, redirect, request, session, send_file, url_for, jsonify
from flask_oidc import OpenIDConnect
from dotenv import load_dotenv
import dropbox
from dropbox import DropboxOAuth2Flow
import zipfile
from io import BytesIO
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Flask and Database Setup
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update({
    'OIDC_CLIENT_SECRETS': 'keycloak_config.json',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token',    
})
oidc = OpenIDConnect(app)

Base = declarative_base()
engine = create_engine("sqlite:///dropbox_tokens.db", echo=True)
Session = sessionmaker(bind=engine)


# Create tables
class DropboxToken(Base):
    __tablename__ = "dropbox_tokens"
    user_id = Column(String, primary_key=True)
    dropbox_id = Column(String, unique=True)
    refresh_token = Column(String)


Base.metadata.create_all(engine)

# Dropbox App Configuration
load_dotenv()
DROPBOX_APP_KEY = os.getenv("DROPBOX_APP_KEY")
DROPBOX_APP_SECRET = os.getenv("DROPBOX_APP_SECRET")
REDIRECT_URI = "http://localhost:5000/dropbox_callback"

@app.route('/')
def home():
    if oidc.user_loggedin:
        db_session = Session()
        existing_token = (
            db_session.query(DropboxToken)
            .filter_by(user_id=oidc.user_getfield('sub'))
            .first()
        )
        return f"Welcome, {oidc.user_getfield('email')}!\nLogged into Dropbox: {existing_token!=None}"
    else:
        return 'Welcome! Please <a href="/login">log in</a>.'

@app.route('/keycloak_login')
def keycloak_login():
    return redirect(url_for('oidc_login'))

@oidc.require_login # requires the user to be logged in with his keycloak account in order to connect to dropbox
@app.route("/dropbox_login")
def dropbox_login():
    """Initiate Dropbox OAuth flow"""
    # It's possible to do this without a redirect and simply make the user enter a code.
    auth_flow = DropboxOAuth2Flow(
        consumer_key=DROPBOX_APP_KEY,
        consumer_secret=DROPBOX_APP_SECRET,
        redirect_uri=REDIRECT_URI,
        token_access_type="offline",
        session=session,
        csrf_token_session_key="dropbox-auth-csrf-token",
    )
    return redirect(auth_flow.start())


@app.route("/dropbox_callback")
def dropbox_callback():
    """Handle Dropbox OAuth callback"""
    try:
        auth_flow = DropboxOAuth2Flow(
            consumer_key=DROPBOX_APP_KEY,
            consumer_secret=DROPBOX_APP_SECRET,
            redirect_uri=REDIRECT_URI,
            token_access_type="offline",
            session=session,
            csrf_token_session_key="dropbox-auth-csrf-token",
        )
        oauth_result = auth_flow.finish(request.args)

        # Once we have this we can always use it, no need to login again
        refresh_token = oauth_result.refresh_token

        # Store refresh token in database
        db_session = Session()
        existing_token = (
            db_session.query(DropboxToken)
            .filter_by(dropbox_id=oauth_result.account_id)
            .first()
        )

        if existing_token:  # TODO This shouldn't happen in the first place tbh
            existing_token.refresh_token = refresh_token
        else:
            new_token = DropboxToken(
                user_id = oidc.user_getfield('sub'),
                dropbox_id=oauth_result.account_id,
                refresh_token=refresh_token
            )
            db_session.add(new_token)

        db_session.commit()
        db_session.close()

        return "Authentication successful for user: " + oauth_result.account_id

    except Exception as e:
        return f"Authentication failed: {str(e)}", 500


def get_dropbox_client():
    """Retrieve Dropbox client for a specific user"""
    db_session = Session()
    token_record = (
        db_session.query(DropboxToken).filter_by(user_id=oidc.user_getfield('sub')).first()
    )  

    if not token_record:
        raise ValueError("No Dropbox token found for this user")

    # The refresh token will be used automatically to get access tokens, no need to supply one
    dbx = dropbox.Dropbox(
        app_key=DROPBOX_APP_KEY,
        app_secret=DROPBOX_APP_SECRET,
        oauth2_refresh_token=token_record.refresh_token,
    )
    return dbx

# Checks if the logged in user has a dropbox account linked or not
@app.route("/dropbox_linked")
@oidc.require_login
def dropbox_linked():
    # Store refresh token in database
    db_session = Session()
    existing_token = (
        db_session.query(DropboxToken)
        .filter_by(user_id=oidc.user_getfield('sub'))
        .first()
    )

    if existing_token:  
        return "User dropbox account linked"
    else:
       return "User dropbox account not found" 


@app.route("/list_files/")
def list_dropbox_files():
    """List files for a given user"""
    dbx = get_dropbox_client()
    try:
        files = dbx.files_list_folder("").entries
        return [file.name for file in files]
    except Exception as e:
        print(f"Error listing files: {e}")
        return []


@app.route("/upload_file/", methods=["POST"])
@app.route("/upload_file/<path:file_path>", methods=["POST"])
def upload_file(file_path=""):
    """Upload a file to Dropbox"""
    if "file" not in request.files:
        return "No file provided", 400

    file = request.files["file"]
    filename = file.filename

    dbx = get_dropbox_client()
    try:
        dbx.files_upload(file.read(), f"/{file_path}/{filename}")
        return "File uploaded successfully"
    except Exception as e:
        print(f"Error uploading file: {e}")
        return "Error uploading file", 500


@app.route("/download/<path:file_path>")
def download_file(file_path):
    """Download a specific file from Dropbox"""
    dbx = get_dropbox_client()
    try:
        _, res = dbx.files_download(f"/{file_path}")

        file_stream = BytesIO(res.content)
        file_stream.seek(0)
        res.close()

        return send_file(file_stream, as_attachment=True, download_name=file_path)
    except Exception as e:
        print(f"Error downloading file: {e}")
        return "Error downloading file", 500


@app.route("/download_all/")
def download_all_files():
    """Download all files from Dropbox as a single ZIP archive, including subdirectories"""
    dbx = get_dropbox_client()

    def add_files_to_zip(folder_path, zip_file):
        try:
            entries = dbx.files_list_folder(folder_path).entries

            for entry in entries:
                entry_path = f"{folder_path}/{entry.name}"

                if isinstance(entry, dropbox.files.FolderMetadata):
                    add_files_to_zip(entry_path, zip_file)
                elif isinstance(entry, dropbox.files.FileMetadata):
                    _, res = dbx.files_download(entry.path_lower)
                    zip_file.writestr(entry_path.lstrip("/"), res.content)
                    res.close()
        except Exception as e:
            print(f"Error processing folder {folder_path}: {e}")

    try:
        zip_buffer = BytesIO()

        #TODO ZIP_DEFLATED might eventually cause problems
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            add_files_to_zip("", zip_file)

        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name="all_files.zip",
            mimetype="application/zip",
        )
    except Exception as e:
        print(f"Error downloading files: {e}")
        return "Error downloading files", 500


if __name__ == "__main__":
    app.run(debug=True)
