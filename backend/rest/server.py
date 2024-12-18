import os
from flask import Flask, redirect, request, session
import dropbox
from dropbox import DropboxOAuth2Flow
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Flask and Database Setup
app = Flask(__name__)
app.secret_key = os.urandom(24)

Base = declarative_base()
engine = create_engine("sqlite:///dropbox_tokens.db", echo=True)
Session = sessionmaker(bind=engine)


# Create tables
class DropboxToken(Base):
    __tablename__ = "dropbox_tokens"
    # TODO Add user_id?
    id = Column(Integer, primary_key=True)
    dropbox_id = Column(String, unique=True)
    refresh_token = Column(String)


Base.metadata.create_all(engine)

# Dropbox App Configuration
DROPBOX_APP_KEY = os.getenv("DROPBOX_APP_KEY")
DROPBOX_APP_SECRET = os.getenv("DROPBOX_APP_SECRET")
REDIRECT_URI = "http://localhost:5000/dropbox_callback"


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
                dropbox_id=oauth_result.account_id, refresh_token=refresh_token
            )
            db_session.add(new_token)

        db_session.commit()
        db_session.close()

        return "Authentication successful for user: " + oauth_result.account_id

    except Exception as e:
        return f"Authentication failed: {str(e)}", 400


def get_dropbox_client(user_id):
    """Retrieve Dropbox client for a specific user"""
    db_session = Session()
    token_record = (
        db_session.query(DropboxToken).filter_by(dropbox_id=user_id).first()
    )  # TODO this is temporary, should filter by user_id

    if not token_record:
        raise ValueError("No Dropbox token found for this user")

    # The refresh token will be used automatically to get access tokens, no need to supply one
    dbx = dropbox.Dropbox(
        app_key=DROPBOX_APP_KEY,
        app_secret=DROPBOX_APP_SECRET,
        oauth2_refresh_token=token_record.refresh_token,
        session=session,
    )
    return dbx


@app.route("/list_dropbox_files/<user_id>")
def list_dropbox_files(user_id):
    """List files for a given user"""
    dbx = get_dropbox_client(user_id)
    if dbx:
        try:
            files = dbx.files_list_folder("").entries
            return [file.name for file in files]
        except Exception as e:
            print(f"Error listing files: {e}")
            return []


if __name__ == "__main__":
    app.run(debug=True)