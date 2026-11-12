# Notes app

An Android notes app. `LoginActivity` is the launcher screen: it signs the user in and saves the returned session token. `DeepLinkActivity` opens shared notes from `notes://open?url=...` links. `HelpActivity` shows the help site from `notes://help?page=...` links. `TokenStore` keeps the signed-in session token.
