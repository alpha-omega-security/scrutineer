# Hybrid notes

`app/` is a React Native notes app. `server/` is the notes API it talks to. Start the API with `python server/server.py`. Sign in through `POST /login` with a JSON body holding `username` and `password`, then send the returned token as `Authorization: Bearer <token>`. `GET /notes` returns the signed-in user's notes.
