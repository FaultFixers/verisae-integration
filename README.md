FaultFixers Email Replies Handler
---------------------------------

When a ticket update email is replied to, the reply to updates@faultfixers.com is handled by this repository.

Setup
=====

First, run `pip install -r requirements.txt`

Create these files:

* `service-account-key.json` - should be a service account JSON file created through the Google API Console.
* `.env` - should have the keys seen in `.env.example`
* `account-map.json` - should be in the format as seen in `account-map.json.example`

When requirements change:

`pip freeze > requirements.txt`

Run
===

`python run.py`
