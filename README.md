FaultFixers Verisae Email Integration
-------------------------------------

Parses emails from Verisae and pushes the information into FaultFixers.

The email types supported are:
* New work order
* Quote requested
* Quote authorised
* Quote rejected
* Work order escalated
* Work order de-escalated
* Work order has a new note
* Work order cancelled
* Work order recalled
* Work order needs re-quoted
* CPPM SLA approaching

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
