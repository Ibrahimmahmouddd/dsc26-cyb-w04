# AI usage: dsc26-cyb-w04

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Claude for explanations and code drafts, while I handled running the tests, implementing the code, and checking the output using the provided fixture.

## What AI got wrong

In W4 I did not hit a failing test. But I did not trust the code blindly: I ran the CLI on the fixture and checked that the 11 groups matched the task, and I tested the severity boundaries (9.0, 7.0, 4.0, 0.0, "abc", 11, True) myself.

## In my own words

1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?

I would fix DB_PASSWORD first, because exposing it could allow unauthorized access to the database and sensitive customer information. Although Bandit rates MD5 as HIGH, it is only used for generating an ETag to detect file changes, so its actual risk in this project is lower.


2. Why does a suppression need an expiry date?

A suppression needs an expiry date because the code may change over time, making a previously ignored warning a real security risk that should be reviewed again. Without an expiry date, the warning could remain hidden forever.
